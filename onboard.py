#!/usr/bin/env python3
"""
Behavioral Baseline Onboarding Controller
==========================================
Automatically provisions and maintains behavioral baseline detectors for
every environment (deployment.environment) active in Splunk Observability.

Run this on a schedule (daily cron or CD pipeline) and it will:

  1. DISCOVER  — query the APM topology API for all active environments
                 and the service set in each one.

  2. DIFF      — compare against onboarding_state.json (the record of what
                 was last provisioned). Three cases are handled:
                   NEW ENV     — never seen before → provision + learn
                   UPDATED ENV — service set changed since last run → re-baseline
                   REMOVED ENV — no longer active → tear down (optional)

  3. ACT       — for each new/updated environment:
                   a. Run provision_detectors.py  (Tiers 1, 3, 4)
                   b. Run trace_fingerprint.py learn  (Tier 2 baseline)
                   c. Record the result in onboarding_state.json

  4. REPORT    — print a summary and optionally emit a Splunk custom event
                 so the action is auditable in your observability platform.

Typical deployment patterns:

  # Daily cron — fully automatic
  0 6 * * * cd /opt/behavioral-baseline && python onboard.py --auto >> onboard.log 2>&1

  # CI/CD pipeline step — run after every deployment
  python onboard.py --environment $DEPLOY_ENV

  # Manual / ad-hoc
  python onboard.py --dry-run          # preview without changes
  python onboard.py --environment prod # onboard one specific env

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM                  (default: us0)
  ONBOARDING_STATE_PATH         (default: ./onboarding_state.json)
  BASELINE_PATH                 (default: ./baseline.json)
  TOPOLOGY_LOOKBACK_HOURS       (default: 48)

Required files in same directory:
  provision_detectors.py
  trace_fingerprint.py
  error_fingerprint.py
  correlate.py
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN         = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM                = os.environ.get("SPLUNK_REALM", "us0")
STATE_PATH           = Path(os.environ.get("ONBOARDING_STATE_PATH",
                                           "./onboarding_state.json"))
BASELINE_PATH        = Path(os.environ.get("BASELINE_PATH", "./baseline.json"))
TOPOLOGY_LOOKBACK_HOURS = int(os.environ.get("TOPOLOGY_LOOKBACK_HOURS", "48"))

# How many services must change in an environment before we treat it as
# "updated" and trigger a re-baseline. 0 = any change triggers re-baseline.
SERVICE_CHANGE_THRESHOLD = 0

# If True, removed environments (no longer active) have their detectors torn down.
TEARDOWN_REMOVED_ENVS = False  # set to True or pass --teardown-removed

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL = f"https://api.{REALM}.signalfx.com"
APP_URL  = f"https://app.{REALM}.signalfx.com"

SCRIPT_DIR = Path(__file__).parent

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url = f"{base_url}{path}"
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            detail = json.loads(raw)
        except Exception:
            detail = raw
        raise RuntimeError(f"Splunk API error {e.code}: {json.dumps(detail)}")


# ── Environment discovery ──────────────────────────────────────────────────────

def discover_all_environments() -> dict[str, list[str]]:
    """
    Query the APM topology for all environments by fetching the global
    topology and examining the sf_environment dimension on each node.

    Because the topology API doesn't directly enumerate environments, we
    query across the full lookback window without an env filter, then
    cross-reference with the trace search API to find per-environment
    service sets.

    Returns: {environment_name: [service, ...], ...}
    The sentinel key None represents the "no environment tag" case.
    """
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - TOPOLOGY_LOOKBACK_HOURS * 3600))

    # Step 1: get the global topology (all envs merged)
    global_result = _request("POST", "/v2/apm/topology", {"timeRange": f"{then}/{now}"})
    all_nodes = (global_result.get("data") or {}).get("nodes", [])
    all_services = [n["serviceName"] for n in all_nodes if not n.get("inferred")]

    if not all_services:
        return {}

    # Step 2: probe known environment names via a SignalFlow metadata query.
    # sf.org.apm.numTracingServices gives per-environment MTS if MetricSets
    # are enabled. Fall back to searching the dimension API for sf_environment
    # values as a more universally available approach.
    env_services: dict[str, list[str]] = {}

    # Try dimension search for sf_environment values
    dim_result = _request("GET",
        "/v2/dimension?query=key:sf_environment&limit=100")
    env_values = [
        d["value"] for d in dim_result.get("results", [])
        if d.get("key") == "sf_environment"
    ]

    if env_values:
        # For each env, get its scoped topology
        for env in env_values:
            env_result = _request("POST", "/v2/apm/topology", {
                "timeRange": f"{then}/{now}",
                "tagFilters": [{"name": "sf_environment", "operator": "equals",
                                "value": env, "scope": "global"}]
            })
            env_nodes = (env_result.get("data") or {}).get("nodes", [])
            env_svcs  = sorted([n["serviceName"] for n in env_nodes
                                 if not n.get("inferred")])
            if env_svcs:
                env_services[env] = env_svcs
    else:
        # No explicit environment tags found — treat the whole org as one
        # un-tagged environment (key = None)
        env_services[None] = sorted(all_services)

    return env_services


# ── State management ───────────────────────────────────────────────────────────

def load_state() -> dict:
    """
    Load the onboarding state file. Structure:
    {
      "environments": {
        "production": {
          "services": [...],
          "provisioned_at": "ISO",
          "baseline_built_at": "ISO",
          "detector_ids": [...]
        },
        ...
      },
      "last_run": "ISO"
    }
    """
    if STATE_PATH.exists():
        with open(STATE_PATH) as f:
            return json.load(f)
    return {"environments": {}, "last_run": None}


def save_state(state: dict) -> None:
    state["last_run"] = datetime.now(timezone.utc).isoformat()
    with open(STATE_PATH, "w") as f:
        json.dump(state, f, indent=2)
    print(f"  State saved -> {STATE_PATH}")


# ── Diff ───────────────────────────────────────────────────────────────────────

def diff_environments(
    current: dict[str, list[str]],
    state: dict,
) -> tuple[list[str], list[str], list[str]]:
    """
    Compare current active environments against the last recorded state.

    Returns:
      new_envs     — environments not in state at all
      updated_envs — environments whose service set changed beyond threshold
      removed_envs — environments in state but no longer active
    """
    recorded = state.get("environments", {})

    new_envs, updated_envs, removed_envs = [], [], []

    for env, services in current.items():
        env_key = env or "__none__"
        if env_key not in recorded:
            new_envs.append(env)
        else:
            prev_services = set(recorded[env_key].get("services", []))
            curr_services = set(services)
            delta = len(curr_services.symmetric_difference(prev_services))
            if delta > SERVICE_CHANGE_THRESHOLD:
                updated_envs.append(env)

    for env_key in recorded:
        env = None if env_key == "__none__" else env_key
        if env not in current:
            removed_envs.append(env)

    return new_envs, updated_envs, removed_envs


# ── Actions ────────────────────────────────────────────────────────────────────

def _run(script: str, args: list[str], dry_run: bool = False) -> bool:
    """Run a sibling script as a subprocess. Returns True on success."""
    cmd = [sys.executable, str(SCRIPT_DIR / script)] + args
    env = {**os.environ}  # inherit SPLUNK_ACCESS_TOKEN, SPLUNK_REALM, etc.

    print(f"    $ {' '.join(cmd)}")
    if dry_run:
        print(f"      [dry-run] skipped")
        return True

    result = subprocess.run(cmd, env=env, capture_output=False)
    if result.returncode != 0:
        print(f"    [ERROR] {script} exited with code {result.returncode}",
              file=sys.stderr)
        return False
    return True


def provision_environment(env: str | None, dry_run: bool = False) -> bool:
    """Run provision_detectors.py for a specific environment."""
    args = ["--environment", env] if env else []
    return _run("provision_detectors.py", args, dry_run=dry_run)


def build_baseline(env: str | None, window_minutes: int = 120,
                   dry_run: bool = False) -> bool:
    """Run trace_fingerprint.py learn for a specific environment."""
    args = ["learn", f"--window-minutes={window_minutes}"]
    if env:
        args = ["--environment", env] + args
    return _run("trace_fingerprint.py", args, dry_run=dry_run)


def build_error_baseline(env: str | None, window_minutes: int = 120,
                          dry_run: bool = False) -> bool:
    """Run error_fingerprint.py learn for a specific environment."""
    args = ["learn", f"--window-minutes={window_minutes}"]
    if env:
        args = ["--environment", env] + args
    return _run("error_fingerprint.py", args, dry_run=dry_run)


def teardown_environment(env: str | None, dry_run: bool = False) -> bool:
    """Run provision_detectors.py --teardown for a specific environment."""
    args = ["--teardown"]
    if env:
        args += ["--environment", env]
    return _run("provision_detectors.py", args, dry_run=dry_run)


def send_audit_event(event_type: str, properties: dict) -> None:
    """Emit an audit event to Splunk so onboarding actions are observable."""
    try:
        _request("POST", "/v2/event", {
            "eventType":  event_type,
            "category":   "AUDIT",
            "dimensions": {"realm": REALM},
            "properties": properties,
            "timestamp":  int(time.time() * 1000),
        })
    except Exception as e:
        print(f"    [warn] Could not send audit event: {e}", file=sys.stderr)


# ── Main orchestration ─────────────────────────────────────────────────────────

def run(
    target_env: str | None = None,
    dry_run: bool = False,
    auto: bool = False,
    teardown_removed: bool = TEARDOWN_REMOVED_ENVS,
    learn_window: int = 120,
) -> None:
    """
    Main onboarding loop.

    target_env — if set, only process this one environment
    auto       — process all discovered environments (new + updated)
    dry_run    — print plan without executing anything
    """
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[onboard] Starting at {ts}")

    # ── Discover ───────────────────────────────────────────────────────────────
    if target_env is not None:
        # Single-env mode: bypass discovery, treat it as a new/forced env
        current_envs = {target_env: []}  # services filled in by provision script
        print(f"[onboard] Single-environment mode: '{target_env}'")
    else:
        print(f"[onboard] Discovering all active environments...")
        current_envs = discover_all_environments()
        if not current_envs:
            print("  No environments found. Ensure APM MetricSets are enabled "
                  "or traces are flowing with deployment.environment set.")
            return
        for env, svcs in sorted(current_envs.items(), key=lambda x: x[0] or ""):
            label = env or "(no environment tag)"
            print(f"  {label}: {len(svcs)} services — {svcs}")

    # ── Diff ───────────────────────────────────────────────────────────────────
    state = load_state()

    if target_env is not None:
        # Forced single-env: always treat as new/updated
        new_envs     = [target_env]
        updated_envs = []
        removed_envs = []
    else:
        new_envs, updated_envs, removed_envs = diff_environments(
            current_envs, state
        )

    print(f"\n[onboard] Diff results:")
    print(f"  New environments:     {[e or '(none)' for e in new_envs] or '—'}")
    print(f"  Updated environments: {[e or '(none)' for e in updated_envs] or '—'}")
    print(f"  Removed environments: {[e or '(none)' for e in removed_envs] or '—'}")

    to_provision = new_envs + updated_envs
    if not to_provision and not (teardown_removed and removed_envs):
        print("\n[onboard] Nothing to do — all environments are up to date.")
        return

    # ── Act ────────────────────────────────────────────────────────────────────
    print(f"\n[onboard] {'[DRY RUN] ' if dry_run else ''}Acting on changes...")

    for env in to_provision:
        label = env or "(no environment tag)"
        action = "new" if env in new_envs else "updated"
        print(f"\n  [{action}] {label}")

        ok_provision      = provision_environment(env, dry_run=dry_run)
        ok_baseline       = build_baseline(env, window_minutes=learn_window,
                                           dry_run=dry_run)
        ok_error_baseline = build_error_baseline(env, window_minutes=learn_window,
                                                  dry_run=dry_run)

        if not dry_run:
            env_key = env or "__none__"
            state.setdefault("environments", {})[env_key] = {
                "services":                sorted(current_envs.get(env, [])),
                "provisioned_at":          ts,
                "baseline_built_at":       ts if ok_baseline else None,
                "error_baseline_built_at": ts if ok_error_baseline else None,
                "last_action":             action,
                "provision_ok":            ok_provision,
                "baseline_ok":             ok_baseline,
                "error_baseline_ok":       ok_error_baseline,
            }
            send_audit_event("behavioral_baseline.onboarded", {
                "environment":        label,
                "action":             action,
                "provision_ok":       str(ok_provision),
                "baseline_ok":        str(ok_baseline),
                "error_baseline_ok":  str(ok_error_baseline),
            })

    if teardown_removed:
        for env in removed_envs:
            label = env or "(no environment tag)"
            print(f"\n  [removed] {label} — tearing down detectors")
            teardown_environment(env, dry_run=dry_run)
            if not dry_run:
                env_key = env or "__none__"
                state["environments"].pop(env_key, None)
                send_audit_event("behavioral_baseline.torn_down",
                                 {"environment": label})

    # ── Save state ─────────────────────────────────────────────────────────────
    if not dry_run:
        save_state(state)
    else:
        print(f"\n[onboard] Dry run complete — no changes written.")

    print(f"\n[onboard] Done.")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Onboarding controller — auto-provisions behavioral baseline "
            "detectors for every active Splunk Observability APM environment."
        )
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help=(
            "Onboard a single specific environment (deployment.environment value). "
            "Skips discovery and always provisions/re-baselines this environment."
        ),
    )
    parser.add_argument(
        "--auto", action="store_true",
        help="Discover all environments and process new/updated ones (cron mode).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would happen without making any changes.",
    )
    parser.add_argument(
        "--teardown-removed", action="store_true",
        default=TEARDOWN_REMOVED_ENVS,
        help="Tear down detectors for environments no longer seen in APM.",
    )
    parser.add_argument(
        "--learn-window", type=int, default=120,
        help="Minutes of trace history to use when building baseline (default: 120).",
    )
    parser.add_argument(
        "--show-state", action="store_true",
        help="Print the current onboarding state and exit.",
    )
    args = parser.parse_args()

    if args.show_state:
        state = load_state()
        print(json.dumps(state, indent=2))
        return

    if not args.environment and not args.auto:
        parser.print_help()
        print(
            "\nExamples:\n"
            "  python onboard.py --auto                    # process all envs\n"
            "  python onboard.py --environment production  # force one env\n"
            "  python onboard.py --auto --dry-run          # preview\n"
            "  python onboard.py --show-state              # inspect state file\n"
        )
        sys.exit(1)

    run(
        target_env=args.environment,
        dry_run=args.dry_run,
        auto=args.auto,
        teardown_removed=args.teardown_removed,
        learn_window=args.learn_window,
    )


if __name__ == "__main__":
    main()
