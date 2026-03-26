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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Cron management ────────────────────────────────────────────────────────────

PYTHON = sys.executable
SCRIPT_DIR_STR = str(Path(__file__).parent)

# Tag embedded in cron comments so we can find/remove our own entries
CRON_TAG = "# behavioral-baseline-managed"

# Cron schedule for per-environment watch jobs (every 5 minutes)
WATCH_SCHEDULE = "*/5 * * * *"

# Cron schedule for auto-onboarding discovery (every 30 minutes)
AUTO_SCHEDULE = "*/30 * * * *"


def _read_crontab() -> list[str]:
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if result.returncode != 0:
        return []
    return result.stdout.splitlines()


def _write_crontab(lines: list[str]) -> None:
    content = "\n".join(lines) + "\n"
    proc = subprocess.run(["crontab", "-"], input=content, text=True,
                          capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"crontab write failed: {proc.stderr}")


def _env_cron_lines(env: str) -> list[str]:
    """Return the 3 cron lines for a given environment."""
    base = f"{SCRIPT_DIR_STR}"
    log_base = f"/tmp/bab_{env.replace('-', '_')}"
    return [
        (f"{WATCH_SCHEDULE} {PYTHON} {base}/trace_fingerprint.py "
         f"--environment {env} watch --window-minutes 5 "
         f">> {log_base}_trace.log 2>&1 {CRON_TAG} env={env}"),
        (f"{WATCH_SCHEDULE} {PYTHON} {base}/error_fingerprint.py "
         f"--environment {env} watch --window-minutes 5 "
         f">> {log_base}_error.log 2>&1 {CRON_TAG} env={env}"),
        (f"{WATCH_SCHEDULE} {PYTHON} {base}/correlate.py "
         f"--environment {env} --window-minutes 15 "
         f">> {log_base}_correlate.log 2>&1 {CRON_TAG} env={env}"),
    ]


def _auto_cron_line() -> str:
    base = f"{SCRIPT_DIR_STR}"
    return (f"{AUTO_SCHEDULE} {PYTHON} {base}/onboard.py --auto "
            f">> /tmp/bab_onboard_auto.log 2>&1 {CRON_TAG} env=__auto__")


def _daily_relearn_cron_lines(env: str) -> list[str]:
    """Return daily re-learn cron lines for both trace and error baselines."""
    base = f"{SCRIPT_DIR_STR}"
    log_base = f"/tmp/bab_{env.replace('-', '_')}"
    return [
        (f"0 2 * * * {PYTHON} {base}/trace_fingerprint.py "
         f"--environment {env} learn --window-minutes 120 "
         f">> {log_base}_relearn.log 2>&1 {CRON_TAG} env={env}"),
        (f"0 2 * * * {PYTHON} {base}/error_fingerprint.py "
         f"--environment {env} learn --window-minutes 120 "
         f">> {log_base}_relearn.log 2>&1 {CRON_TAG} env={env}"),
    ]


def add_env_cron(env: str, dry_run: bool = False) -> None:
    """Add watch + correlate cron jobs for an environment if not already present."""
    lines = _read_crontab()
    existing = "\n".join(lines)

    new_lines = []
    added = 0
    for line in _env_cron_lines(env) + _daily_relearn_cron_lines(env):
        # Check by script + env tag to avoid duplicates
        marker = f"env={env}"
        script = line.split()[5] if len(line.split()) > 5 else ""
        if marker in existing and script in existing:
            continue
        new_lines.append(line)
        added += 1

    if not new_lines:
        print(f"    Cron jobs for '{env}' already present — skipping")
        return

    if dry_run:
        print(f"    [dry-run] Would add {added} cron job(s) for '{env}'")
        return

    _write_crontab(lines + new_lines)
    print(f"    Added {added} cron job(s) for '{env}'")


def remove_env_cron(env: str, dry_run: bool = False) -> None:
    """Remove all managed cron jobs for an environment."""
    lines = _read_crontab()
    marker = f"{CRON_TAG} env={env}"
    kept = [l for l in lines if marker not in l]
    removed = len(lines) - len(kept)
    if removed == 0:
        return
    if dry_run:
        print(f"    [dry-run] Would remove {removed} cron job(s) for '{env}'")
        return
    _write_crontab(kept)
    print(f"    Removed {removed} cron job(s) for '{env}'")


def ensure_auto_cron(dry_run: bool = False) -> None:
    """Add the daily --auto onboard cron job if not already present."""
    lines = _read_crontab()
    marker = f"{CRON_TAG} env=__auto__"
    if any(marker in l for l in lines):
        return
    auto_line = _auto_cron_line()
    if dry_run:
        print(f"    [dry-run] Would add daily auto-onboard cron job")
        return
    _write_crontab(lines + [auto_line])
    print(f"    Added daily auto-onboard cron job (6am)")

# ── Config ─────────────────────────────────────────────────────────────────────

# Load .env file from script directory if present (fallback for cron/non-shell contexts)
_env_file = os.path.join(os.path.dirname(__file__), ".env")
if os.path.exists(_env_file):
    for _line in open(_env_file).read().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN         = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN         = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
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

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

SCRIPT_DIR = Path(__file__).parent

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url = f"{base_url}{path}"
    token = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
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
        # Fetch scoped topology for each environment in parallel
        def _fetch_env_topology(env: str) -> tuple[str, list[str]]:
            env_result = _request("POST", "/v2/apm/topology", {
                "timeRange": f"{then}/{now}",
                "tagFilters": [{"name": "sf_environment", "operator": "equals",
                                "value": env, "scope": "global"}]
            })
            env_nodes = (env_result.get("data") or {}).get("nodes", [])
            return env, sorted([n["serviceName"] for n in env_nodes
                                 if not n.get("inferred")])

        with ThreadPoolExecutor(max_workers=min(len(env_values), 10)) as pool:
            futures = {pool.submit(_fetch_env_topology, env): env
                       for env in env_values}
            for future in as_completed(futures):
                try:
                    env, svcs = future.result()
                    if svcs:
                        env_services[env] = svcs
                except Exception as e:
                    print(f"  [warn] topology fetch error: {e}", file=sys.stderr)
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


# ── Dashboard provisioning ─────────────────────────────────────────────────────

def _get_or_create_dashboard_group(env: str) -> str | None:
    """
    Find the user's personal dashboard group (first group owned by this token's
    user), or fall back to the first writable group. Returns the group ID.
    """
    try:
        result = _request("GET", "/v2/dashboardgroup?limit=50")
        groups = result.get("results", [])
        # Prefer a group named after the env or already containing our dashboards
        for g in groups:
            if "behavioral" in g.get("name", "").lower():
                return g["id"]
        # Fall back to first personal group (email-named)
        for g in groups:
            if "@" in g.get("name", ""):
                return g["id"]
        return groups[0]["id"] if groups else None
    except Exception as e:
        print(f"    [warn] Could not find dashboard group: {e}", file=sys.stderr)
        return None


def _create_chart(name: str, program_text: str, chart_type: str = "Event",
                  extra_options: dict | None = None) -> str | None:
    """Create a single chart and return its ID, or None on failure."""
    options: dict = {"type": chart_type, "time": {"type": "relative", "range": 86400000}}
    if extra_options:
        options.update(extra_options)
    try:
        result = _request("POST", "/v2/chart", {
            "name": name,
            "options": options,
            "programText": program_text,
        })
        return result.get("id")
    except Exception as e:
        print(f"    [warn] Could not create chart '{name}': {e}", file=sys.stderr)
        return None


def provision_dashboard(env: str, dry_run: bool = False) -> str | None:
    """
    Create a 4-panel Behavioral Baseline dashboard for the given environment
    in Splunk Observability. Returns the dashboard ID, or None on failure.

    Panels:
      - Trace Path Drift event feed
      - Error Signature Drift event feed
      - Correlated Anomalies event feed
      - Anomaly event count over time (column chart)
    """
    label = env or "all"
    print(f"    Provisioning dashboard for environment '{label}'...")

    if dry_run:
        print(f"      [dry-run] Would create dashboard: "
              f"Behavioral Baseline — {label}")
        return None

    group_id = _get_or_create_dashboard_group(env)
    if not group_id:
        print(f"    [warn] No dashboard group found — skipping dashboard",
              file=sys.stderr)
        return None

    # Create the 4 charts
    env_filter = f", filter=filter('sf_environment', '{env}')" if env else ""
    charts = [
        _create_chart(
            "Trace Path Drift",
            f"E = events(eventType='trace.path.drift'{env_filter}).publish('Trace Path Drift')",
        ),
        _create_chart(
            "Error Signature Drift",
            f"E = events(eventType='error.signature.drift'{env_filter}).publish('Error Signature Drift')",
        ),
        _create_chart(
            "Correlated Anomalies",
            f"E = events(eventType='behavioral_baseline.correlated_anomaly'{env_filter}).publish('Correlated Anomaly')",
        ),
        _create_chart(
            "Anomaly Event Count (24h)",
            (
                f"A = events(eventType='trace.path.drift'{env_filter}).count().publish('Trace Drift')\n"
                f"B = events(eventType='error.signature.drift'{env_filter}).count().publish('Error Signature')\n"
                f"C = events(eventType='behavioral_baseline.correlated_anomaly'{env_filter}).count().publish('Correlated')"
            ),
            chart_type="TimeSeriesChart",
            extra_options={"defaultPlotType": "ColumnChart"},
        ),
    ]

    chart_ids = [c for c in charts if c]
    if not chart_ids:
        print(f"    [warn] All chart creations failed — skipping dashboard",
              file=sys.stderr)
        return None

    # Layout: 2×2 grid, each chart 6 wide × 3 tall
    positions = [(0, 0), (0, 6), (3, 0), (3, 6)]
    chart_specs = [
        {"chartId": cid, "row": row, "column": col, "width": 6, "height": 3}
        for cid, (row, col) in zip(chart_ids, positions)
    ]

    try:
        result = _request("POST", "/v2/dashboard", {
            "name": f"Behavioral Baseline — {label}",
            "description": (
                f"Real-time behavioral anomalies for environment '{label}'. "
                f"Populated by trace_fingerprint.py, error_fingerprint.py, "
                f"and correlate.py running every 5 minutes."
            ),
            "tags": ["behavioral-baseline", f"env-{label}"],
            "groupId": group_id,
            "charts": chart_specs,
        })
        dashboard_id = result.get("id")
        print(f"    Dashboard created: {dashboard_id} "
              f"(group: {group_id})")
        return dashboard_id
    except Exception as e:
        print(f"    [warn] Could not create dashboard: {e}", file=sys.stderr)
        return None


def teardown_dashboard(dashboard_id: str, dry_run: bool = False) -> None:
    """Delete the dashboard and its charts for a torn-down environment."""
    if dry_run:
        print(f"      [dry-run] Would delete dashboard {dashboard_id}")
        return
    try:
        # Fetch chart IDs before deleting the dashboard
        charts = _request("GET", f"/v2/dashboard/{dashboard_id}/chart")
        chart_ids = [c["id"] for c in charts.get("results", [])]
        _request("DELETE", f"/v2/dashboard/{dashboard_id}")
        for cid in chart_ids:
            try:
                _request("DELETE", f"/v2/chart/{cid}")
            except Exception:
                pass
        print(f"    Dashboard {dashboard_id} deleted ({len(chart_ids)} charts)")
    except Exception as e:
        print(f"    [warn] Could not delete dashboard {dashboard_id}: {e}",
              file=sys.stderr)


def send_audit_event(event_type: str, properties: dict) -> None:
    """Emit an audit event to Splunk so onboarding actions are observable."""
    try:
        _request("POST", "/v2/event", [{
            "eventType":  event_type,
            "category":   "AUDIT",
            "dimensions": {"realm": REALM},
            "properties": properties,
            "timestamp":  int(time.time() * 1000),
        }], base_url=INGEST_URL)
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

    def _onboard_one(env: str) -> dict:
        """Provision + baseline a single environment. Returns result dict."""
        label  = env or "(no environment tag)"
        action = "new" if env in new_envs else "updated"
        print(f"\n  [{action}] {label}")

        # Provision detectors first (prerequisite), then run both baselines
        # and create the dashboard concurrently.
        ok_provision = provision_environment(env, dry_run=dry_run)

        with ThreadPoolExecutor(max_workers=3) as pool:
            bl_future   = pool.submit(build_baseline, env, learn_window, dry_run)
            ebl_future  = pool.submit(build_error_baseline, env, learn_window,
                                      dry_run)
            dash_future = pool.submit(provision_dashboard, env, dry_run)
            ok_baseline       = bl_future.result()
            ok_error_baseline = ebl_future.result()
            dashboard_id      = dash_future.result()

        # Register cron jobs for this environment
        add_env_cron(env, dry_run=dry_run)

        return {
            "env":               env,
            "label":             label,
            "action":            action,
            "ok_provision":      ok_provision,
            "ok_baseline":       ok_baseline,
            "ok_error_baseline": ok_error_baseline,
            "dashboard_id":      dashboard_id,
        }

    # Process all environments concurrently
    results = []
    with ThreadPoolExecutor(max_workers=min(len(to_provision), 4)) as pool:
        futures = {pool.submit(_onboard_one, env): env for env in to_provision}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                env = futures[future]
                print(f"  [error] onboarding {env or '(none)'}: {e}",
                      file=sys.stderr)

    # Ensure the daily auto-onboard cron job exists
    ensure_auto_cron(dry_run=dry_run)

    for r in results:
        if not dry_run:
            env_key = r["env"] or "__none__"
            # Resolve services: prefer topology discovery result; fall back to
            # what provision_detectors discovered (stored in state after first run).
            discovered_services = current_envs.get(r["env"], [])
            if not discovered_services:
                # Single-env mode: re-query topology to capture real service set
                try:
                    from provision_detectors import discover_topology
                    topo = discover_topology(r["env"])
                    discovered_services = topo.get("services", [])
                except Exception:
                    pass
            state.setdefault("environments", {})[env_key] = {
                "services":                sorted(discovered_services),
                "provisioned_at":          ts,
                "baseline_built_at":       ts if r["ok_baseline"] else None,
                "error_baseline_built_at": ts if r["ok_error_baseline"] else None,
                "last_action":             r["action"],
                "provision_ok":            r["ok_provision"],
                "baseline_ok":             r["ok_baseline"],
                "error_baseline_ok":       r["ok_error_baseline"],
                "dashboard_id":            r["dashboard_id"],
            }
            send_audit_event("behavioral_baseline.onboarded", {
                "environment":        r["label"],
                "action":             r["action"],
                "provision_ok":       str(r["ok_provision"]),
                "baseline_ok":        str(r["ok_baseline"]),
                "error_baseline_ok":  str(r["ok_error_baseline"]),
            })

    if teardown_removed:
        for env in removed_envs:
            label = env or "(no environment tag)"
            print(f"\n  [removed] {label} — tearing down detectors, dashboard, and cron jobs")
            teardown_environment(env, dry_run=dry_run)
            remove_env_cron(env, dry_run=dry_run)
            if not dry_run:
                env_key = env or "__none__"
                env_state = state["environments"].get(env_key, {})
                if env_state.get("dashboard_id"):
                    teardown_dashboard(env_state["dashboard_id"], dry_run=dry_run)
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
