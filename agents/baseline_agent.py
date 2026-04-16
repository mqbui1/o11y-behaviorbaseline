#!/usr/bin/env python3
"""
Behavioral Baseline — Baseline Lifecycle Agent
===============================================
Long-running Deployment that replaces the baseline-learn and baseline-onboard
CronJobs. Runs all baseline lifecycle tasks on configurable intervals without
relying on Kubernetes CronJob scheduling.

Responsibilities:
  - Learn + promote trace and error fingerprints on LEARN_INTERVAL_MINUTES
  - Push updated baseline to ConfigMap + inject into otelcol-fingerprint pods
  - Run all post-learn steps: noise pruning, coverage audit, adaptive thresholds,
    baseline health monitor (auto-fix), self-healing after incidents, runbook gen
  - Run onboarding discovery on ONBOARD_INTERVAL_MINUTES
  - Continuously monitor anomaly rate via IncidentTracker; trigger emergency
    re-learn when an incident resolves (outside the normal schedule)
  - Emit behavioral_baseline.baseline_agent.alive heartbeat each cycle

Usage (in-cluster):
  kubectl apply -f otel-processor/k8s/baseline-agent-deployment.yaml

Usage (local):
  python agents/baseline_agent.py --environment petclinicmbtest

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us1)
  SPLUNK_INGEST_TOKEN       (default: ACCESS_TOKEN)
  ENVIRONMENT               single env (or use ENVIRONMENTS for multi-env)

Optional env vars:
  ENVIRONMENTS              comma-separated list of environments
  LEARN_INTERVAL_MINUTES    how often to run learn cycle (default: 120)
  ONBOARD_INTERVAL_MINUTES  how often to run onboarding discovery (default: 360)
  HEAL_POLL_INTERVAL_S      seconds between anomaly rate checks (default: 120)
  LEARN_WINDOW_MINUTES      how far back each learn cycle looks (default: 60)
  DRY_RUN                   set to "true" to skip writes and kubectl ops
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Path setup ─────────────────────────────────────────────────────────────────

_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

# ── .env loader ────────────────────────────────────────────────────────────────

_ENV_FILE = _ROOT / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN  = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM         = os.environ.get("SPLUNK_REALM", "us1")
INGEST_URL    = f"https://ingest.{REALM}.signalfx.com"

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

# Intervals
LEARN_INTERVAL_MINUTES   = int(os.environ.get("LEARN_INTERVAL_MINUTES",   "120"))
ONBOARD_INTERVAL_MINUTES = int(os.environ.get("ONBOARD_INTERVAL_MINUTES", "360"))
HEAL_POLL_INTERVAL_S     = int(os.environ.get("HEAL_POLL_INTERVAL_S",     "120"))
LEARN_WINDOW_MINUTES     = int(os.environ.get("LEARN_WINDOW_MINUTES",     "60"))
DRY_RUN                  = os.environ.get("DRY_RUN", "false").lower() == "true"

_DATA_DIR  = _ROOT / "data"
_CORE_DIR  = _ROOT / "core"
_AGENT_DIR = _ROOT / "agents"
TRACE_FP   = str(_CORE_DIR / "trace_fingerprint.py")
ERROR_FP   = str(_CORE_DIR / "error_fingerprint.py")

# ── Optional agent imports ─────────────────────────────────────────────────────

try:
    from core.trace_fingerprint import cmd_learn as _tf_learn, cmd_promote as _tf_promote
    _TF_AVAILABLE = True
except ImportError:
    _TF_AVAILABLE = False

try:
    from core.error_fingerprint import cmd_learn as _ef_learn, cmd_promote as _ef_promote
    _EF_AVAILABLE = True
except ImportError:
    _EF_AVAILABLE = False

try:
    from agents.noise_learner import run as _noise_run
    _NOISE_AVAILABLE = True
except ImportError:
    _NOISE_AVAILABLE = False

try:
    from agents.coverage_auditor import compute_coverage, emit_low_coverage_events
    _COVERAGE_AVAILABLE = True
except ImportError:
    _COVERAGE_AVAILABLE = False

try:
    from agents.adaptive_thresholds import run as _adaptive_run
    _ADAPTIVE_AVAILABLE = True
except ImportError:
    _ADAPTIVE_AVAILABLE = False

try:
    from agents.baseline_monitor import run_health_check, auto_fix
    _MONITOR_AVAILABLE = True
except ImportError:
    _MONITOR_AVAILABLE = False

try:
    from agents.baseline_healer import (
        measure_anomaly_rate, pick_best_window, heal,
        IncidentTracker,
        SPIKE_THRESHOLD, RESOLVED_THRESHOLD,
        MIN_SPIKE_MINUTES, STABILIZATION_MINUTES,
        RATE_WINDOW_MINUTES,
    )
    _HEALER_AVAILABLE = True
except ImportError:
    _HEALER_AVAILABLE = False

try:
    from agents.runbook_generator import generate_runbook
    _RUNBOOK_AVAILABLE = True
except ImportError:
    _RUNBOOK_AVAILABLE = False

try:
    from agents.onboarding_advisor import advise
    _ONBOARD_ADVISOR_AVAILABLE = True
except ImportError:
    _ONBOARD_ADVISOR_AVAILABLE = False

try:
    import onboard
    _ONBOARD_AVAILABLE = True
except ImportError:
    _ONBOARD_AVAILABLE = False


# ── Splunk helpers ─────────────────────────────────────────────────────────────

def _emit_event(event_type: str, dims: dict, props: dict) -> None:
    body = json.dumps([{
        "eventType": event_type,
        "category":  "USER_DEFINED",
        "dimensions": dims,
        "properties": props,
        "timestamp":  int(time.time() * 1000),
    }]).encode()
    req = urllib.request.Request(
        f"{INGEST_URL}/v2/event", data=body,
        headers={"X-SF-Token": INGEST_TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"  [warn] Could not emit {event_type}: {e}", file=sys.stderr)


def _emit_heartbeat(environment: str) -> None:
    body = json.dumps([{
        "metric": "behavioral_baseline.baseline_agent.alive",
        "value":  1,
        "dimensions": {"sf_environment": environment},
        "timestamp": int(time.time() * 1000),
    }]).encode()
    req = urllib.request.Request(
        f"{INGEST_URL}/v2/datapoint", data=body,
        headers={"X-SF-Token": INGEST_TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


# ── kubectl helpers ────────────────────────────────────────────────────────────

def _kubectl(*args: str) -> tuple[int, str]:
    """Run a kubectl command. Returns (returncode, combined output)."""
    result = subprocess.run(
        ["kubectl"] + list(args),
        capture_output=True, text=True, timeout=30,
    )
    out = (result.stdout + result.stderr).strip()
    return result.returncode, out


def _push_baseline(env: str, baseline_path: Path) -> bool:
    """Update ConfigMap and inject baseline into running otelcol-fingerprint pods."""
    if DRY_RUN:
        print(f"  [dry-run] Would push {baseline_path.name} to ConfigMap + pods")
        return True

    # Update ConfigMap (delete+create so data is always fresh)
    rc, out = _kubectl("delete", "configmap", "behavioral-baseline", "--ignore-not-found")
    rc, out = _kubectl("create", "configmap", "behavioral-baseline",
                       f"--from-file=baseline.json={baseline_path}")
    if rc != 0:
        print(f"  [warn] ConfigMap update failed: {out}", file=sys.stderr)
        return False
    print(f"  ConfigMap behavioral-baseline updated.")

    # Inject into running pods
    rc, pods_out = _kubectl(
        "get", "pods", "-l", "app=otelcol-fingerprint",
        "--field-selector=status.phase=Running",
        "-o", "jsonpath={.items[*].metadata.name}",
    )
    pods = pods_out.split() if rc == 0 and pods_out else []
    injected = 0
    for pod in pods:
        rc, _ = _kubectl("cp", str(baseline_path),
                         f"{pod}:/baseline/baseline.json", "-c", "otelcol")
        if rc == 0:
            injected += 1
            print(f"    {pod}: injected")
        else:
            print(f"    {pod}: skipped")
    print(f"  Injected into {injected}/{len(pods)} pod(s).")
    return True


# ── Learn cycle ────────────────────────────────────────────────────────────────

def run_learn_cycle(environments: list[str],
                    window_minutes: int = LEARN_WINDOW_MINUTES,
                    reset: bool = False,
                    window_offset_minutes: int = 0) -> None:
    """Run learn+promote+push for every environment in the list."""
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    print(f"\n[baseline-agent] === Learn cycle @ {ts} "
          f"(window={window_minutes}m, envs={','.join(environments)}) ===")

    for env in environments:
        print(f"\n[baseline-agent] --- {env} ---")

        # 1. Learn trace fingerprints
        print(f"  Learning trace fingerprints...")
        if _TF_AVAILABLE and not DRY_RUN:
            try:
                _tf_learn(
                    window_minutes=window_minutes,
                    environment=env,
                    reset=reset,
                    window_offset_minutes=window_offset_minutes,
                )
            except Exception as e:
                print(f"  [error] trace learn failed: {e}", file=sys.stderr)
                _emit_event("behavioral_baseline.learn_failed",
                            {"sf_environment": env},
                            {"environment": env, "step": "trace_learn", "message": str(e)})
                continue
        else:
            rc, out = _run_subprocess(
                [sys.executable, TRACE_FP, "--environment", env,
                 "learn", "--window-minutes", str(window_minutes)]
                + (["--reset"] if reset else [])
                + (["--window-offset-minutes", str(window_offset_minutes)]
                   if window_offset_minutes else [])
            )
            if rc != 0:
                print(f"  [error] trace learn subprocess failed", file=sys.stderr)
                _emit_event("behavioral_baseline.learn_failed",
                            {"sf_environment": env},
                            {"environment": env, "step": "trace_learn",
                             "message": f"subprocess exit {rc}"})
                continue

        # 2. Promote trace fingerprints
        print(f"  Promoting trace fingerprints...")
        if _TF_AVAILABLE and not DRY_RUN:
            try:
                _tf_promote(hashes=None, environment=env)
            except Exception as e:
                print(f"  [warn] trace promote failed: {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, TRACE_FP, "--environment", env, "promote"])

        # 3. Learn error fingerprints
        print(f"  Learning error fingerprints...")
        if _EF_AVAILABLE and not DRY_RUN:
            try:
                _ef_learn(
                    window_minutes=window_minutes,
                    environment=env,
                    reset=reset,
                    window_offset_minutes=window_offset_minutes,
                )
            except Exception as e:
                print(f"  [warn] error learn failed: {e}", file=sys.stderr)
        else:
            _run_subprocess(
                [sys.executable, ERROR_FP, "--environment", env,
                 "learn", "--window-minutes", str(window_minutes)]
                + (["--reset"] if reset else [])
            )

        # 4. Promote error fingerprints
        if _EF_AVAILABLE and not DRY_RUN:
            try:
                _ef_promote(hashes=None, environment=env)
            except Exception as e:
                print(f"  [warn] error promote failed: {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, ERROR_FP, "--environment", env, "promote"])

        # 5. Push to ConfigMap + pods
        baseline_path = _DATA_DIR / f"baseline.{env}.json"
        if baseline_path.exists():
            _push_baseline(env, baseline_path)
        else:
            print(f"  [warn] baseline file not found: {baseline_path}", file=sys.stderr)

    # 6. Post-learn steps (run once, across all envs)
    _run_post_learn_steps(environments)


def _run_subprocess(cmd: list[str]) -> tuple[int, str]:
    result = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=str(_ROOT), timeout=300)
    if result.stdout:
        for line in result.stdout.strip().splitlines()[-5:]:
            print(f"    {line}")
    return result.returncode, result.stderr


# ── Post-learn steps ───────────────────────────────────────────────────────────

def _run_post_learn_steps(environments: list[str]) -> None:
    print(f"\n[baseline-agent] Running post-learn steps...")

    # Noise pruning
    print("  [1/6] Noise pruning...")
    if _NOISE_AVAILABLE and not DRY_RUN:
        try:
            _noise_run(apply=True)
        except Exception as e:
            print(f"  [warn] noise_learner: {e}", file=sys.stderr)
    else:
        _run_subprocess([sys.executable, str(_AGENT_DIR / "noise_learner.py"), "--apply"])

    # Coverage audit
    print("  [2/6] Coverage audit...")
    for env in environments:
        if _COVERAGE_AVAILABLE and not DRY_RUN:
            try:
                results = compute_coverage(env, None, LEARN_WINDOW_MINUTES, 200)
                emit_low_coverage_events(results, env)
            except Exception as e:
                print(f"  [warn] coverage_auditor({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "coverage_auditor.py"),
                             "--environment", env,
                             "--window-minutes", str(LEARN_WINDOW_MINUTES), "--emit"])

    # Adaptive thresholds
    print("  [3/6] Adaptive thresholds...")
    for env in environments:
        if _ADAPTIVE_AVAILABLE and not DRY_RUN:
            try:
                _adaptive_run(environment=env, emit=True)
            except Exception as e:
                print(f"  [warn] adaptive_thresholds({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "adaptive_thresholds.py"),
                             "--environment", env, "--emit"])

    # Baseline health monitor + auto-fix
    print("  [4/6] Baseline health monitor...")
    for env in environments:
        if _MONITOR_AVAILABLE and not DRY_RUN:
            try:
                issues = run_health_check(env)
                if issues:
                    auto_fix(issues, dry_run=False)
            except Exception as e:
                print(f"  [warn] baseline_monitor({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "baseline_monitor.py"),
                             "--environment", env, "--auto-fix"])

    # Runbook generation
    print("  [5/6] Runbook generation...")
    for env in environments:
        if _RUNBOOK_AVAILABLE and not DRY_RUN:
            try:
                generate_runbook(env, force=False)
            except Exception as e:
                print(f"  [warn] runbook_generator({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "runbook_generator.py"),
                             "--environment", env])

    # Dedup state pruning (entries older than 7 days)
    print("  [6/6] Dedup state pruning...")
    try:
        cutoff = time.time() - 7 * 24 * 3600
        for f in _DATA_DIR.glob("*dedup_state*.json"):
            try:
                raw = json.loads(f.read_text())
                pruned = {k: v for k, v in raw.items()
                          if isinstance(v, dict) and v.get("ts", 0) > cutoff}
                if len(pruned) < len(raw):
                    f.write_text(json.dumps(pruned))
                    print(f"    pruned {f.name} ({len(raw)-len(pruned)} entries removed)")
            except Exception:
                pass
    except Exception as e:
        print(f"  [warn] dedup pruning: {e}", file=sys.stderr)

    print("[baseline-agent] Post-learn steps complete.")


# ── Onboarding cycle ───────────────────────────────────────────────────────────

def run_onboard_cycle(environments: list[str]) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
    print(f"\n[baseline-agent] === Onboard cycle @ {ts} ===")

    # Auto-discover new environments
    if _ONBOARD_AVAILABLE and not DRY_RUN:
        try:
            onboard.main_auto()
        except AttributeError:
            _run_subprocess([sys.executable, str(_ROOT / "onboard.py"), "--auto"])
        except Exception as e:
            print(f"  [warn] onboard.py: {e}", file=sys.stderr)
    else:
        _run_subprocess([sys.executable, str(_ROOT / "onboard.py"), "--auto"])

    # Onboarding advisor + runbook for each known environment
    for env in environments:
        if _ONBOARD_ADVISOR_AVAILABLE and not DRY_RUN:
            try:
                advise(env, apply=False)
            except Exception as e:
                print(f"  [warn] onboarding_advisor({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "onboarding_advisor.py"),
                             "--environment", env])

        if _RUNBOOK_AVAILABLE and not DRY_RUN:
            try:
                generate_runbook(env, force=False)
            except Exception as e:
                print(f"  [warn] runbook_generator({env}): {e}", file=sys.stderr)
        else:
            _run_subprocess([sys.executable, str(_AGENT_DIR / "runbook_generator.py"),
                             "--environment", env])

    print("[baseline-agent] Onboard cycle complete.")


# ── Main poll loop ─────────────────────────────────────────────────────────────

def run_poll(environments: list[str]) -> None:
    """
    Main loop. Runs learn and onboard cycles on their respective intervals.
    Between cycles, polls the anomaly rate for self-healing triggers.
    """
    now = time.time()
    last_learn_s   = 0.0   # force learn on first cycle
    last_onboard_s = 0.0   # force onboard on first cycle

    learn_interval_s   = LEARN_INTERVAL_MINUTES * 60
    onboard_interval_s = ONBOARD_INTERVAL_MINUTES * 60

    # One IncidentTracker per environment for self-healing
    trackers: dict[str, Any] = {}
    if _HEALER_AVAILABLE:
        for env in environments:
            trackers[env] = IncidentTracker(
                spike_threshold       = SPIKE_THRESHOLD,
                resolved_threshold    = RESOLVED_THRESHOLD,
                min_spike_minutes     = MIN_SPIKE_MINUTES,
                stabilization_minutes = STABILIZATION_MINUTES,
            )

    print(f"[baseline-agent] Starting poll loop")
    print(f"  environments:    {', '.join(environments)}")
    print(f"  learn interval:  {LEARN_INTERVAL_MINUTES}m")
    print(f"  onboard interval:{ONBOARD_INTERVAL_MINUTES}m")
    print(f"  heal poll:       {HEAL_POLL_INTERVAL_S}s")
    print(f"  dry_run:         {DRY_RUN}")

    while True:
        now = time.time()

        # ── Scheduled learn cycle ──────────────────────────────────────────────
        if now - last_learn_s >= learn_interval_s:
            try:
                run_learn_cycle(environments)
            except Exception as e:
                print(f"[baseline-agent] [error] Learn cycle failed: {e}",
                      file=sys.stderr)
                _emit_event("behavioral_baseline.learn_failed",
                            {"sf_environment": environments[0] if environments else "all"},
                            {"message": str(e), "step": "learn_cycle"})
            last_learn_s = time.time()

        # ── Scheduled onboard cycle ────────────────────────────────────────────
        if now - last_onboard_s >= onboard_interval_s:
            try:
                run_onboard_cycle(environments)
            except Exception as e:
                print(f"[baseline-agent] [error] Onboard cycle failed: {e}",
                      file=sys.stderr)
            last_onboard_s = time.time()

        # ── Self-healing: anomaly rate monitor ────────────────────────────────
        if _HEALER_AVAILABLE:
            for env in environments:
                try:
                    now_ms       = int(time.time() * 1000)
                    window_ms    = RATE_WINDOW_MINUTES * 60 * 1000
                    current_rate = measure_anomaly_rate(
                        now_ms - window_ms, now_ms, env
                    )
                    ts_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    print(f"[{ts_str}] {env}: anomaly rate={current_rate:.2f}/min "
                          f"state={trackers[env].state}")

                    action = trackers[env].update(current_rate, now_ms)
                    if action == "HEAL":
                        best = pick_best_window(
                            trackers[env].incident_start_ms, env
                        )
                        if best:
                            print(f"[baseline-agent] Healing '{env}' — "
                                  f"re-learning from window: {best['label']}")
                            heal(trackers[env].incident_start_ms, env,
                                 best, DRY_RUN)
                            # Trigger an immediate learn cycle after healing
                            run_learn_cycle([env],
                                           window_minutes=best.get("duration_min",
                                                                    LEARN_WINDOW_MINUTES),
                                           reset=True,
                                           window_offset_minutes=best.get(
                                               "offset_min", 0))
                        trackers[env].reset_after_heal()
                except Exception as e:
                    print(f"  [warn] healer({env}): {e}", file=sys.stderr)

        # ── Heartbeat ─────────────────────────────────────────────────────────
        for env in environments:
            _emit_heartbeat(env)

        time.sleep(HEAL_POLL_INTERVAL_S)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    global DRY_RUN, LEARN_INTERVAL_MINUTES, ONBOARD_INTERVAL_MINUTES

    parser = argparse.ArgumentParser(
        description="Baseline Lifecycle Agent — continuous learn/heal/onboard"
    )
    parser.add_argument("--environment", type=str, default=None,
                        help="Single environment (overridden by ENVIRONMENTS env var)")
    parser.add_argument("--learn-interval", type=int, default=LEARN_INTERVAL_MINUTES,
                        help=f"Minutes between learn cycles (default: {LEARN_INTERVAL_MINUTES})")
    parser.add_argument("--onboard-interval", type=int, default=ONBOARD_INTERVAL_MINUTES,
                        help=f"Minutes between onboard cycles (default: {ONBOARD_INTERVAL_MINUTES})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip writes, kubectl ops, and Splunk emissions")
    parser.add_argument("--once", action="store_true",
                        help="Run one learn cycle and exit (useful for testing)")
    args = parser.parse_args()

    if args.dry_run:
        DRY_RUN = True

    # Build environment list: CLI arg < ENVIRONMENT env var < ENVIRONMENTS env var
    env_str = os.environ.get("ENVIRONMENTS") or os.environ.get("ENVIRONMENT") or args.environment
    if not env_str:
        print("Error: specify --environment or set ENVIRONMENT/ENVIRONMENTS", file=sys.stderr)
        sys.exit(1)
    environments = [e.strip() for e in env_str.split(",") if e.strip()]

    LEARN_INTERVAL_MINUTES   = args.learn_interval
    ONBOARD_INTERVAL_MINUTES = args.onboard_interval

    if args.once:
        run_learn_cycle(environments)
        return

    run_poll(environments)


if __name__ == "__main__":
    main()
