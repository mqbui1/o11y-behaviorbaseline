#!/usr/bin/env python3
"""
Behavioral Baseline — Multi-Environment Anomaly Correlator (#10)
================================================================
Today: correlation only works within one environment. The same anomaly
pattern propagating dev → staging → prod is invisible until it hits prod.

This agent watches for the same anomaly pattern appearing across multiple
environments in sequence:

  [14:02] dev        api-gateway  MISSING_SERVICE (vets-service)
  [14:08] staging    api-gateway  MISSING_SERVICE (vets-service)      ← 6m later
  [14:15] prod       api-gateway  MISSING_SERVICE (vets-service)      ← 13m later
  ⚠️  PROPAGATION DETECTED: api-gateway/MISSING_SERVICE spreading dev→staging→prod

Action: fires a high-priority "behavioral_baseline.propagation.detected" event
BEFORE prod is fully impacted, giving you 5-15 minutes to roll back the deploy.

How it works:
  1. Queries anomaly events across all environments for the last LOOKBACK_HOURS
  2. Groups by (service, anomaly_type) across environments
  3. Detects ordered sequences: if env-A fires, then env-B fires the same pattern
     within PROPAGATION_WINDOW_MINUTES, it's a propagation candidate
  4. Scores by: time-ordering match, environment pipeline position,
     number of environments already affected

Environment pipeline order is auto-detected from naming conventions
(dev/develop < test/staging < preprod/uat < prod/production)
or can be configured explicitly.

Usage:
  python multi_env_correlator.py
  python multi_env_correlator.py --pipeline dev staging prod
  python multi_env_correlator.py --lookback-hours 4 --dry-run

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Max gap between env firings to count as propagation (minutes)
PROPAGATION_WINDOW_MINUTES = int(os.environ.get("PROPAGATION_WINDOW_MINUTES", "60"))

# How far back to look for anomaly events
LOOKBACK_HOURS = int(os.environ.get("PROPAGATION_LOOKBACK_HOURS", "6"))

# Anomaly event types to correlate across environments
ANOMALY_EVENT_TYPES = ["trace.path.drift", "error.signature.drift"]

# Pipeline tier ordering — lower = earlier in pipeline
_PIPELINE_KEYWORDS: list[tuple[int, list[str]]] = [
    (0,  ["local", "dev", "develop", "development"]),
    (1,  ["test", "testing", "ci", "qa"]),
    (2,  ["staging", "stage", "preprod", "pre-prod", "uat"]),
    (3,  ["prod", "production", "live"]),
]


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _emit(event_type: str, dims: dict, props: dict) -> None:
    token   = INGEST_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
    data    = json.dumps([{"eventType": event_type, "category": "ALERT",
                           "dimensions": dims, "properties": props,
                           "timestamp": int(time.time() * 1000)}]).encode()
    req     = urllib.request.Request(f"{INGEST_URL}/v2/event",
                                      data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as _:
            pass
    except Exception as e:
        print(f"  [warn] emit {event_type}: {e}", file=sys.stderr)


# ── Event fetching ────────────────────────────────────────────────────────────

def _fetch_anomaly_events(event_type: str, start_ms: int, end_ms: int,
                          timeout: float = 15.0) -> list[dict]:
    """Fetch ALL anomaly events across ALL environments for this window."""
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url, data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data_lines: list[str] = []
            for raw_line in resp:
                line     = raw_line.decode()
                stripped = line.strip()
                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    payload    = "".join(data_lines)
                    data_lines = []
                    try:
                        msg = json.loads(payload)
                    except json.JSONDecodeError:
                        continue
                    if "properties" in msg and "metadata" in msg:
                        results.append(msg)
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [warn] SignalFlow {event_type}: {e}", file=sys.stderr)
    return results


def _parse_event(msg: dict) -> dict | None:
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})

    environment  = dims.get("environment") or props.get("environment", "")
    anomaly_type = dims.get("anomaly_type") or props.get("anomaly_type", "")
    service = (dims.get("service") or props.get("service")
               or (dims.get("root_operation", "").split(":")[0]
                   if ":" in dims.get("root_operation", "") else None)
               or (props.get("services", "").split(",")[0].strip() or None))

    # Timestamp: try to get from message; fall back to now
    ts_ms = props.get("timestamp") or dims.get("timestamp") or int(time.time() * 1000)
    if isinstance(ts_ms, str):
        try:
            ts_ms = int(ts_ms)
        except ValueError:
            ts_ms = int(time.time() * 1000)

    if not environment or not anomaly_type or not service:
        return None

    return {
        "environment":  environment,
        "service":      service,
        "anomaly_type": anomaly_type,
        "ts_ms":        ts_ms,
        "message":      props.get("message", ""),
    }


# ── Pipeline tier detection ───────────────────────────────────────────────────

def _pipeline_tier(env: str, explicit_pipeline: list[str] | None) -> int:
    if explicit_pipeline:
        try:
            return explicit_pipeline.index(env)
        except ValueError:
            return len(explicit_pipeline)  # unknown env → after all known

    env_lo = env.lower()
    for tier, keywords in _PIPELINE_KEYWORDS:
        if any(kw in env_lo for kw in keywords):
            return tier
    return 99  # unknown


def _order_environments(envs: set[str],
                        explicit_pipeline: list[str] | None) -> list[str]:
    return sorted(envs, key=lambda e: (_pipeline_tier(e, explicit_pipeline), e))


# ── Propagation detection ─────────────────────────────────────────────────────

def detect_propagations(events: list[dict],
                         explicit_pipeline: list[str] | None) -> list[dict]:
    """
    Group events by (service, anomaly_type).
    For each group, find environments that fired in pipeline order
    within PROPAGATION_WINDOW_MINUTES of the first firing.
    """
    groups: dict[tuple, list[dict]] = defaultdict(list)
    all_envs: set[str] = set()

    for ev in events:
        key = (ev["service"], ev["anomaly_type"])
        groups[key].append(ev)
        all_envs.add(ev["environment"])

    ordered_envs = _order_environments(all_envs, explicit_pipeline)
    propagations: list[dict] = []

    for (service, anomaly_type), evs in groups.items():
        # Group by environment: earliest event per environment
        env_first: dict[str, int] = {}
        env_count: dict[str, int] = defaultdict(int)
        for ev in evs:
            env = ev["environment"]
            env_count[env] += 1
            if env not in env_first or ev["ts_ms"] < env_first[env]:
                env_first[ev["environment"]] = ev["ts_ms"]

        if len(env_first) < 2:
            continue  # Only 1 environment — not a propagation

        # Check if environments fired in pipeline order within window
        envs_in_order = [e for e in ordered_envs if e in env_first]
        if len(envs_in_order) < 2:
            continue

        # Verify time ordering matches pipeline ordering
        times = [env_first[e] for e in envs_in_order]
        is_ordered = all(times[i] <= times[i+1] for i in range(len(times)-1))

        if not is_ordered:
            continue

        # All firings within PROPAGATION_WINDOW_MINUTES of the first
        window_ms = PROPAGATION_WINDOW_MINUTES * 60 * 1000
        spread_ms = max(times) - min(times)
        if spread_ms > window_ms:
            continue

        # Compute how far through the pipeline we are
        all_ordered = _order_environments(all_envs, explicit_pipeline)
        pipeline_progress = len(envs_in_order) / max(1, len(all_ordered))

        # Find the last env in the pipeline that hasn't fired yet
        fired_set = set(envs_in_order)
        next_env  = next((e for e in all_ordered if e not in fired_set), None)

        propagations.append({
            "service":          service,
            "anomaly_type":     anomaly_type,
            "environments":     envs_in_order,
            "env_times":        {e: env_first[e] for e in envs_in_order},
            "spread_minutes":   round(spread_ms / 60000, 1),
            "pipeline_progress": pipeline_progress,
            "next_env":         next_env,
            "event_counts":     dict(env_count),
            "severity":         "CRITICAL" if next_env and _pipeline_tier(
                                    next_env, explicit_pipeline) >= 3 else "HIGH",
        })

    return sorted(propagations, key=lambda p: -p["pipeline_progress"])


# ── Report & emit ─────────────────────────────────────────────────────────────

def print_report(propagations: list[dict], all_envs: set[str],
                 explicit_pipeline: list[str] | None) -> None:
    ordered = _order_environments(all_envs, explicit_pipeline)
    print(f"\n{'='*65}")
    print(f"MULTI-ENVIRONMENT PROPAGATION REPORT")
    print(f"  Pipeline order: {' → '.join(ordered)}")
    print(f"  Propagation window: {PROPAGATION_WINDOW_MINUTES}m")
    print(f"{'='*65}")

    if not propagations:
        print("\n  ✅ No cross-environment propagations detected.")
        print()
        return

    for p in propagations:
        sev_icon = "🔴" if p["severity"] == "CRITICAL" else "🟠"
        chain = " → ".join(
            f"{e} (+{round((p['env_times'][e] - min(p['env_times'].values())) / 60000, 1)}m)"
            for e in p["environments"]
        )
        print(f"\n  {sev_icon} {p['severity']}  {p['service']}/{p['anomaly_type']}")
        print(f"     Spread: {chain}")
        print(f"     {len(p['environments'])}/{len(ordered)} envs affected "
              f"({p['pipeline_progress']:.0%} through pipeline)")
        if p["next_env"]:
            next_tier = _pipeline_tier(p["next_env"], explicit_pipeline)
            prod_warn = " ← PRODUCTION NEXT" if next_tier >= 3 else ""
            print(f"     Next at risk: {p['next_env']}{prod_warn}")
        counts = ", ".join(f"{e}: {c}" for e, c in p["event_counts"].items())
        print(f"     Event counts: {counts}")
    print()


def emit_propagations(propagations: list[dict], dry_run: bool) -> None:
    for p in propagations:
        if dry_run:
            print(f"  [dry-run] Would emit propagation.detected: "
                  f"{p['service']}/{p['anomaly_type']} "
                  f"across {', '.join(p['environments'])}")
            continue
        _emit("behavioral_baseline.propagation.detected", {
            "service":      p["service"],
            "anomaly_type": p["anomaly_type"],
            "severity":     p["severity"],
        }, {
            "service":           p["service"],
            "anomaly_type":      p["anomaly_type"],
            "environments":      ",".join(p["environments"]),
            "next_env":          p["next_env"] or "",
            "spread_minutes":    p["spread_minutes"],
            "pipeline_progress": round(p["pipeline_progress"] * 100),
            "severity":          p["severity"],
            "message": (
                f"PROPAGATION: {p['service']}/{p['anomaly_type']} "
                f"spreading {' → '.join(p['environments'])} "
                f"({p['spread_minutes']}m spread). "
                f"Next at risk: {p['next_env'] or 'none'}"
            ),
        })
        print(f"  → behavioral_baseline.propagation.detected emitted: "
              f"{p['service']}/{p['anomaly_type']}")


# ── Main run ──────────────────────────────────────────────────────────────────

def run(lookback_hours: int = LOOKBACK_HOURS,
        explicit_pipeline: list[str] | None = None,
        dry_run: bool = False) -> list[dict]:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - lookback_hours * 3600 * 1000

    print(f"[multi-env-correlator] Fetching anomaly events (last {lookback_hours}h)...")
    all_events: list[dict] = []
    for et in ANOMALY_EVENT_TYPES:
        raw = _fetch_anomaly_events(et, start_ms, now_ms)
        for msg in raw:
            ev = _parse_event(msg)
            if ev:
                all_events.append(ev)

    # Deduplicate environments seen
    all_envs = {ev["environment"] for ev in all_events}
    print(f"  {len(all_events)} events across {len(all_envs)} environment(s): "
          f"{', '.join(sorted(all_envs))}")

    if len(all_envs) < 2:
        print("  Only 1 environment visible — multi-env correlation requires ≥2.")
        return []

    propagations = detect_propagations(all_events, explicit_pipeline)
    print_report(propagations, all_envs, explicit_pipeline)

    if propagations:
        emit_propagations(propagations, dry_run)

    return propagations


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multi-Env Correlator — detects anomaly propagation across environments"
    )
    parser.add_argument("--pipeline", nargs="+", default=None,
                        help="Explicit pipeline order, e.g. --pipeline dev staging prod")
    parser.add_argument("--lookback-hours", type=int, default=LOOKBACK_HOURS)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    result = run(
        lookback_hours=args.lookback_hours,
        explicit_pipeline=args.pipeline,
        dry_run=args.dry_run,
    )

    if args.json:
        # Serialize timestamps to ISO for JSON output
        for p in result:
            p["env_times"] = {e: datetime.fromtimestamp(
                ts/1000, tz=timezone.utc).isoformat()
                for e, ts in p["env_times"].items()}
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
