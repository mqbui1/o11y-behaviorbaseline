#!/usr/bin/env python3
"""
Behavioral Baseline — Cross-Tier Correlation Engine
=====================================================
Joins anomaly events from Tiers 2 and 3 across a time window and fires a
correlated alert when multiple tiers hit the same service simultaneously.

Why this matters:
  Each tier firing alone may be a false positive — a new trace path could be
  a canary deployment, a new error signature could be a one-off. But when
  Tier 2 (trace path drift) AND Tier 3 (new error signature) both fire on the
  same service within minutes of each other, the probability of a real incident
  is dramatically higher. Correlation turns noisy individual signals into
  high-confidence actionable alerts.

Correlation rules:
  TIER2_TIER3  — trace path drift + error signature drift on same service
  TIER2_TIER1  — trace path drift + topology new-service event on same service
  MULTI_TIER   — 3+ different tiers hit the same service (highest confidence)

Deployment correlation:
  If notify_deployment.py was called within DEPLOYMENT_CORRELATION_WINDOW_MINUTES
  of the anomalies, the correlated alert is annotated with deployment context
  and its severity is downgraded by one level (Critical→Major, Major→Minor).
  This distinguishes "bad change" from "expected change" without suppressing
  the alert entirely.

How it works:
  1. Queries recent custom events from Splunk:
       trace.path.drift        (Tier 2)
       error.signature.drift   (Tier 3)
       topology.new_service    (Tier 1)
       deployment.started      (from notify_deployment.py)
  2. Groups anomaly events by service within a correlation window
  3. If 2+ tiers are represented for the same service, fires a
     behavioral_baseline.correlated_anomaly event with full context
  4. If a deployment event matches the same service+environment within
     DEPLOYMENT_CORRELATION_WINDOW_MINUTES, annotates and downgrades severity

Usage:
  python correlate.py [--window-minutes 30] [--environment petclinicmbtest]

  # Run after each fingerprint watch cycle:
  */5 * * * * python error_fingerprint.py --environment X watch --window-minutes 5
  */5 * * * * python trace_fingerprint.py --environment X watch --window-minutes 5
  */5 * * * * python correlate.py --environment X --window-minutes 15

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN  = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM         = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.",
          file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# Minimum number of distinct tiers that must fire on the same service
# within the correlation window to emit a correlated alert.
MIN_TIERS_FOR_CORRELATION = 2

# How far back (in minutes) to look for deployment events when annotating
# correlated anomalies. A deployment within this window of the anomalies
# is considered a likely cause and downgrades severity by one level.
DEPLOYMENT_CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("DEPLOYMENT_CORRELATION_WINDOW_MINUTES", "60")
)

# Event types emitted by the fingerprint scripts — these are what we query
TIER_EVENT_MAP = {
    "trace.path.drift":       "tier2",
    "error.signature.drift":  "tier3",
    "topology.new_service":   "tier1",
}

# Severity downgrade map for deployment-correlated anomalies
_SEVERITY_DOWNGRADE = {"Critical": "Major", "Major": "Minor", "Minor": "Info"}

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url     = f"{base_url}{path}"
    token   = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
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


# ── Event fetching ─────────────────────────────────────────────────────────────

def fetch_anomaly_events(start_ms: int, end_ms: int,
                          environment: str | None = None) -> list[dict]:
    """
    Fetch all behavioral baseline anomaly events from Splunk within the window.
    Returns a flat list of event dicts, each with injected 'tier' and 'service'
    fields derived from the event dimensions.
    """
    all_events: list[dict] = []

    for event_type, tier in TIER_EVENT_MAP.items():
        params = (
            f"type={event_type}"
            f"&startTime={start_ms}"
            f"&endTime={end_ms}"
            f"&limit=200"
        )
        try:
            result = _request("GET", f"/v2/event?{params}")
        except RuntimeError as e:
            print(f"  [warn] Could not fetch {event_type}: {e}", file=sys.stderr)
            continue

        for event in result.get("results", []):
            dims = event.get("dimensions", {})
            props = event.get("properties", {})

            # Extract service from dimensions (varies by event type)
            service = (
                dims.get("service")
                or dims.get("new_service")
                or props.get("service")
                or _infer_service_from_event(dims, props)
            )
            if not service:
                continue

            # Filter by environment if specified
            event_env = dims.get("environment") or props.get("environment")
            if environment and event_env and event_env != environment:
                continue

            all_events.append({
                "tier":         tier,
                "event_type":   event_type,
                "service":      service,
                "anomaly_type": dims.get("anomaly_type", event_type),
                "message":      props.get("message", ""),
                "timestamp":    event.get("timestamp", 0),
                "environment":  event_env or environment or "all",
                "raw":          event,
            })

    return all_events


def fetch_deployment_events(start_ms: int, end_ms: int,
                             environment: str | None = None) -> list[dict]:
    """
    Fetch deployment.started events emitted by notify_deployment.py within
    the given time window. Returns a list of deployment dicts keyed by
    service and environment.
    """
    params = (
        f"type=deployment.started"
        f"&startTime={start_ms}"
        f"&endTime={end_ms}"
        f"&limit=200"
    )
    try:
        result = _request("GET", f"/v2/event?{params}")
    except RuntimeError as e:
        print(f"  [warn] Could not fetch deployment events: {e}", file=sys.stderr)
        return []

    deployments = []
    for event in result.get("results", []):
        dims  = event.get("dimensions", {})
        props = event.get("properties", {})
        svc   = dims.get("service") or props.get("service")
        if not svc:
            continue
        event_env = dims.get("environment") or props.get("environment") or "all"
        if environment and event_env not in (environment, "all"):
            continue
        deployments.append({
            "service":     svc,
            "environment": event_env,
            "version":     props.get("version", ""),
            "deployer":    props.get("deployer", ""),
            "commit":      props.get("commit", ""),
            "description": props.get("description", ""),
            "timestamp":   event.get("timestamp", 0),
        })
    return deployments


def _infer_service_from_event(dims: dict, props: dict) -> str | None:
    """
    Try to infer a service name from event dimensions/properties when
    no explicit 'service' key is present.
    """
    # trace.path.drift uses root_operation which is "service:operation"
    root_op = dims.get("root_operation", "")
    if ":" in root_op:
        return root_op.split(":")[0]
    # Fall back to checking properties
    return props.get("services", "").split(",")[0] or None


# ── Correlation ────────────────────────────────────────────────────────────────

def correlate(events: list[dict],
              deployments: list[dict] | None = None) -> list[dict]:
    """
    Group events by service and identify cases where multiple tiers fired.
    Returns a list of correlation results — one per affected service that
    meets the MIN_TIERS_FOR_CORRELATION threshold.

    deployments: list of deployment events from fetch_deployment_events().
    When provided, any correlated anomaly whose service+environment matches
    a recent deployment is annotated and its severity downgraded by one level.
    """
    # Index deployments by service for fast lookup
    deploy_by_service: dict[str, list[dict]] = defaultdict(list)
    for d in (deployments or []):
        deploy_by_service[d["service"]].append(d)

    # Group anomaly events by service
    by_service: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        by_service[event["service"]].append(event)

    correlations = []
    for service, svc_events in by_service.items():
        tiers_present = {e["tier"] for e in svc_events}
        if len(tiers_present) < MIN_TIERS_FOR_CORRELATION:
            continue

        # Determine correlation type
        if len(tiers_present) >= 3:
            corr_type = "MULTI_TIER"
            severity  = "Critical"
        elif "tier2" in tiers_present and "tier3" in tiers_present:
            corr_type = "TIER2_TIER3"
            severity  = "Major"
        elif "tier2" in tiers_present and "tier1" in tiers_present:
            corr_type = "TIER2_TIER1"
            severity  = "Major"
        else:
            corr_type = "MULTI_TIER"
            severity  = "Major"

        # Collect all anomaly messages for context
        messages = [e["message"] for e in svc_events if e.get("message")]
        anomaly_types = sorted({e["anomaly_type"] for e in svc_events})
        timestamps = [e["timestamp"] for e in svc_events if e.get("timestamp")]
        time_span_s = (
            (max(timestamps) - min(timestamps)) // 1000
            if len(timestamps) > 1 else 0
        )
        environment = svc_events[0].get("environment", "all")

        # ── Deployment correlation ────────────────────────────────────────────
        # Check if a deployment event for this service exists within the
        # deployment correlation window relative to the earliest anomaly.
        deployment_match: dict | None = None
        earliest_ms = min(timestamps) if timestamps else 0
        window_ms   = DEPLOYMENT_CORRELATION_WINDOW_MINUTES * 60 * 1000
        for d in deploy_by_service.get(service, []):
            delta_ms = abs(d["timestamp"] - earliest_ms)
            if delta_ms <= window_ms:
                deployment_match = d
                break  # use the first (closest) match

        if deployment_match:
            # Downgrade severity — change is likely intentional
            severity = _SEVERITY_DOWNGRADE.get(severity, severity)

        correlations.append({
            "service":           service,
            "corr_type":         corr_type,
            "severity":          severity,
            "tiers":             sorted(tiers_present),
            "event_count":       len(svc_events),
            "anomaly_types":     anomaly_types,
            "messages":          messages,
            "time_span_s":       time_span_s,
            "environment":       environment,
            "earliest_ms":       earliest_ms,
            "latest_ms":         max(timestamps) if timestamps else 0,
            "deployment":        deployment_match,
        })

    # Sort by severity then event count
    order = {"Critical": 0, "Major": 1, "Minor": 2, "Info": 3}
    correlations.sort(key=lambda x: (order.get(x["severity"], 9),
                                     -x["event_count"]))
    return correlations


def send_correlated_event(corr: dict) -> None:
    deploy = corr.get("deployment")
    deploy_note = (
        f" [deployment: {deploy.get('version') or deploy.get('commit') or 'unknown'}]"
        if deploy else ""
    )
    props = {
        "message": (
            f"[{corr['severity']}] {corr['corr_type']} on "
            f"{corr['service']}: {len(corr['tiers'])} tiers fired "
            f"({', '.join(corr['tiers'])}) within "
            f"{corr['time_span_s']}s{deploy_note}"
        ),
        "tiers":         ",".join(corr["tiers"]),
        "anomaly_types": ",".join(corr["anomaly_types"]),
        "event_count":   corr["event_count"],
        "time_span_s":   corr["time_span_s"],
        "environment":   corr["environment"],
        "details":       " | ".join(corr["messages"][:5]),
        "detector_tier": "correlation",
        "detector_name": "cross-tier-correlator",
    }
    if deploy:
        props["deployment_version"]  = deploy.get("version", "")
        props["deployment_commit"]   = deploy.get("commit", "")
        props["deployment_deployer"] = deploy.get("deployer", "")
        props["deployment_desc"]     = deploy.get("description", "")
        props["deployment_ts_ms"]    = str(deploy.get("timestamp", ""))
        props["deployment_correlated"] = "true"

    _request("POST", "/v2/event", [{
        "eventType":  "behavioral_baseline.correlated_anomaly",
        "category":   "ALERT",
        "dimensions": {
            "service":     corr["service"],
            "corr_type":   corr["corr_type"],
            "severity":    corr["severity"],
            "environment": corr["environment"],
            "tiers":       ",".join(corr["tiers"]),
        },
        "properties": props,
        "timestamp":  int(time.time() * 1000),
    }], base_url=INGEST_URL)


# ── Main ───────────────────────────────────────────────────────────────────────

def run(window_minutes: int = 30, environment: str | None = None,
        dry_run: bool = False) -> None:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000
    # Deployment window extends further back than the anomaly window
    deploy_start_ms = now_ms - DEPLOYMENT_CORRELATION_WINDOW_MINUTES * 60 * 1000
    env_desc = f"environment '{environment}'" if environment else "all environments"

    print(f"[correlate] Fetching anomaly events for {env_desc} "
          f"(last {window_minutes}m)...")

    events = fetch_anomaly_events(start_ms, now_ms, environment=environment)
    print(f"  Found {len(events)} anomaly events across "
          f"{len({e['tier'] for e in events})} tiers")

    if not events:
        print("  No anomaly events found — nothing to correlate.")
        return

    # Show per-tier breakdown
    tier_counts: dict[str, int] = defaultdict(int)
    for e in events:
        tier_counts[e["tier"]] += 1
    for tier, count in sorted(tier_counts.items()):
        print(f"    {tier}: {count} event(s)")

    # Fetch deployment events for context
    deployments = fetch_deployment_events(
        deploy_start_ms, now_ms, environment=environment
    )
    if deployments:
        print(f"  Found {len(deployments)} deployment event(s) in last "
              f"{DEPLOYMENT_CORRELATION_WINDOW_MINUTES}m:")
        for d in deployments:
            print(f"    {d['service']}  version={d.get('version') or 'n/a'}  "
                  f"deployer={d.get('deployer') or 'n/a'}")

    correlations = correlate(events, deployments=deployments)
    if not correlations:
        print(f"\n  No correlations found "
              f"(threshold: {MIN_TIERS_FOR_CORRELATION} tiers per service).")
        return

    print(f"\n  Found {len(correlations)} correlated anomaly group(s):\n")
    for corr in correlations:
        deploy = corr.get("deployment")
        deploy_tag = "  [deployment-correlated]" if deploy else ""
        print(f"  [{corr['severity']}] {corr['corr_type']} — "
              f"{corr['service']}{deploy_tag}")
        print(f"    Tiers:         {', '.join(corr['tiers'])}")
        print(f"    Anomaly types: {', '.join(corr['anomaly_types'])}")
        print(f"    Events:        {corr['event_count']} over {corr['time_span_s']}s")
        if deploy:
            print(f"    Deployment:    version={deploy.get('version') or 'n/a'}  "
                  f"commit={deploy.get('commit') or 'n/a'}  "
                  f"deployer={deploy.get('deployer') or 'n/a'}")
            if deploy.get("description"):
                print(f"                   \"{deploy['description']}\"")
        for msg in corr["messages"][:3]:
            print(f"    - {msg}")
        if not dry_run:
            try:
                send_correlated_event(corr)
                print(f"    Event sent (behavioral_baseline.correlated_anomaly)")
            except Exception as e:
                print(f"    Failed to send event: {e}", file=sys.stderr)
        else:
            print(f"    [dry-run] Would send correlated event")
        print()

    if dry_run:
        print(f"  Dry run complete — no events sent.")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cross-tier correlation engine for behavioral baseline alerts"
    )
    parser.add_argument(
        "--window-minutes", type=int, default=30,
        help="How far back to look for anomaly events (default: 30)",
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help="APM environment to scope correlation to (sf_environment).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print correlations without emitting events.",
    )
    args = parser.parse_args()
    run(window_minutes=args.window_minutes,
        environment=args.environment,
        dry_run=args.dry_run)


if __name__ == "__main__":
    main()
