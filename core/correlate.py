#!/usr/bin/env python3
"""
Behavioral Anomaly Detection Framework — Cross-Tier Correlation Engine
=======================================================================
Joins anomaly signals from Tiers 1, 2, and 3 across a time window and fires a
correlated alert when multiple tiers hit the same service simultaneously.

Why this matters:
  Each tier firing alone may be a false positive — a new trace path could be
  a canary deployment, a new error signature could be a one-off. But when
  Tier 1 (AutoDetect metric alert) AND Tier 2 (trace path drift) AND Tier 3
  (new error signature) all fire on the same service within minutes of each
  other, the probability of a real incident is dramatically higher.
  Correlation turns noisy individual signals into high-confidence actionable alerts.

Correlation rules:
  TIER2_TIER3  — trace path drift + error signature drift on same service
  TIER1_TIER2  — AutoDetect metric alert + trace path drift on same service
  TIER1_TIER3  — AutoDetect metric alert + error signature drift on same service
  MULTI_TIER   — all 3 tiers hit the same service (highest confidence, Critical)

Tier 1 — APM AutoDetect (built-in Splunk detectors):
  Fetched via GET /v2/incident filtered to active incidents within the window.
  Detector tags (svc-<name>, env-<name>) are used to resolve service+environment.
  Only detectors tagged behavioral-baseline-managed are considered, so generic
  infra alerts don't pollute correlation.

Deployment correlation:
  If notify_deployment.py was called within DEPLOYMENT_CORRELATION_WINDOW_MINUTES
  of the anomalies, the correlated alert is annotated with deployment context
  and its severity is downgraded by one level (Critical→Major, Major→Minor).

How it works:
  1. In parallel, fetches:
       trace.path.drift        (Tier 2) — via SignalFlow custom events
       error.signature.drift   (Tier 3) — via SignalFlow custom events
       active incidents        (Tier 1) — via GET /v2/incident + detector tag lookup
       deployment.started               — via SignalFlow custom events
  2. Groups all events by service within the correlation window
  3. If 2+ tiers are represented for the same service, fires a
     behavioral_baseline.correlated_anomaly event with full context
  4. If a deployment event matches within DEPLOYMENT_CORRELATION_WINDOW_MINUTES,
     annotates and downgrades severity

Usage:
  python correlate.py [--window-minutes 30] [--environment petclinicmbtest]

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

# Load .env file from script directory if present (fallback for cron/non-shell contexts)
_env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(_env_file):
    for _line in open(_env_file).read().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN  = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM         = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.",
          file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Minimum number of distinct tiers that must fire on the same service
# within the correlation window to emit a correlated alert.
MIN_TIERS_FOR_CORRELATION = 2

# How far back (in minutes) to look for deployment events when annotating
# correlated anomalies. A deployment within this window of the anomalies
# is considered a likely cause and downgrades severity by one level.
DEPLOYMENT_CORRELATION_WINDOW_MINUTES = int(
    os.environ.get("DEPLOYMENT_CORRELATION_WINDOW_MINUTES", "60")
)

# Custom event types emitted by the fingerprint scripts — queried via SignalFlow
TIER_EVENT_MAP = {
    "trace.path.drift":       "tier2",
    "error.signature.drift":  "tier3",
}

# Only consider Tier 1 incidents from detectors carrying this tag.
# Prevents generic infra alerts from polluting APM service correlation.
TIER1_DETECTOR_TAG = "behavioral-baseline-managed"

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

def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 10.0) -> list[dict]:
    """
    Query custom events via the SignalFlow streaming API.
    Returns a list of raw event dicts parsed from the SSE stream.
    Uses events(eventType="...") — works on all realms including us1.
    """
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url,
        data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # SSE streams each object as multiple "data: <line>" lines followed
            # by a blank line. Accumulate data lines until blank, then parse.
            data_lines: list[str] = []
            for raw_line in resp:
                line = raw_line.decode()
                stripped = line.strip()

                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    # End of one SSE message block — parse accumulated JSON
                    payload = "".join(data_lines)
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
        print(f"  [warn] SignalFlow query for {event_type}: {e}", file=sys.stderr)
    return results


def _fetch_events_for_type(event_type: str, tier: str,
                            start_ms: int, end_ms: int,
                            environment: str | None) -> list[dict]:
    """Fetch and normalize events for a single event type via SignalFlow."""
    raw_events = _signalflow_events(event_type, start_ms, end_ms)

    events = []
    for msg in raw_events:
        dims  = msg.get("metadata", {})
        props = msg.get("properties", {})

        service = (
            dims.get("service")
            or dims.get("new_service")
            or props.get("service")
            or _infer_service_from_event(dims, props)
        )
        if not service:
            continue

        event_env = dims.get("environment") or props.get("environment")
        if environment and event_env and event_env not in (environment, "all"):
            continue

        events.append({
            "tier":         tier,
            "event_type":   event_type,
            "service":      service,
            "anomaly_type": dims.get("anomaly_type", event_type),
            "message":      props.get("message", ""),
            "timestamp":    msg.get("timestampMs", 0),
            "environment":  event_env or environment or "all",
            "raw":          msg,
        })
    return events


def fetch_anomaly_events(start_ms: int, end_ms: int,
                          environment: str | None = None) -> list[dict]:
    """
    Fetch all behavioral baseline anomaly events from Splunk within the window.
    Returns a flat list of event dicts, each with injected 'tier' and 'service'
    fields derived from the event dimensions.
    All tier fetches run in parallel.
    """
    all_events: list[dict] = []
    with ThreadPoolExecutor(max_workers=len(TIER_EVENT_MAP)) as pool:
        futures = {
            pool.submit(_fetch_events_for_type, et, tier, start_ms, end_ms,
                        environment): et
            for et, tier in TIER_EVENT_MAP.items()
        }
        for future in as_completed(futures):
            try:
                all_events.extend(future.result())
            except Exception as e:
                print(f"  [warn] fetch error: {e}", file=sys.stderr)
    return all_events


def fetch_deployment_events(start_ms: int, end_ms: int,
                             environment: str | None = None) -> list[dict]:
    """
    Fetch deployment.started events emitted by notify_deployment.py within
    the given time window via SignalFlow. Returns a list of deployment dicts.
    """
    raw_events = _signalflow_events("deployment.started", start_ms, end_ms)

    deployments = []
    for msg in raw_events:
        dims  = msg.get("metadata", {})
        props = msg.get("properties", {})
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
            "timestamp":   msg.get("timestampMs", 0),
        })
    return deployments


def fetch_autodetect_incidents(start_ms: int, end_ms: int,
                               environment: str | None = None) -> list[dict]:
    """
    Fetch active Tier 1 incidents from Splunk AutoDetect detectors.

    Strategy:
      1. GET /v2/incident?includeResolved=false — active incidents only
      2. Filter to incidents whose anomalyStateUpdateTimestamp falls within window
      3. For each incident, resolve service + environment from detector tags
         (tags like svc-<name> and env-<name> are set by provision_detectors.py)
      4. Only include incidents from detectors tagged TIER1_DETECTOR_TAG to
         avoid generic infra alerts polluting APM correlation
    """
    # Step 1: fetch all active incidents (paginate up to 200)
    try:
        resp = _request("GET", "/v2/incident?includeResolved=false&limit=200")
    except Exception as e:
        print(f"  [warn] Could not fetch Tier 1 incidents: {e}", file=sys.stderr)
        return []

    raw_incidents = resp if isinstance(resp, list) else resp.get("results", [])

    # Step 2: build a detector tag index to avoid redundant API calls
    # Collect all unique detector IDs from relevant incidents first
    candidate_ids = set()
    for inc in raw_incidents:
        ts = inc.get("anomalyStateUpdateTimestamp", 0)
        if start_ms <= ts <= end_ms:
            candidate_ids.add(inc.get("detectorId"))

    if not candidate_ids:
        return []

    # Fetch detector details in parallel to resolve tags
    detector_index: dict[str, dict] = {}  # detectorId -> {service, environment, tier}

    def _fetch_detector_tags(det_id: str) -> tuple[str, dict]:
        try:
            d = _request("GET", f"/v2/detector/{det_id}")
            tags = d.get("tags", [])
            if TIER1_DETECTOR_TAG not in tags:
                return det_id, {}
            svc = next((t[4:] for t in tags if t.startswith("svc-")), None)
            env = next((t[4:] for t in tags if t.startswith("env-")), None)
            tier = next((t for t in tags if t in ("tier1b", "tier3", "tier4")), "tier1")
            return det_id, {"service": svc, "environment": env, "tier": tier,
                            "name": d.get("name", det_id)}
        except Exception:
            return det_id, {}

    with ThreadPoolExecutor(max_workers=min(10, len(candidate_ids))) as pool:
        for det_id, info in pool.map(_fetch_detector_tags, candidate_ids):
            if info:
                detector_index[det_id] = info

    # Step 3: build tier1 events from qualifying incidents
    events = []
    for inc in raw_incidents:
        ts = inc.get("anomalyStateUpdateTimestamp", 0)
        if not (start_ms <= ts <= end_ms):
            continue
        det_id = inc.get("detectorId")
        info = detector_index.get(det_id)
        if not info or not info.get("service"):
            continue
        svc = info["service"]
        env = info["environment"] or "all"
        if environment and env not in (environment, "all"):
            continue
        detector_tier = info["tier"]
        # Map detector tier tags to tier1 for correlation purposes
        # (tier1b = request rate, tier3/tier4 via AutoDetect = metric-based)
        events.append({
            "tier":         "tier1",
            "event_type":   "autodetect.incident",
            "service":      svc,
            "anomaly_type": detector_tier.upper(),
            "message":      f"AutoDetect: {inc.get('detectLabel', info['name'])} "
                            f"(severity={inc.get('severity', 'unknown')})",
            "timestamp":    ts,
            "environment":  env,
            "raw":          inc,
        })
    return events


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

    Tier 1 (AutoDetect incidents), Tier 2 (trace drift), and Tier 3 (error
    signature drift) are all represented in the events list. When all three
    fire on the same service → MULTI_TIER at Critical severity.

    deployments: list of deployment events from fetch_deployment_events().
    When provided, any correlated anomaly whose service+environment matches
    a recent deployment is annotated and its severity downgraded by one level.
    """
    # Index deployments by service for fast lookup
    deploy_by_service: dict[str, list[dict]] = defaultdict(list)
    for d in (deployments or []):
        deploy_by_service[d["service"]].append(d)

    # Group anomaly events by service.
    # For MISSING_SERVICE tier2 events, also fan out to every affected service
    # listed in props["services"] so that a tier3 error on e.g. customers-service
    # joins the same group as a MISSING_SERVICE silent on api-gateway:PUT customers-service.
    by_service: dict[str, list[dict]] = defaultdict(list)
    for event in events:
        by_service[event["service"]].append(event)
        if event.get("anomaly_type") == "MISSING_SERVICE":
            raw_props = event.get("raw", {}).get("properties", {})
            extra_svcs = [s.strip() for s in raw_props.get("services", "").split(",") if s.strip()]
            for svc in extra_svcs:
                if svc != event["service"]:
                    by_service[svc].append(event)

    correlations = []
    for service, svc_events in by_service.items():
        tiers_present = {e["tier"] for e in svc_events}
        if len(tiers_present) < MIN_TIERS_FOR_CORRELATION:
            continue

        # Determine correlation type
        has1 = "tier1" in tiers_present
        has2 = "tier2" in tiers_present
        has3 = "tier3" in tiers_present
        if has1 and has2 and has3:
            corr_type = "MULTI_TIER"
            severity  = "Critical"
        elif has2 and has3:
            corr_type = "TIER2_TIER3"
            severity  = "Major"
        elif has1 and has2:
            corr_type = "TIER1_TIER2"
            severity  = "Major"
        elif has1 and has3:
            corr_type = "TIER1_TIER3"
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
        # Check if a deployment event exists for this service OR any affected
        # service mentioned in the anomaly events (e.g. a deployment for
        # vets-service that surfaces as MISSING_SERVICE on api-gateway).
        deployment_match: dict | None = None
        earliest_ms = min(timestamps) if timestamps else 0
        window_ms   = DEPLOYMENT_CORRELATION_WINDOW_MINUTES * 60 * 1000
        # Collect all services mentioned in anomaly event messages
        candidate_services = {service}
        for deployed_svc in deploy_by_service:
            for e in svc_events:
                if deployed_svc in e.get("message", ""):
                    candidate_services.add(deployed_svc)
        for candidate in candidate_services:
            for d in deploy_by_service.get(candidate, []):
                delta_ms = abs(d["timestamp"] - earliest_ms)
                if delta_ms <= window_ms:
                    deployment_match = d
                    break
            if deployment_match:
                break

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
            "sf_environment":       environment,
            "earliest_ms":       earliest_ms,
            "latest_ms":         max(timestamps) if timestamps else 0,
            "deployment":        deployment_match,
        })

    # Sort by severity then event count
    order = {"Critical": 0, "Major": 1, "Minor": 2, "Info": 3}
    correlations.sort(key=lambda x: (order.get(x["severity"], 9),
                                     -x["event_count"]))
    return correlations


def send_metric(metric_name: str, value: int, dimensions: dict) -> None:
    """Emit a gauge metric — immediately queryable via SignalFlow data()."""
    _request("POST", "/v2/datapoint", {
        "gauge": [{
            "metric":     metric_name,
            "value":      value,
            "dimensions": dimensions,
            "timestamp":  int(time.time() * 1000),
        }],
    }, base_url=INGEST_URL)


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
        "environment":   corr.get("sf_environment") or corr.get("environment", "all"),
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

    dims = {
        "service":        corr["service"],
        "corr_type":      corr["corr_type"],
        "severity":       corr["severity"],
        "sf_environment": corr.get("sf_environment", corr.get("environment", "all")),
        "tiers":          ",".join(corr["tiers"]),
    }
    _request("POST", "/v2/event", [{
        "eventType":  "behavioral_baseline.correlated_anomaly",
        "category":   "ALERT",
        "dimensions": dims,
        "properties": props,
        "timestamp":  int(time.time() * 1000),
    }], base_url=INGEST_URL)
    send_metric("behavioral_baseline.correlated_anomaly.count", 1, dims)


# ── Main ───────────────────────────────────────────────────────────────────────

def run(window_minutes: int = 30, environment: str | None = None,
        dry_run: bool = False) -> None:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000
    # Deployment window extends further back than the anomaly window
    deploy_start_ms = now_ms - DEPLOYMENT_CORRELATION_WINDOW_MINUTES * 60 * 1000
    env_desc = f"environment '{environment}'" if environment else "all environments"

    print(f"[correlate] Fetching anomaly + deployment events in parallel ({env_desc})...")

    # Fetch tier2/3 custom events, tier1 AutoDetect incidents, and deployment
    # events all concurrently
    with ThreadPoolExecutor(max_workers=3) as pool:
        anomaly_future    = pool.submit(fetch_anomaly_events, start_ms, now_ms,
                                        environment)
        tier1_future      = pool.submit(fetch_autodetect_incidents, start_ms, now_ms,
                                        environment)
        deployment_future = pool.submit(fetch_deployment_events, deploy_start_ms,
                                        now_ms, environment)
        events      = anomaly_future.result()
        tier1_events = tier1_future.result()
        deployments = deployment_future.result()

    events = events + tier1_events

    tiers_seen = {e["tier"] for e in events}
    print(f"  Found {len(events)} anomaly events across {len(tiers_seen)} tier(s)")

    if not events:
        print("  No anomaly events found — nothing to correlate.")
        return

    # Show per-tier breakdown
    tier_counts: dict[str, int] = defaultdict(int)
    for e in events:
        tier_counts[e["tier"]] += 1
    for tier, count in sorted(tier_counts.items()):
        print(f"    {tier}: {count} event(s)")

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
        if dry_run:
            print(f"    [dry-run] Would send correlated event")
        print()

    if dry_run:
        print(f"  Dry run complete — no events sent.")
        return

    # Send all correlated events in parallel
    if correlations:
        with ThreadPoolExecutor(max_workers=len(correlations)) as pool:
            futures = {pool.submit(send_correlated_event, c): c["service"]
                       for c in correlations}
            for future in as_completed(futures):
                svc = futures[future]
                try:
                    future.result()
                    print(f"  Event sent for {svc} "
                          f"(behavioral_baseline.correlated_anomaly)")
                except Exception as e:
                    print(f"  Failed to send event for {svc}: {e}",
                          file=sys.stderr)


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
