#!/usr/bin/env python3
"""
Tier 2 Behavioral Baseline — Trace Path Drift Detector
=======================================================
Detects when execution paths (trace fingerprints) change structurally:
  - New span sequence never seen before
  - New service appearing in a trace
  - Span count deviation beyond threshold
  - Missing expected span in a known trace type

How it works:
  1. LEARN mode  — sample recent traces, build a baseline fingerprint DB,
                   save to baseline.json. Run once to establish the baseline.
  2. WATCH mode  — sample recent traces, compare to baseline, emit a Splunk
                   custom event for every unknown fingerprint found.
                   Run on a cron schedule (e.g. every 5 minutes).

A "fingerprint" is a stable, order-preserving description of a trace's
execution path built from the parent→child span edges, not raw span IDs.
It captures structure (which services call which, and what operations) while
being immune to normal variation in timing and IDs.

Usage:
  # Build baseline from last 2 hours of traces
  python trace_fingerprint.py learn

  # Watch mode — compare last 10 minutes to baseline, alert on drift
  python trace_fingerprint.py watch

  # Watch with custom look-back window
  python trace_fingerprint.py watch --window-minutes 5

  # Print current baseline (no API calls)
  python trace_fingerprint.py show

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM            (default: us0)
  BASELINE_PATH           (default: ./baseline.json)
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")
BASELINE_PATH = Path(os.environ.get("BASELINE_PATH", "./baseline.json"))

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# Services to monitor — matches our known topology
MONITORED_SERVICES = [
    "api-gateway",
    "customers-service",
    "vets-service",
    "visits-service",
]

# Minimum span count for a trace to be worth fingerprinting.
# 1-span traces (single health checks with no children) are ignored —
# they carry no structural information.
MIN_SPANS = 2

# How many traces to sample per service per run
TRACES_PER_SERVICE = 50

# A fingerprint seen fewer than this many times in the baseline is treated
# as "rare" and won't suppress alerts if it reappears later.
MIN_BASELINE_OCCURRENCES = 2

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


def _qs(params: dict) -> str:
    filtered = {k: str(v) for k, v in params.items() if v is not None}
    return ("?" + urllib.parse.urlencode(filtered)) if filtered else ""


# ── Splunk APM helpers ─────────────────────────────────────────────────────────

def search_traces(services: list[str], start_ms: int, end_ms: int,
                  limit: int = TRACES_PER_SERVICE) -> list[dict]:
    """Search for traces involving any of the given services."""
    tag_filters = [{"tag": "sf_service", "operation": "IN", "values": services}]
    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": end_ms},
            "filters": [{"traceFilter": {"tags": tag_filters}, "filterType": "traceFilter"}],
            "samplingFactor": 100,
        },
        "sectionsParameters": [{"sectionType": "traceExamples", "limit": limit}],
    }
    start_body = {
        "operationName": "StartAnalyticsSearch",
        "variables": {"parameters": parameters},
        "query": "query StartAnalyticsSearch($parameters: JSON!) { startAnalyticsSearch(parameters: $parameters) }",
    }
    start_result = _request("POST", "/v2/apm/graphql?op=StartAnalyticsSearch",
                             start_body, base_url=APP_URL)
    job_id = ((start_result.get("data") or {}).get("startAnalyticsSearch") or {}).get("jobId")
    if not job_id:
        print(f"  [warn] search_traces: no jobId returned", file=sys.stderr)
        return []

    get_body = {
        "operationName": "GetAnalyticsSearch",
        "variables": {"jobId": job_id},
        "query": "query GetAnalyticsSearch($jobId: ID!) { getAnalyticsSearch(jobId: $jobId) }",
    }
    for _ in range(15):
        result = _request("POST", "/v2/apm/graphql?op=GetAnalyticsSearch",
                          get_body, base_url=APP_URL)
        sections = ((result.get("data") or {}).get("getAnalyticsSearch") or {}).get("sections", [])
        for section in sections:
            if section.get("sectionType") == "traceExamples":
                examples = section.get("legacyTraceExamples") or []
                if section.get("isComplete"):
                    return examples[:limit]
        time.sleep(0.5)
    return []


def get_trace_full(trace_id: str) -> dict | None:
    """Fetch full span details for a single trace via GraphQL."""
    query = (
        "query TraceFullDetailsLessValidation($id: ID!) {"
        " trace(id: $id) {"
        " traceID startTime duration"
        " spans { spanID operationName serviceName parentSpanID"
        " startTime duration tags { key value } } } }"
    )
    gql_body = {
        "operationName": "TraceFullDetailsLessValidation",
        "variables": {"id": trace_id},
        "query": query,
    }
    result = _request("POST", "/v2/apm/graphql?op=TraceFullDetailsLessValidation",
                      gql_body, base_url=APP_URL)
    return (result.get("data") or {}).get("trace")


def send_custom_event(event_type: str, dimensions: dict, properties: dict) -> None:
    """Emit a custom event to Splunk Observability Cloud."""
    event = {
        "eventType": event_type,
        "category": "USER_DEFINED",
        "dimensions": dimensions,
        "properties": properties,
        "timestamp": int(time.time() * 1000),
    }
    _request("POST", "/v2/event", event)


# ── Fingerprinting ─────────────────────────────────────────────────────────────

def build_fingerprint(trace: dict) -> dict | None:
    """
    Build a stable structural fingerprint from a trace's span tree.

    The fingerprint captures:
      - The ordered list of (parent_service:parent_op → child_service:child_op) edges
        sorted by start time so the sequence is deterministic
      - The set of unique services involved
      - The total span count
      - The root operation (entry point)

    It intentionally ignores:
      - Span IDs (change every request)
      - Timestamps and durations (vary normally)
      - Tag values like HTTP status codes (vary normally)

    Returns None if the trace has fewer than MIN_SPANS spans.
    """
    spans = trace.get("spans", [])
    if len(spans) < MIN_SPANS:
        return None

    # Index spans by ID for parent lookup
    by_id = {s["spanID"]: s for s in spans}

    # Sort spans by start time to get a deterministic traversal order
    sorted_spans = sorted(spans, key=lambda s: s.get("startTime", 0))

    # Build edge list: (parent_service:parent_op → child_service:child_op)
    edges = []
    for span in sorted_spans:
        parent_id = span.get("parentSpanID")
        if parent_id and parent_id in by_id:
            parent = by_id[parent_id]
            edge = (
                f"{parent['serviceName']}:{parent['operationName']}",
                f"{span['serviceName']}:{span['operationName']}",
            )
            edges.append(edge)

    # Find root span (no parent in this trace)
    root_span = next(
        (s for s in sorted_spans if not s.get("parentSpanID") or s["parentSpanID"] not in by_id),
        sorted_spans[0] if sorted_spans else None,
    )
    root_op = f"{root_span['serviceName']}:{root_span['operationName']}" if root_span else "unknown"

    services = sorted({s["serviceName"] for s in spans})

    # The canonical path is the edge list in traversal order
    path = " → ".join(f"{e[0]} → {e[1]}" for e in edges) if edges else root_op

    # Stable hash of the structural path (not including timing)
    fp_hash = hashlib.sha256(path.encode()).hexdigest()[:16]

    return {
        "hash":       fp_hash,
        "path":       path,
        "root_op":    root_op,
        "services":   services,
        "span_count": len(spans),
        "edge_count": len(edges),
    }


def classify_anomaly(fp: dict, baseline: dict) -> dict | None:
    """
    Compare a fingerprint against the baseline.
    Returns an anomaly description dict, or None if the trace is normal.

    Anomaly types:
      NEW_FINGERPRINT     — execution path never seen before
      NEW_SERVICE         — a service not in any baseline trace for this root op
      SPAN_COUNT_SPIKE    — span count > 2× the baseline max for this root op
      MISSING_SERVICE     — a service always present is now absent
    """
    root_op = fp["root_op"]
    fp_hash = fp["hash"]

    # Gather baseline entries for the same entry point
    baseline_for_root = {
        h: info for h, info in baseline.get("fingerprints", {}).items()
        if info.get("root_op") == root_op
           and info.get("occurrences", 0) >= MIN_BASELINE_OCCURRENCES
    }

    # ── NEW_FINGERPRINT ───────────────────────────────────────────────────────
    if fp_hash not in baseline.get("fingerprints", {}):
        return {
            "type":    "NEW_FINGERPRINT",
            "message": f"Unknown execution path for '{root_op}'",
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # ── NEW_SERVICE ───────────────────────────────────────────────────────────
    all_baseline_services: set[str] = set()
    for info in baseline_for_root.values():
        all_baseline_services.update(info.get("services", []))

    new_services = set(fp["services"]) - all_baseline_services
    if new_services:
        return {
            "type":    "NEW_SERVICE",
            "message": f"New service(s) in trace for '{root_op}': {sorted(new_services)}",
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # ── SPAN_COUNT_SPIKE ──────────────────────────────────────────────────────
    baseline_max_spans = max(
        (info.get("span_count", 0) for info in baseline_for_root.values()),
        default=0,
    )
    if baseline_max_spans > 0 and fp["span_count"] > baseline_max_spans * 2:
        return {
            "type":    "SPAN_COUNT_SPIKE",
            "message": f"Span count spike for '{root_op}': {fp['span_count']} vs baseline max {baseline_max_spans}",
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # ── MISSING_SERVICE ───────────────────────────────────────────────────────
    # Services that appear in ALL baseline traces for this root op (always-present set)
    if baseline_for_root:
        always_present = set.intersection(
            *[set(info.get("services", [])) for info in baseline_for_root.values()]
        )
        missing = always_present - set(fp["services"])
        if missing:
            return {
                "type":    "MISSING_SERVICE",
                "message": f"Expected service(s) absent from '{root_op}': {sorted(missing)}",
                "detail":  f"Path: {fp['path']}",
                "fp":      fp,
            }

    return None  # known-good


# ── Baseline I/O ───────────────────────────────────────────────────────────────

def load_baseline() -> dict:
    if BASELINE_PATH.exists():
        with open(BASELINE_PATH) as f:
            return json.load(f)
    return {"fingerprints": {}, "created_at": None, "updated_at": None}


def save_baseline(baseline: dict) -> None:
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline saved → {BASELINE_PATH}  "
          f"({len(baseline['fingerprints'])} fingerprints)")


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_learn(window_minutes: int = 120) -> None:
    """
    Sample traces from the last `window_minutes` minutes and build the
    baseline fingerprint database.  Merges into any existing baseline.
    """
    print(f"[learn] Sampling last {window_minutes}m of traces for services: "
          f"{MONITORED_SERVICES}")

    now_ms  = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    traces = search_traces(MONITORED_SERVICES, start_ms, now_ms,
                           limit=TRACES_PER_SERVICE * len(MONITORED_SERVICES))
    print(f"  Found {len(traces)} candidate traces")

    baseline = load_baseline()
    if not baseline["created_at"]:
        baseline["created_at"] = datetime.now(timezone.utc).isoformat()

    fingerprints = baseline.setdefault("fingerprints", {})
    new_count = 0
    updated_count = 0
    skipped = 0

    for meta in traces:
        trace_id = meta.get("traceId")
        if not trace_id:
            continue

        trace = get_trace_full(trace_id)
        if not trace:
            skipped += 1
            continue

        fp = build_fingerprint(trace)
        if fp is None:
            skipped += 1
            continue

        h = fp["hash"]
        if h in fingerprints:
            fingerprints[h]["occurrences"] = fingerprints[h].get("occurrences", 1) + 1
            updated_count += 1
        else:
            fingerprints[h] = {
                "hash":        h,
                "path":        fp["path"],
                "root_op":     fp["root_op"],
                "services":    fp["services"],
                "span_count":  fp["span_count"],
                "edge_count":  fp["edge_count"],
                "occurrences": 1,
                "first_seen":  datetime.now(timezone.utc).isoformat(),
            }
            new_count += 1
            print(f"  [new] {fp['root_op']}  →  {fp['path'][:80]}...")

    print(f"  Summary: {new_count} new fingerprints, "
          f"{updated_count} updated, {skipped} skipped (too shallow)")
    save_baseline(baseline)


def cmd_watch(window_minutes: int = 10) -> None:
    """
    Sample recent traces and compare to baseline.
    Emits a Splunk custom event for every unknown fingerprint found.
    """
    print(f"[watch] Checking last {window_minutes}m of traces...")

    baseline = load_baseline()
    if not baseline["fingerprints"]:
        print("  [warn] Baseline is empty — run 'learn' first.", file=sys.stderr)
        sys.exit(1)

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    traces = search_traces(MONITORED_SERVICES, start_ms, now_ms,
                           limit=TRACES_PER_SERVICE * len(MONITORED_SERVICES))
    print(f"  Found {len(traces)} candidate traces")

    anomalies_found = 0
    checked = 0
    skipped = 0

    # Deduplicate — only alert once per unique fingerprint per run
    alerted_hashes: set[str] = set()

    for meta in traces:
        trace_id = meta.get("traceId")
        if not trace_id:
            continue

        trace = get_trace_full(trace_id)
        if not trace:
            skipped += 1
            continue

        fp = build_fingerprint(trace)
        if fp is None:
            skipped += 1
            continue

        checked += 1

        # Skip if we already alerted for this exact fingerprint this run
        if fp["hash"] in alerted_hashes:
            continue

        anomaly = classify_anomaly(fp, baseline)
        if anomaly:
            alerted_hashes.add(fp["hash"])
            anomalies_found += 1

            print(f"\n  ⚠  ANOMALY DETECTED")
            print(f"     Type:    {anomaly['type']}")
            print(f"     Message: {anomaly['message']}")
            print(f"     Detail:  {anomaly['detail']}")
            print(f"     TraceID: {trace_id}")

            # Fire custom event to Splunk
            try:
                send_custom_event(
                    event_type="trace.path.drift",
                    dimensions={
                        "anomaly_type":   anomaly["type"],
                        "root_operation": fp["root_op"],
                        "fp_hash":        fp["hash"],
                    },
                    properties={
                        "message":        anomaly["message"],
                        "detail":         anomaly["detail"],
                        "trace_id":       trace_id,
                        "path":           fp["path"],
                        "services":       ",".join(fp["services"]),
                        "span_count":     fp["span_count"],
                        "detector_tier":  "tier2",
                        "detector_name":  "trace-path-drift",
                    },
                )
                print(f"     ✓ Custom event sent to Splunk (eventType: trace.path.drift)")
            except Exception as e:
                print(f"     ✗ Failed to send event: {e}", file=sys.stderr)

    print(f"\n  Checked {checked} traces, {skipped} skipped, "
          f"{anomalies_found} anomalies detected")

    if anomalies_found == 0:
        print("  ✓ All trace paths match baseline")


def cmd_show() -> None:
    """Print the current baseline fingerprints to stdout."""
    baseline = load_baseline()
    fps = baseline.get("fingerprints", {})
    if not fps:
        print("Baseline is empty — run 'learn' first.")
        return

    print(f"Baseline fingerprints ({len(fps)} total)")
    print(f"  Created:  {baseline.get('created_at', 'unknown')}")
    print(f"  Updated:  {baseline.get('updated_at', 'unknown')}")
    print()

    # Group by root operation for readable output
    by_root: dict[str, list] = defaultdict(list)
    for info in fps.values():
        by_root[info["root_op"]].append(info)

    for root_op, entries in sorted(by_root.items()):
        print(f"  {root_op}  ({len(entries)} pattern{'s' if len(entries) != 1 else ''})")
        for e in sorted(entries, key=lambda x: -x.get("occurrences", 0)):
            services = ", ".join(e.get("services", []))
            print(f"    [{e['hash']}]  seen={e.get('occurrences', '?')}  "
                  f"spans={e.get('span_count', '?')}  services=[{services}]")
            path_short = e.get("path", "")[:100]
            print(f"      {path_short}{'...' if len(e.get('path','')) > 100 else ''}")
        print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Tier 2 trace path drift detector for Splunk Observability Cloud"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_learn = sub.add_parser("learn", help="Build baseline from recent traces")
    p_learn.add_argument("--window-minutes", type=int, default=120,
                         help="How far back to sample traces (default: 120)")

    p_watch = sub.add_parser("watch", help="Compare recent traces to baseline")
    p_watch.add_argument("--window-minutes", type=int, default=10,
                         help="Look-back window in minutes (default: 10)")

    sub.add_parser("show", help="Print current baseline")

    args = parser.parse_args()

    if args.command == "learn":
        cmd_learn(args.window_minutes)
    elif args.command == "watch":
        cmd_watch(args.window_minutes)
    elif args.command == "show":
        cmd_show()


if __name__ == "__main__":
    main()
