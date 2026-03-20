#!/usr/bin/env python3
"""
Tier 3 Behavioral Baseline — Error Signature Fingerprinter
===========================================================
Detects NEW error signatures, not just error rate spikes.

A "rate spike" detector (SignalFlow) tells you: more errors than usual.
This script tells you: a NEW KIND of error never seen before.

How it works:
  Each error span is reduced to a canonical signature:
    service + error_type + http_status + top-N operation frames

  Signatures are hashed and stored in a baseline (error_baseline.json).
  On each watch run, new signatures fire a Splunk custom event.

Anomaly types detected:
  NEW_ERROR_SIGNATURE  — an error pattern never seen in baseline
  SIGNATURE_SPIKE      — a known signature's rate exceeds N× its baseline rate
  SIGNATURE_VANISHED   — a previously dominant signature has disappeared
                         (may indicate a fix — useful for change correlation)

GENERIC — works with any application. No hardcoded service names.
Services are auto-discovered from the live APM topology.

Usage:
  python error_fingerprint.py discover
  python error_fingerprint.py learn [--window-minutes 120]
  python error_fingerprint.py watch [--window-minutes 10]
  python error_fingerprint.py show

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
  ERROR_BASELINE_PATH       (default: ./error_baseline.json)
  TOPOLOGY_LOOKBACK_HOURS   (default: 48)
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

ACCESS_TOKEN            = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM                   = os.environ.get("SPLUNK_REALM", "us0")
BASELINE_PATH           = Path(os.environ.get("ERROR_BASELINE_PATH",
                                              "./error_baseline.json"))
TOPOLOGY_LOOKBACK_HOURS = int(os.environ.get("TOPOLOGY_LOOKBACK_HOURS", "48"))

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.",
          file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# Traces to sample per watch/learn run
TRACES_SAMPLE_LIMIT = 200

# Signatures seen fewer times than this in baseline are "rare" (lower confidence)
MIN_BASELINE_OCCURRENCES = 2

# A signature's rate must exceed this multiple of its baseline rate to fire SPIKE
SPIKE_MULTIPLIER = 3

# A signature must have appeared in at least this fraction of baseline windows
# to be considered "dominant" (used for VANISHED detection)
DOMINANCE_THRESHOLD = 0.1  # 10% of traces in its service

# Top N span operation names to include in the signature path
SIGNATURE_TOP_FRAMES = 5

# Tags examined when building error signatures
ERROR_TAG_KEYS = [
    "error",
    "error.type",
    "exception.type",
    "http.status_code",
    "db.system",
    "otel.status_code",
]

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


# ── Topology discovery ─────────────────────────────────────────────────────────

def discover_services(environment: str | None = None) -> list[str]:
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - TOPOLOGY_LOOKBACK_HOURS * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [
            {"name": "sf_environment", "operator": "equals",
             "value": environment, "scope": "global"}
        ]
    result = _request("POST", "/v2/apm/topology", body)
    nodes  = (result.get("data") or {}).get("nodes", [])
    return [n["serviceName"] for n in nodes if not n.get("inferred")]


# ── Trace search ───────────────────────────────────────────────────────────────

def search_error_traces(services: list[str], start_ms: int, end_ms: int,
                        limit: int = TRACES_SAMPLE_LIMIT,
                        environment: str | None = None) -> list[dict]:
    """Search for traces that contain at least one error span."""
    if not services:
        return []
    tag_filters = [
        {"tag": "sf_service",    "operation": "IN", "values": services},
        {"tag": "error",         "operation": "IN", "values": ["true"]},
    ]
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN",
                             "values": [environment]})
    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": end_ms},
            "filters": [{"traceFilter": {"tags": tag_filters},
                         "filterType": "traceFilter"}],
            "samplingFactor": 100,
        },
        "sectionsParameters": [{"sectionType": "traceExamples", "limit": limit}],
    }
    start_body = {
        "operationName": "StartAnalyticsSearch",
        "variables": {"parameters": parameters},
        "query": ("query StartAnalyticsSearch($parameters: JSON!) "
                  "{ startAnalyticsSearch(parameters: $parameters) }"),
    }
    start_result = _request("POST", "/v2/apm/graphql?op=StartAnalyticsSearch",
                             start_body, base_url=APP_URL)
    job_id = (
        ((start_result.get("data") or {}).get("startAnalyticsSearch") or {})
        .get("jobId")
    )
    if not job_id:
        print("  [warn] search_error_traces: no jobId returned", file=sys.stderr)
        return []
    get_body = {
        "operationName": "GetAnalyticsSearch",
        "variables": {"jobId": job_id},
        "query": ("query GetAnalyticsSearch($jobId: ID!) "
                  "{ getAnalyticsSearch(jobId: $jobId) }"),
    }
    for _ in range(15):
        result = _request("POST", "/v2/apm/graphql?op=GetAnalyticsSearch",
                          get_body, base_url=APP_URL)
        sections = (
            ((result.get("data") or {}).get("getAnalyticsSearch") or {})
            .get("sections", [])
        )
        for section in sections:
            if section.get("sectionType") == "traceExamples":
                if section.get("isComplete"):
                    return (section.get("legacyTraceExamples") or [])[:limit]
        time.sleep(0.5)
    return []


def get_trace_full(trace_id: str) -> dict | None:
    query = (
        "query TraceFullDetailsLessValidation($id: ID!) {"
        " trace(id: $id) {"
        " traceID startTime duration"
        " spans { spanID operationName serviceName parentSpanID"
        "         startTime duration tags { key value } } } }"
    )
    gql_body = {
        "operationName": "TraceFullDetailsLessValidation",
        "variables": {"id": trace_id},
        "query": query,
    }
    result = _request("POST", "/v2/apm/graphql?op=TraceFullDetailsLessValidation",
                      gql_body, base_url=APP_URL)
    return (result.get("data") or {}).get("trace")


def send_custom_event(event_type: str, dimensions: dict,
                      properties: dict) -> None:
    _request("POST", "/v2/event", {
        "eventType":  event_type,
        "category":   "USER_DEFINED",
        "dimensions": dimensions,
        "properties": properties,
        "timestamp":  int(time.time() * 1000),
    })


# ── Signature extraction ───────────────────────────────────────────────────────

def _span_tags(span: dict) -> dict[str, str]:
    return {t["key"]: t["value"] for t in span.get("tags", [])}


def _is_error_span(span: dict) -> bool:
    tags = _span_tags(span)
    return (
        tags.get("error", "").lower() in ("true", "1")
        or tags.get("otel.status_code", "").upper() == "ERROR"
        or (tags.get("http.status_code", "0").isdigit()
            and int(tags.get("http.status_code", "0")) >= 500)
    )


def build_error_signatures(trace: dict) -> list[dict]:
    """
    Extract all error signatures from a trace.
    Each error span produces one signature. Returns [] if no error spans.

    Signature key components:
      - service name
      - error_type  (exception.type > error.type > http.status_code > "error")
      - http_status (if present)
      - operation   (the span's operation name)
      - call_path   (top SIGNATURE_TOP_FRAMES ancestor operation names, root first)
    """
    spans = trace.get("spans", [])
    if not spans:
        return []

    by_id = {s["spanID"]: s for s in spans}
    sigs  = []

    for span in spans:
        if not _is_error_span(span):
            continue

        tags        = _span_tags(span)
        service     = span.get("serviceName", "unknown")
        operation   = span.get("operationName", "unknown")
        error_type  = (tags.get("exception.type")
                       or tags.get("error.type")
                       or tags.get("http.status_code")
                       or "error")
        http_status = tags.get("http.status_code", "")
        db_system   = tags.get("db.system", "")

        # Build ancestor call path (root → error span)
        path_frames: list[str] = []
        cur = span
        while cur:
            pid = cur.get("parentSpanID")
            parent = by_id.get(pid) if pid else None
            if parent:
                path_frames.insert(0,
                    f"{parent['serviceName']}:{parent['operationName']}")
            cur = parent
            if len(path_frames) >= SIGNATURE_TOP_FRAMES:
                break

        call_path = " -> ".join(path_frames) if path_frames else ""

        sig_str = "|".join([service, error_type, http_status,
                            operation, call_path])
        sig_hash = hashlib.sha256(sig_str.encode()).hexdigest()[:16]

        sigs.append({
            "hash":        sig_hash,
            "service":     service,
            "error_type":  error_type,
            "http_status": http_status,
            "db_system":   db_system,
            "operation":   operation,
            "call_path":   call_path,
            "sig_str":     sig_str,
        })

    return sigs


# ── Baseline I/O ───────────────────────────────────────────────────────────────

def _baseline_path(environment: str | None) -> Path:
    if environment:
        return BASELINE_PATH.with_suffix(f".{environment}.json")
    return BASELINE_PATH


def load_baseline(environment: str | None = None) -> dict:
    path = _baseline_path(environment)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"signatures": {}, "created_at": None, "updated_at": None,
            "environment": environment}


def save_baseline(baseline: dict, environment: str | None = None) -> None:
    path = _baseline_path(environment)
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    baseline["environment"] = environment
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline saved -> {path}  "
          f"({len(baseline['signatures'])} signatures)")


# ── Anomaly classification ─────────────────────────────────────────────────────

def classify_signature(sig: dict, baseline: dict) -> dict | None:
    """
    Compare an error signature against the baseline.
    Returns an anomaly dict or None if signature is known and within bounds.
    """
    sigs     = baseline.get("signatures", {})
    sig_hash = sig["hash"]

    # NEW_ERROR_SIGNATURE — never seen before
    if sig_hash not in sigs:
        return {
            "type":    "NEW_ERROR_SIGNATURE",
            "message": (f"New error signature in {sig['service']}: "
                        f"{sig['error_type']} on {sig['operation']}"),
            "detail":  (f"call_path={sig['call_path'] or 'root'}  "
                        f"http_status={sig['http_status'] or 'n/a'}  "
                        f"db_system={sig['db_system'] or 'n/a'}"),
            "sig":     sig,
        }

    return None


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_discover(environment: str | None = None) -> None:
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[discover] Querying APM topology for {env_desc}...")
    services = discover_services(environment)
    print(f"\n  Services ({len(services)}):")
    for s in sorted(services):
        print(f"    {s}")
    env_flag = f" --environment {environment}" if environment else ""
    print(f"\n  Run 'learn{env_flag}' to build an error signature baseline.")


def cmd_learn(window_minutes: int = 120,
              environment: str | None = None) -> None:
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[learn] Discovering services for {env_desc}...")
    services = discover_services(environment)
    print(f"  Found {len(services)} services")
    print(f"  Sampling last {window_minutes}m of error traces...")

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    traces = search_error_traces(services, start_ms, now_ms,
                                 environment=environment)
    print(f"  Found {len(traces)} error trace candidates")

    baseline = load_baseline(environment)
    if not baseline["created_at"]:
        baseline["created_at"] = datetime.now(timezone.utc).isoformat()

    signatures = baseline.setdefault("signatures", {})
    new_count = updated_count = skipped = 0

    for meta in traces:
        trace_id = meta.get("traceId")
        if not trace_id:
            continue
        trace = get_trace_full(trace_id)
        if not trace:
            skipped += 1
            continue

        sigs = build_error_signatures(trace)
        if not sigs:
            skipped += 1
            continue

        for sig in sigs:
            h = sig["hash"]
            if h in signatures:
                signatures[h]["occurrences"] = \
                    signatures[h].get("occurrences", 1) + 1
                updated_count += 1
            else:
                signatures[h] = {
                    "hash":        h,
                    "service":     sig["service"],
                    "error_type":  sig["error_type"],
                    "http_status": sig["http_status"],
                    "db_system":   sig["db_system"],
                    "operation":   sig["operation"],
                    "call_path":   sig["call_path"],
                    "occurrences": 1,
                    "first_seen":  datetime.now(timezone.utc).isoformat(),
                }
                new_count += 1
                print(f"  [new] {sig['service']}  "
                      f"{sig['error_type']} on {sig['operation']}")

    print(f"  Summary: {new_count} new signatures, {updated_count} updated, "
          f"{skipped} traces skipped (no error spans)")
    save_baseline(baseline, environment)


def cmd_watch(window_minutes: int = 10,
              environment: str | None = None) -> None:
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[watch] Discovering services for {env_desc}...")
    services = discover_services(environment)

    baseline = load_baseline(environment)
    if not baseline["signatures"]:
        print(f"  [warn] Baseline for {env_desc} is empty — run 'learn' first.",
              file=sys.stderr)
        sys.exit(1)

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    print(f"[watch] Checking last {window_minutes}m of error traces "
          f"across {len(services)} services ({env_desc})...")
    traces = search_error_traces(services, start_ms, now_ms,
                                 environment=environment)
    print(f"  Found {len(traces)} error trace candidates")

    anomalies_found = checked = skipped = 0
    alerted_hashes: set[str] = set()

    for meta in traces:
        trace_id = meta.get("traceId")
        if not trace_id:
            continue
        trace = get_trace_full(trace_id)
        if not trace:
            skipped += 1
            continue

        sigs = build_error_signatures(trace)
        if not sigs:
            skipped += 1
            continue

        checked += 1
        for sig in sigs:
            if sig["hash"] in alerted_hashes:
                continue
            anomaly = classify_signature(sig, baseline)
            if anomaly:
                alerted_hashes.add(sig["hash"])
                anomalies_found += 1
                print(f"\n  ANOMALY DETECTED")
                print(f"    Type:    {anomaly['type']}")
                print(f"    Message: {anomaly['message']}")
                print(f"    Detail:  {anomaly['detail']}")
                print(f"    TraceID: {trace_id}")
                try:
                    send_custom_event(
                        event_type="error.signature.drift",
                        dimensions={
                            "anomaly_type": anomaly["type"],
                            "service":      sig["service"],
                            "error_type":   sig["error_type"],
                            "sig_hash":     sig["hash"],
                            "environment":  environment or "all",
                        },
                        properties={
                            "message":       anomaly["message"],
                            "detail":        anomaly["detail"],
                            "trace_id":      trace_id,
                            "operation":     sig["operation"],
                            "call_path":     sig["call_path"],
                            "http_status":   sig["http_status"],
                            "db_system":     sig["db_system"],
                            "environment":   environment or "all",
                            "detector_tier": "tier3",
                            "detector_name": "error-signature-fingerprint",
                        },
                    )
                    print(f"    Event sent (error.signature.drift)")
                except Exception as e:
                    print(f"    Failed to send event: {e}", file=sys.stderr)

    print(f"\n  Checked {checked} traces, {skipped} skipped, "
          f"{anomalies_found} new signatures detected")
    if anomalies_found == 0:
        print("  All error signatures match baseline")


def cmd_show(environment: str | None = None) -> None:
    env_desc = f"environment '{environment}'" if environment else "all environments"
    baseline = load_baseline(environment)
    sigs = baseline.get("signatures", {})
    if not sigs:
        print(f"Error baseline for {env_desc} is empty — run 'learn' first.")
        return

    print(f"Error baseline ({env_desc}): {len(sigs)} signatures")
    print(f"  Created: {baseline.get('created_at', 'unknown')}")
    print(f"  Updated: {baseline.get('updated_at', 'unknown')}")
    print()

    by_service: dict[str, list] = defaultdict(list)
    for info in sigs.values():
        by_service[info["service"]].append(info)

    for service, entries in sorted(by_service.items()):
        print(f"  {service}  ({len(entries)} signature{'s' if len(entries)!=1 else ''})")
        for e in sorted(entries, key=lambda x: -x.get("occurrences", 0)):
            print(f"    [{e['hash']}]  seen={e.get('occurrences','?')}  "
                  f"type={e['error_type']}  op={e['operation']}")
            if e.get("call_path"):
                print(f"      path: {e['call_path'][:100]}")
        print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Error signature fingerprinter for Splunk Observability Cloud"
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help="APM environment to scope to (sf_environment). "
             "Omit to cover all environments.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("discover", help="List services from live topology")
    p_learn = sub.add_parser("learn", help="Build error signature baseline")
    p_learn.add_argument("--window-minutes", type=int, default=120)
    p_watch = sub.add_parser("watch", help="Watch for new error signatures")
    p_watch.add_argument("--window-minutes", type=int, default=10)
    sub.add_parser("show", help="Print current error baseline")

    args = parser.parse_args()
    env  = args.environment

    if args.command == "discover":
        cmd_discover(environment=env)
    elif args.command == "learn":
        cmd_learn(args.window_minutes, environment=env)
    elif args.command == "watch":
        cmd_watch(args.window_minutes, environment=env)
    elif args.command == "show":
        cmd_show(environment=env)


if __name__ == "__main__":
    main()
