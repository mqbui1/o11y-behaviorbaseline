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
  python error_fingerprint.py promote [hash ...]

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
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN            = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN            = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
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

# Traces to sample per learn run
TRACES_SAMPLE_LIMIT = 200

# Traces to sample per watch run — lower is faster; new signatures surface
# on the first occurrence so high volume adds little signal.
WATCH_SAMPLE_LIMIT = int(os.environ.get("WATCH_SAMPLE_LIMIT", "50"))

# Signatures seen fewer times than this in baseline are "rare" (lower confidence)
MIN_BASELINE_OCCURRENCES = 2

# A signature's watch-window count must exceed this multiple of its per-window
# baseline rate to fire SIGNATURE_SPIKE
SPIKE_MULTIPLIER = 3

# A signature must have been seen at least this many times in baseline to be
# considered "established" (guards against spiking on rare baseline signatures)
SPIKE_MIN_BASELINE_OCCURRENCES = 5

# A signature is "dominant" if it accounts for >= this fraction of all errors
# for its service in the baseline. Used for SIGNATURE_VANISHED detection.
DOMINANCE_THRESHOLD = 0.2  # 20% of errors in its service

# Top N span operation names to include in the signature path
SIGNATURE_TOP_FRAMES = 5

# New signatures consistently seen across N watch runs are auto-promoted
# to the baseline (stops alerting on them). Set to 0 to disable.
AUTO_PROMOTE_THRESHOLD = int(os.environ.get("AUTO_PROMOTE_THRESHOLD", "5"))

# Number of parallel threads for fetching trace details.
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "20"))

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
    delay = 0.1
    elapsed = 0.0
    while elapsed < 30.0:
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
        time.sleep(delay)
        elapsed += delay
        delay = min(delay * 2, 2.0)
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
    _request("POST", "/v2/event", [{
        "eventType":  event_type,
        "category":   "USER_DEFINED",
        "dimensions": dimensions,
        "properties": properties,
        "timestamp":  int(time.time() * 1000),
    }], base_url=INGEST_URL)


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
    return {"signatures": {}, "learn_runs": 0, "created_at": None,
            "updated_at": None, "environment": environment}


def save_baseline(baseline: dict, environment: str | None = None) -> None:
    path = _baseline_path(environment)
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    baseline["environment"] = environment
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline saved -> {path}  "
          f"({len(baseline['signatures'])} signatures)")


# ── Anomaly classification ─────────────────────────────────────────────────────

def classify_signature(sig: dict, baseline: dict,
                        watch_counts: dict[str, int]) -> dict | None:
    """
    Compare an error signature against the baseline.

    watch_counts: {sig_hash: count_in_this_watch_window} — used for spike detection.
    Returns an anomaly dict or None if signature is known and within bounds.
    """
    sigs        = baseline.get("signatures", {})
    learn_runs  = max(baseline.get("learn_runs", 1), 1)
    sig_hash    = sig["hash"]

    # NEW_ERROR_SIGNATURE — never seen before (or pending-promotion but not yet promoted)
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

    stored = sigs[sig_hash]

    # Skip auto-promoted signatures (intentional, silenced)
    if stored.get("auto_promoted"):
        return None

    # SIGNATURE_SPIKE — known signature appearing far more than its baseline rate
    # baseline_rate = average occurrences per learn run
    # watch_rate    = occurrences in this watch window
    baseline_occurrences = stored.get("occurrences", 1)
    if baseline_occurrences >= SPIKE_MIN_BASELINE_OCCURRENCES:
        baseline_rate = baseline_occurrences / learn_runs
        watch_rate    = watch_counts.get(sig_hash, 0)
        if watch_rate > baseline_rate * SPIKE_MULTIPLIER:
            return {
                "type":    "SIGNATURE_SPIKE",
                "message": (f"Error spike in {sig['service']}: "
                            f"{sig['error_type']} on {sig['operation']} "
                            f"({watch_rate}× in window vs baseline rate "
                            f"{baseline_rate:.1f}/run)"),
                "detail":  (f"watch_count={watch_rate}  "
                            f"baseline_rate={baseline_rate:.2f}/run  "
                            f"multiplier={watch_rate/baseline_rate:.1f}×"),
                "sig":     sig,
            }

    return None


def check_vanished_signatures(baseline: dict, watch_counts: dict[str, int],
                               service_filter: list[str] | None = None
                               ) -> list[dict]:
    """
    Detect dominant error signatures that have completely disappeared in this
    watch window. A signature is dominant if it accounts for >= DOMINANCE_THRESHOLD
    of all errors for its service in the baseline.

    Returns a list of anomaly dicts (one per vanished signature).
    Called once per watch run after all traces are processed.
    """
    sigs       = baseline.get("signatures", {})
    learn_runs = max(baseline.get("learn_runs", 1), 1)
    anomalies  = []

    # Compute total occurrences per service in baseline
    service_totals: dict[str, int] = defaultdict(int)
    for info in sigs.values():
        service_totals[info["service"]] += info.get("occurrences", 1)

    for sig_hash, info in sigs.items():
        service = info["service"]
        if service_filter and service not in service_filter:
            continue

        total = service_totals.get(service, 1)
        fraction = info.get("occurrences", 1) / total

        # Only flag dominant signatures that are now absent from the watch window
        if fraction >= DOMINANCE_THRESHOLD and sig_hash not in watch_counts:
            baseline_rate = info.get("occurrences", 1) / learn_runs
            anomalies.append({
                "type":    "SIGNATURE_VANISHED",
                "message": (f"Dominant error signature disappeared in {service}: "
                            f"{info['error_type']} on {info['operation']} "
                            f"(was {fraction*100:.0f}% of service errors)"),
                "detail":  (f"baseline_rate={baseline_rate:.2f}/run  "
                            f"service_share={fraction*100:.0f}%  "
                            f"call_path={info.get('call_path') or 'root'}"),
                "sig":     info,
            })

    return anomalies


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

    trace_ids = [m.get("traceId") for m in traces if m.get("traceId")]
    print(f"  Fetching {len(trace_ids)} traces ({MAX_WORKERS} parallel)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_id = {pool.submit(get_trace_full, tid): tid for tid in trace_ids}
        for future in as_completed(future_to_id):
            try:
                trace = future.result()
            except Exception as e:
                print(f"  [warn] fetch error: {e}", file=sys.stderr)
                skipped += 1
                continue
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
                        "hash":          h,
                        "service":       sig["service"],
                        "error_type":    sig["error_type"],
                        "http_status":   sig["http_status"],
                        "db_system":     sig["db_system"],
                        "operation":     sig["operation"],
                        "call_path":     sig["call_path"],
                        "occurrences":   1,
                        "watch_hits":    0,
                        "auto_promoted": False,
                        "promoted_at":   None,
                        "first_seen":    datetime.now(timezone.utc).isoformat(),
                    }
                    new_count += 1
                    print(f"  [new] {sig['service']}  "
                          f"{sig['error_type']} on {sig['operation']}")

    # Track number of learn runs — used to compute per-run baseline rate
    baseline["learn_runs"] = baseline.get("learn_runs", 0) + 1

    print(f"  Summary: {new_count} new signatures, {updated_count} updated, "
          f"{skipped} traces skipped (no error spans)")
    save_baseline(baseline, environment)


def cmd_watch(window_minutes: int = 10,
              environment: str | None = None) -> None:
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[watch] Discovering services + searching error traces in parallel ({env_desc})...")

    baseline = load_baseline(environment)
    if not baseline.get("created_at"):
        print(f"  [warn] No baseline found for {env_desc} — run 'learn' first.",
              file=sys.stderr)
        sys.exit(1)

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    # Seed search with baseline services; run discovery concurrently.
    baseline_services = list(set(
        sig["service"] for sig in baseline.get("signatures", {}).values()
    ))

    with ThreadPoolExecutor(max_workers=2) as pool:
        svc_future    = pool.submit(discover_services, environment)
        traces_future = pool.submit(search_error_traces, baseline_services,
                                    start_ms, now_ms, WATCH_SAMPLE_LIMIT,
                                    environment)
        services = svc_future.result()
        traces   = traces_future.result()

    print(f"  Services: {len(services)} | Error trace candidates: {len(traces)}")

    anomalies_found = checked = skipped = 0
    alerted_hashes: set[str] = set()
    # Count how many times each signature hash appears in this watch window
    watch_counts: dict[str, int] = defaultdict(int)
    # Track which services appeared in this window (for vanished check)
    seen_services: set[str] = set()

    # First pass: fetch all traces in parallel, then collect signatures and counts
    trace_ids = [m.get("traceId") for m in traces if m.get("traceId")]
    print(f"  Fetching {len(trace_ids)} traces ({MAX_WORKERS} parallel)...")

    all_trace_sigs: list[tuple[str, list[dict]]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_id = {pool.submit(get_trace_full, tid): tid for tid in trace_ids}
        for future in as_completed(future_to_id):
            tid = future_to_id[future]
            try:
                trace = future.result()
            except Exception as e:
                print(f"  [warn] trace {tid}: {e}", file=sys.stderr)
                skipped += 1
                continue
            if not trace:
                skipped += 1
                continue
            sigs = build_error_signatures(trace)
            if not sigs:
                skipped += 1
                continue
            checked += 1
            for sig in sigs:
                watch_counts[sig["hash"]] += 1
                seen_services.add(sig["service"])
            all_trace_sigs.append((tid, sigs))

    # Second pass: classify anomalies now that watch_counts is fully populated
    new_sigs_seen: set[str] = set()
    for trace_id, sigs in all_trace_sigs:
        for sig in sigs:
            if sig["hash"] in alerted_hashes:
                continue
            anomaly = classify_signature(sig, baseline, watch_counts)
            if anomaly:
                alerted_hashes.add(sig["hash"])
                if anomaly["type"] == "NEW_ERROR_SIGNATURE":
                    new_sigs_seen.add(sig["hash"])
                    # Upsert a pending-promotion record
                    stored_sigs = baseline.setdefault("signatures", {})
                    if sig["hash"] not in stored_sigs:
                        stored_sigs[sig["hash"]] = {
                            "hash":          sig["hash"],
                            "service":       sig["service"],
                            "error_type":    sig["error_type"],
                            "http_status":   sig["http_status"],
                            "db_system":     sig["db_system"],
                            "operation":     sig["operation"],
                            "call_path":     sig["call_path"],
                            "occurrences":   1,
                            "watch_hits":    0,
                            "auto_promoted": False,
                            "promoted_at":   None,
                            "first_seen":    datetime.now(timezone.utc).isoformat(),
                        }
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

    # Third pass: check for vanished dominant signatures
    vanished = check_vanished_signatures(
        baseline, watch_counts,
        service_filter=list(seen_services) if seen_services else None,
    )
    for anomaly in vanished:
        sig = anomaly["sig"]
        anomalies_found += 1
        print(f"\n  ANOMALY DETECTED")
        print(f"    Type:    {anomaly['type']}")
        print(f"    Message: {anomaly['message']}")
        print(f"    Detail:  {anomaly['detail']}")
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
                    "operation":     sig["operation"],
                    "call_path":     sig.get("call_path", ""),
                    "environment":   environment or "all",
                    "detector_tier": "tier3",
                    "detector_name": "error-signature-fingerprint",
                },
            )
            print(f"    Event sent (error.signature.drift)")
        except Exception as e:
            print(f"    Failed to send event: {e}", file=sys.stderr)

    # ── Auto-promotion ─────────────────────────────────────────────────────────
    promoted_count = 0
    if AUTO_PROMOTE_THRESHOLD > 0:
        stored_sigs = baseline.get("signatures", {})
        baseline_dirty = False
        for h in new_sigs_seen:
            rec = stored_sigs.get(h)
            if rec and not rec.get("auto_promoted"):
                rec["watch_hits"] = rec.get("watch_hits", 0) + 1
                if rec["watch_hits"] >= AUTO_PROMOTE_THRESHOLD:
                    rec["auto_promoted"] = True
                    rec["promoted_at"]   = datetime.now(timezone.utc).isoformat()
                    promoted_count += 1
                    print(f"\n  AUTO-PROMOTED: {h[:16]}... "
                          f"(seen {rec['watch_hits']} watch runs) "
                          f"service={rec['service']}  "
                          f"error_type={rec['error_type']}")
                baseline_dirty = True
        if baseline_dirty:
            save_baseline(baseline, environment)

    print(f"\n  Checked {checked} traces, {skipped} skipped, "
          f"{anomalies_found} anomalies detected"
          + (f", {promoted_count} auto-promoted" if promoted_count else ""))
    if anomalies_found == 0:
        print("  All error signatures match baseline")


def cmd_promote(hashes: list[str] | None, environment: str | None = None) -> None:
    """
    Manually promote error signature(s) to the baseline (stops alerting on them).
    If no hashes given, promotes all pending signatures (watch_hits > 0).
    """
    env_desc = f"environment '{environment}'" if environment else "all environments"
    baseline = load_baseline(environment)
    sigs = baseline.get("signatures", {})
    if not sigs:
        print(f"Error baseline for {env_desc} is empty — run 'learn' first.")
        return

    targets = (
        [sigs[h] for h in hashes if h in sigs]
        if hashes
        else [r for r in sigs.values() if not r.get("auto_promoted")]
    )
    if not targets:
        print("No signatures to promote.")
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    promoted = 0
    for rec in targets:
        if not rec.get("auto_promoted"):
            rec["auto_promoted"] = True
            rec["promoted_at"]   = now_iso
            promoted += 1
            print(f"  Promoted: {rec['hash'][:16]}...  "
                  f"service={rec['service']}  error_type={rec['error_type']}")

    if promoted:
        save_baseline(baseline, environment)
        print(f"\n  {promoted} signature(s) promoted for {env_desc}.")
    else:
        print("All specified signatures were already promoted.")


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
    p_promote = sub.add_parser(
        "promote",
        help="Manually promote signature(s) to baseline (stops alerting on them)",
    )
    p_promote.add_argument(
        "hashes", nargs="*",
        help="Signature hash(es) to promote. Omit to promote all pending.",
    )

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
    elif args.command == "promote":
        cmd_promote(args.hashes or None, environment=env)


if __name__ == "__main__":
    main()
