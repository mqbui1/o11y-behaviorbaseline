#!/usr/bin/env python3
"""
Tier 2 Behavioral Baseline — Trace Path Drift Detector
=======================================================
Detects structural changes in how services communicate:
  - New execution paths never seen before
  - New services appearing in traces
  - Span count spikes (extra hops)
  - Expected services going missing

GENERIC — works with any application onboarded to Splunk Observability.
No hardcoded service names. Services and topology are auto-discovered
from the live APM service map on every run.

How it works:
  1. DISCOVER mode — query the live APM topology, print discovered services
                     and inferred noise patterns. Useful before first learn.

  2. LEARN mode    — sample recent traces across ALL discovered services,
                     build a baseline fingerprint DB, save to baseline.json.
                     Run once (or re-run periodically to re-baseline).

  3. WATCH mode    — sample recent traces, compare to baseline, emit a
                     Splunk custom event for every unknown fingerprint found.
                     Run on a cron schedule (e.g. every 5 minutes).

  4. SHOW mode     — print current baseline without making API calls.

A "fingerprint" is the ordered parent->child service:operation edge list
of a trace, hashed to a stable 16-char ID. Immune to timing variation.

Noise filtering:
  The script auto-detects two categories of noisy self-originated traces
  and excludes them from both baselining and watch:
    - Service-registry heartbeats (Eureka /apps/*, Consul /v1/health/*, etc.)
    - Health-check polls (actuator/health, /health, /ping, /ready, /live)
  These patterns are universal — no application-specific configuration needed.

Usage:
  python trace_fingerprint.py discover
  python trace_fingerprint.py learn [--window-minutes 120]
  python trace_fingerprint.py watch [--window-minutes 10]
  python trace_fingerprint.py show

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
  BASELINE_PATH             (default: ./baseline.json)
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
BASELINE_PATH           = Path(os.environ.get("BASELINE_PATH", "./baseline.json"))
TOPOLOGY_LOOKBACK_HOURS = int(os.environ.get("TOPOLOGY_LOOKBACK_HOURS", "48"))

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# Minimum span count for a trace to be fingerprint-worthy.
MIN_SPANS = 2

# Traces to sample per run (across all discovered services)
TRACES_SAMPLE_LIMIT = 200

# Fingerprints seen fewer times than this in baseline are treated as "rare"
MIN_BASELINE_OCCURRENCES = 2

# Span count must exceed this multiple of baseline max to fire SPAN_COUNT_SPIKE
SPAN_COUNT_SPIKE_MULTIPLIER = 2

# Auto-promotion: a NEW_FINGERPRINT seen in this many consecutive watch runs
# without manual intervention is auto-promoted to the baseline (stops alerting).
# Set to 0 to disable auto-promotion.
AUTO_PROMOTE_THRESHOLD = int(os.environ.get("AUTO_PROMOTE_THRESHOLD", "5"))

# Number of parallel threads for fetching trace details.
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "10"))

# ── Noise patterns ─────────────────────────────────────────────────────────────
# Matched case-insensitively as substrings of a trace's root operation name.
# Traces matching any of these are excluded from baselining and anomaly detection.
# These are universal across frameworks — no application-specific config needed.

REGISTRY_PATTERNS: list[str] = [
    "/eureka/",          # Netflix Eureka
    "/apps/delta",       # Eureka delta fetch
    "/apps/",            # Eureka app registration
    "/register",         # Generic registration
    "/v1/agent/",        # Consul agent
    "/v1/health/",       # Consul health
    "/v1/catalog/",      # Consul catalog
    "/v1/kv/",           # Consul KV
    "/registry/",        # Generic registry
    "service_discovery",
]

HEALTHCHECK_PATTERNS: list[str] = [
    "/actuator/health",  # Spring Boot
    "/health",
    "/healthz",
    "/readyz",
    "/livez",
    "/ready",
    "/live",
    "/ping",
    "/status",
    "/_health",
    "/api/health",
]

NOISE_PATTERNS: list[str] = REGISTRY_PATTERNS + HEALTHCHECK_PATTERNS

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


def _qs(params: dict) -> str:
    filtered = {k: str(v) for k, v in params.items() if v is not None}
    return ("?" + urllib.parse.urlencode(filtered)) if filtered else ""


# ── Topology discovery ─────────────────────────────────────────────────────────

def discover_topology(lookback_hours: int = TOPOLOGY_LOOKBACK_HOURS,
                      environment: str | None = None) -> dict:
    """
    Query the live APM service map. If environment is given, scopes the
    topology query to that sf_environment value. No service names hardcoded.
    """
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - lookback_hours * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [
            {"name": "sf_environment", "operator": "equals",
             "value": environment, "scope": "global"}
        ]
    result = _request("POST", "/v2/apm/topology", body)
    nodes     = (result.get("data") or {}).get("nodes", [])
    edges_raw = (result.get("data") or {}).get("edges", [])

    services = [n["serviceName"] for n in nodes if not n.get("inferred")]
    inferred = [n["serviceName"] for n in nodes if n.get("inferred")]
    edges    = [(e["fromNode"], e["toNode"]) for e in edges_raw
                if e["fromNode"] != e["toNode"]]

    db_keywords = {
        "mysql", "postgres", "postgresql", "mongodb", "redis",
        "cassandra", "elasticsearch", "dynamo", "sqlite", "oracle",
        "sqlserver", "mssql", "mariadb", "cockroach",
    }
    db_nodes = [
        n for n in inferred
        if ":" in n or any(k in n.lower() for k in db_keywords)
    ]

    has_inbound   = {to for (_, to) in edges if to in services}
    ingress_nodes = [s for s in services if s not in has_inbound]

    return {
        "services":      services,
        "inferred":      inferred,
        "db_nodes":      db_nodes,
        "edges":         edges,
        "ingress_nodes": ingress_nodes,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
        "environment":   environment,
    }


# ── Splunk APM helpers ─────────────────────────────────────────────────────────

def search_traces(services: list[str], start_ms: int, end_ms: int,
                  limit: int = TRACES_SAMPLE_LIMIT,
                  environment: str | None = None) -> list[dict]:
    """Search for traces involving any of the given services, optionally scoped
    to a specific deployment.environment value."""
    if not services:
        return []
    tag_filters = [{"tag": "sf_service", "operation": "IN", "values": services}]
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
        print("  [warn] search_traces: no jobId returned", file=sys.stderr)
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
                examples = section.get("legacyTraceExamples") or []
                if section.get("isComplete"):
                    return examples[:limit]
        time.sleep(0.5)
    return []


def get_trace_full(trace_id: str) -> dict | None:
    """
    Fetch full span details for a single trace via GraphQL.
    parentSpanID is not available in this API; parent relationships are
    inferred in build_fingerprint() from span timing.
    """
    query = (
        "query TraceFullDetailsLessValidation($id: ID!) {"
        " trace(id: $id) {"
        " traceID startTime duration"
        " spans { spanID operationName serviceName"
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


def _infer_parent_id(spans: list[dict]) -> dict[str, str | None]:
    """
    Infer parent-child span relationships from timing containment since
    parentSpanID is not available in the GraphQL API response.

    A span B is considered a child of span A when:
      - A contains B's startTime (A.start <= B.start < A.start + A.duration)
      - A != B
    Among all containing spans, the one with the smallest duration is the
    most direct parent (tightest enclosing window).

    Returns: {spanID: parentSpanID or None}
    """
    parents: dict[str, str | None] = {}
    for span in spans:
        sid   = span["spanID"]
        start = span.get("startTime", 0)
        best_parent_id  = None
        best_duration   = float("inf")
        for candidate in spans:
            if candidate["spanID"] == sid:
                continue
            c_start = candidate.get("startTime", 0)
            c_dur   = candidate.get("duration", 0)
            if c_start <= start < c_start + c_dur:
                if c_dur < best_duration:
                    best_duration  = c_dur
                    best_parent_id = candidate["spanID"]
        parents[sid] = best_parent_id
    return parents


def send_custom_event(event_type: str, dimensions: dict, properties: dict) -> None:
    """Emit a custom event to Splunk Observability Cloud."""
    _request("POST", "/v2/event", [{
        "eventType": event_type,
        "category":  "USER_DEFINED",
        "dimensions": dimensions,
        "properties": properties,
        "timestamp":  int(time.time() * 1000),
    }], base_url=INGEST_URL)


# ── Noise filtering ────────────────────────────────────────────────────────────

def _is_noise_trace(root_operation: str) -> bool:
    """
    Return True if the root operation matches a known noise pattern.
    Covers service-registry heartbeats and health-check probes universally.
    """
    op = root_operation.lower()
    return any(p in op for p in NOISE_PATTERNS)


# ── Fingerprinting ─────────────────────────────────────────────────────────────

def build_fingerprint(trace: dict) -> dict | None:
    """
    Build a stable structural fingerprint from a trace's span tree.

    Returns None if the trace has fewer than MIN_SPANS spans or is noise.
    The fingerprint is the ordered parent->child edge sequence hashed to
    a stable 16-char ID, immune to timing and span ID variation.
    """
    spans = trace.get("spans", [])
    if len(spans) < MIN_SPANS:
        return None

    by_id        = {s["spanID"]: s for s in spans}
    sorted_spans = sorted(spans, key=lambda s: s.get("startTime", 0))

    # Infer parent relationships from timing containment
    parent_map = _infer_parent_id(spans)

    root_span = next(
        (s for s in sorted_spans if parent_map.get(s["spanID"]) is None),
        sorted_spans[0] if sorted_spans else None,
    )
    if not root_span:
        return None
    if _is_noise_trace(root_span["operationName"]):
        return None

    root_op = f"{root_span['serviceName']}:{root_span['operationName']}"

    edges = []
    for span in sorted_spans:
        parent_id = parent_map.get(span["spanID"])
        if parent_id and parent_id in by_id:
            parent = by_id[parent_id]
            edges.append((
                f"{parent['serviceName']}:{parent['operationName']}",
                f"{span['serviceName']}:{span['operationName']}",
            ))

    services = sorted({s["serviceName"] for s in spans})
    path     = " -> ".join(f"{a} -> {b}" for a, b in edges) if edges else root_op
    fp_hash  = hashlib.sha256(path.encode()).hexdigest()[:16]

    return {
        "hash":       fp_hash,
        "path":       path,
        "root_op":    root_op,
        "services":   services,
        "span_count": len(spans),
        "edge_count": len(edges),
    }


# ── Anomaly classification ─────────────────────────────────────────────────────

def classify_anomaly(fp: dict, baseline: dict) -> dict | None:
    """
    Compare a fingerprint against the baseline.
    Returns an anomaly dict or None if the trace matches a known pattern.
    Auto-promoted fingerprints are treated as known — no alert fired.
    """
    root_op = fp["root_op"]
    fp_hash = fp["hash"]

    baseline_for_root = {
        h: info for h, info in baseline.get("fingerprints", {}).items()
        if info.get("root_op") == root_op
        and info.get("occurrences", 0) >= MIN_BASELINE_OCCURRENCES
    }

    # NEW_FINGERPRINT — but skip if already auto-promoted
    stored = baseline.get("fingerprints", {}).get(fp_hash)
    if stored and stored.get("auto_promoted"):
        return None

    if fp_hash not in baseline.get("fingerprints", {}):
        return {
            "type":    "NEW_FINGERPRINT",
            "message": f"Unknown execution path for '{root_op}'",
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # NEW_SERVICE
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

    # SPAN_COUNT_SPIKE
    baseline_max = max(
        (info.get("span_count", 0) for info in baseline_for_root.values()),
        default=0,
    )
    if baseline_max > 0 and fp["span_count"] > baseline_max * SPAN_COUNT_SPIKE_MULTIPLIER:
        return {
            "type":    "SPAN_COUNT_SPIKE",
            "message": (f"Span count spike for '{root_op}': "
                        f"{fp['span_count']} vs baseline max {baseline_max}"),
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # MISSING_SERVICE
    if baseline_for_root:
        always_present = set.intersection(
            *[set(info.get("services", [])) for info in baseline_for_root.values()]
        )
        missing = always_present - set(fp["services"])
        if missing:
            return {
                "type":    "MISSING_SERVICE",
                "message": (f"Expected service(s) absent from '{root_op}': "
                            f"{sorted(missing)}"),
                "detail":  f"Path: {fp['path']}",
                "fp":      fp,
            }

    return None


# ── Baseline I/O ───────────────────────────────────────────────────────────────

def _baseline_path(environment: str | None) -> Path:
    """
    Return the baseline file path, scoped per environment.
    Examples:
      environment=None        -> ./baseline.json
      environment=production  -> ./baseline.production.json
      environment=staging     -> ./baseline.staging.json
    This keeps each environment's fingerprint DB isolated so that legitimate
    topology differences between envs don't suppress each other's alerts.
    """
    if environment:
        return BASELINE_PATH.with_suffix(f".{environment}.json")
    return BASELINE_PATH


def load_baseline(environment: str | None = None) -> dict:
    path = _baseline_path(environment)
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {"fingerprints": {}, "topology": None,
            "created_at": None, "updated_at": None,
            "environment": environment}


def save_baseline(baseline: dict, environment: str | None = None) -> None:
    path = _baseline_path(environment)
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    baseline["environment"] = environment
    with open(path, "w") as f:
        json.dump(baseline, f, indent=2)
    print(f"  Baseline saved -> {path}  "
          f"({len(baseline['fingerprints'])} fingerprints)")


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_discover(environment: str | None = None) -> None:
    """Print auto-discovered services and topology. No files written."""
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[discover] Querying APM topology for {env_desc} "
          f"(last {TOPOLOGY_LOOKBACK_HOURS}h)...")
    topo = discover_topology(environment=environment)

    print(f"\n  Services ({len(topo['services'])}):")
    for s in sorted(topo["services"]):
        role = " [ingress]" if s in topo["ingress_nodes"] else ""
        print(f"    {s}{role}")

    if topo["inferred"]:
        print(f"\n  Inferred nodes ({len(topo['inferred'])}):")
        for n in sorted(topo["inferred"]):
            tag = " [database]" if n in topo["db_nodes"] else ""
            print(f"    {n}{tag}")

    print(f"\n  Edges ({len(topo['edges'])}):")
    for src, dst in sorted(topo["edges"]):
        print(f"    {src} -> {dst}")

    print(f"\n  Noise patterns applied automatically:")
    print(f"    Registry:  {REGISTRY_PATTERNS[:4]} ...")
    print(f"    Health:    {HEALTHCHECK_PATTERNS[:4]} ...")

    env_flag = f" --environment {environment}" if environment else ""
    print(f"\n  Run 'learn{env_flag}' to build a baseline from these services.")


def cmd_learn(window_minutes: int = 120,
              environment: str | None = None) -> None:
    """Sample recent traces and build the baseline fingerprint DB."""
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[learn] Discovering services for {env_desc}...")
    topo = discover_topology(environment=environment)
    print(f"  Found {len(topo['services'])} services + "
          f"{len(topo['inferred'])} inferred nodes")
    print(f"  Sampling last {window_minutes}m of traces...")

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    traces = search_traces(topo["services"], start_ms, now_ms,
                           environment=environment)
    print(f"  Found {len(traces)} candidate traces")

    baseline = load_baseline(environment)
    if not baseline["created_at"]:
        baseline["created_at"] = datetime.now(timezone.utc).isoformat()
    baseline["topology"] = topo

    fingerprints = baseline.setdefault("fingerprints", {})
    new_count = updated_count = skipped = 0

    trace_ids = [m.get("traceId") for m in traces if m.get("traceId")]
    print(f"  Fetching {len(trace_ids)} traces ({MAX_WORKERS} parallel)...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_id = {pool.submit(get_trace_full, tid): tid for tid in trace_ids}
        for future in as_completed(future_to_id):
            trace = future.result()
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
                    "hash":           h,
                    "path":           fp["path"],
                    "root_op":        fp["root_op"],
                    "services":       fp["services"],
                    "span_count":     fp["span_count"],
                    "edge_count":     fp["edge_count"],
                    "occurrences":    1,
                    "watch_hits":     0,
                    "auto_promoted":  False,
                    "promoted_at":    None,
                    "first_seen":     datetime.now(timezone.utc).isoformat(),
                }
                new_count += 1
                print(f"  [new] {fp['root_op']}  ->  "
                      f"{fp['path'][:80]}{'...' if len(fp['path']) > 80 else ''}")

    print(f"  Summary: {new_count} new, {updated_count} updated, "
          f"{skipped} skipped (noise/shallow)")
    save_baseline(baseline, environment)


def cmd_watch(window_minutes: int = 10,
              environment: str | None = None) -> None:
    """
    Compare recent traces to baseline. Emits Splunk custom events on drift.
    Also detects entirely new services that have appeared since baseline was built.
    """
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[watch] Discovering current topology for {env_desc}...")
    topo = discover_topology(environment=environment)

    baseline = load_baseline(environment)
    if not baseline["fingerprints"]:
        print(f"  [warn] Baseline for {env_desc} is empty — run 'learn' first.",
              file=sys.stderr)
        sys.exit(1)

    # Alert on new *instrumented* services not present at baseline time.
    # Inferred nodes (db nodes, gateways) are excluded — they vary by trace
    # sampling and should not trigger topology alerts.
    baseline_topo     = baseline.get("topology") or {}
    baseline_services = set(baseline_topo.get("services", []))
    baseline_inferred = set(baseline_topo.get("inferred", []))
    current_services  = set(topo["services"])
    new_topo_services = current_services - baseline_services - baseline_inferred
    if new_topo_services:
        print(f"\n  WARNING: New service(s) in topology since baseline: "
              f"{sorted(new_topo_services)}")
        for svc in new_topo_services:
            try:
                send_custom_event(
                    event_type="topology.new_service",
                    dimensions={"new_service": svc,
                                "environment": environment or "all"},
                    properties={
                        "message":       f"New service '{svc}' appeared in APM topology",
                        "environment":   environment or "all",
                        "detector_tier": "tier1",
                        "detector_name": "topology-new-service",
                    },
                )
                print(f"    Event sent for {svc}")
            except Exception as e:
                print(f"    Failed to send event: {e}", file=sys.stderr)

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    print(f"\n[watch] Checking last {window_minutes}m across "
          f"{len(topo['services'])} services ({env_desc})...")
    traces = search_traces(topo["services"], start_ms, now_ms,
                           environment=environment)
    print(f"  Found {len(traces)} candidate traces")

    anomalies_found = checked = skipped = 0
    alerted_hashes: set[str] = set()
    # Track which new hashes were seen this run (for auto-promotion)
    new_hashes_seen: set[str] = set()

    trace_ids = [m.get("traceId") for m in traces if m.get("traceId")]
    print(f"  Fetching {len(trace_ids)} traces ({MAX_WORKERS} parallel)...")

    # Fetch all traces in parallel, then process results
    fetched: list[tuple[str, dict]] = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_id = {pool.submit(get_trace_full, tid): tid for tid in trace_ids}
        for future in as_completed(future_to_id):
            tid = future_to_id[future]
            trace = future.result()
            if not trace:
                skipped += 1
                continue
            fetched.append((tid, trace))

    for trace_id, trace in fetched:
        fp = build_fingerprint(trace)
        if fp is None:
            skipped += 1
            continue

        checked += 1
        if fp["hash"] in alerted_hashes:
            continue

        anomaly = classify_anomaly(fp, baseline)
        if anomaly:
            alerted_hashes.add(fp["hash"])
            if anomaly["type"] == "NEW_FINGERPRINT":
                new_hashes_seen.add(fp["hash"])
                # Upsert a pending-promotion record so watch_hits persists
                fps = baseline.setdefault("fingerprints", {})
                if fp["hash"] not in fps:
                    fps[fp["hash"]] = {
                        "hash":          fp["hash"],
                        "path":          fp["path"],
                        "root_op":       fp["root_op"],
                        "services":      fp["services"],
                        "span_count":    fp["span_count"],
                        "edge_count":    fp["edge_count"],
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
                    event_type="trace.path.drift",
                    dimensions={
                        "anomaly_type":   anomaly["type"],
                        "root_operation": fp["root_op"],
                        "fp_hash":        fp["hash"],
                        "environment":    environment or "all",
                    },
                    properties={
                        "message":       anomaly["message"],
                        "detail":        anomaly["detail"],
                        "trace_id":      trace_id,
                        "path":          fp["path"],
                        "services":      ",".join(fp["services"]),
                        "span_count":    fp["span_count"],
                        "environment":   environment or "all",
                        "detector_tier": "tier2",
                        "detector_name": "trace-path-drift",
                    },
                )
                print(f"    Event sent (trace.path.drift)")
            except Exception as e:
                print(f"    Failed to send event: {e}", file=sys.stderr)

    # ── Auto-promotion ─────────────────────────────────────────────────────────
    promoted_count = 0
    if AUTO_PROMOTE_THRESHOLD > 0:
        fps = baseline.get("fingerprints", {})
        baseline_dirty = False
        for h in new_hashes_seen:
            rec = fps.get(h)
            if rec and not rec.get("auto_promoted"):
                rec["watch_hits"] = rec.get("watch_hits", 0) + 1
                if rec["watch_hits"] >= AUTO_PROMOTE_THRESHOLD:
                    rec["auto_promoted"] = True
                    rec["promoted_at"]   = datetime.now(timezone.utc).isoformat()
                    promoted_count += 1
                    print(f"\n  AUTO-PROMOTED: {h[:16]}... "
                          f"(seen {rec['watch_hits']} watch runs) "
                          f"root_op={rec['root_op']}")
                baseline_dirty = True
        if baseline_dirty:
            baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
            save_baseline(baseline, environment)

    print(f"\n  Checked {checked} traces, {skipped} skipped, "
          f"{anomalies_found} anomalies detected"
          + (f", {promoted_count} auto-promoted" if promoted_count else ""))
    if anomalies_found == 0:
        print("  All trace paths match baseline")


def cmd_promote(hashes: list[str] | None, environment: str | None = None) -> None:
    """
    Manually promote fingerprints to the baseline (stops alerting on them).
    If no hashes given, promotes all pending fingerprints (watch_hits > 0).
    """
    env_desc = f"environment '{environment}'" if environment else "all environments"
    baseline = load_baseline(environment)
    fps = baseline.get("fingerprints", {})
    if not fps:
        print(f"Baseline for {env_desc} is empty — run 'learn' first.")
        return

    targets = (
        [fps[h] for h in hashes if h in fps]
        if hashes
        else [r for r in fps.values() if not r.get("auto_promoted")]
    )
    if not targets:
        print("No fingerprints to promote.")
        return

    now_iso = datetime.now(timezone.utc).isoformat()
    promoted = 0
    for rec in targets:
        if not rec.get("auto_promoted"):
            rec["auto_promoted"] = True
            rec["promoted_at"]   = now_iso
            promoted += 1
            print(f"  Promoted: {rec['hash'][:16]}...  root_op={rec['root_op']}")

    if promoted:
        baseline["updated_at"] = now_iso
        save_baseline(baseline, environment)
        print(f"\n  {promoted} fingerprint(s) promoted for {env_desc}.")
    else:
        print("All specified fingerprints were already promoted.")


def cmd_show(environment: str | None = None) -> None:
    """Print current baseline fingerprints."""
    env_desc = f"environment '{environment}'" if environment else "all environments"
    baseline = load_baseline(environment)
    fps = baseline.get("fingerprints", {})
    if not fps:
        print(f"Baseline for {env_desc} is empty — run 'learn' first.")
        return

    print(f"Baseline ({env_desc}): {len(fps)} fingerprints")
    print(f"  Created:  {baseline.get('created_at', 'unknown')}")
    print(f"  Updated:  {baseline.get('updated_at', 'unknown')}")
    topo = baseline.get("topology")
    if topo:
        print(f"  Services: {sorted(topo.get('services', []))}")
    print()

    by_root: dict[str, list] = defaultdict(list)
    for info in fps.values():
        by_root[info["root_op"]].append(info)

    for root_op, entries in sorted(by_root.items()):
        print(f"  {root_op}  ({len(entries)} pattern{'s' if len(entries)!=1 else ''})")
        for e in sorted(entries, key=lambda x: -x.get("occurrences", 0)):
            svcs = ", ".join(e.get("services", []))
            print(f"    [{e['hash']}]  seen={e.get('occurrences','?')}  "
                  f"spans={e.get('span_count','?')}  services=[{svcs}]")
            path = e.get("path", "")
            print(f"      {path[:100]}{'...' if len(path) > 100 else ''}")
        print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generic trace path drift detector for Splunk Observability Cloud"
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help=(
            "APM environment to scope to (deployment.environment / sf_environment). "
            "Determines both the topology query scope and which baseline file is used "
            "(baseline.<environment>.json). Omit to cover all environments."
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("discover", help="Auto-discover services from live topology")
    p_learn = sub.add_parser("learn", help="Build baseline from recent traces")
    p_learn.add_argument("--window-minutes", type=int, default=120)
    p_watch = sub.add_parser("watch", help="Compare recent traces to baseline")
    p_watch.add_argument("--window-minutes", type=int, default=10)
    sub.add_parser("show", help="Print current baseline")
    p_promote = sub.add_parser(
        "promote",
        help="Manually promote fingerprint(s) to baseline (stops alerting on them)",
    )
    p_promote.add_argument(
        "hashes", nargs="*",
        help="Fingerprint hash(es) to promote. Omit to promote all pending.",
    )

    args = parser.parse_args()
    env = args.environment

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
