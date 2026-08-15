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
  SPLUNK_REALM              (default: us1)
  BASELINE_PATH             (default: ./baseline.json)
  TOPOLOGY_LOOKBACK_HOURS   (default: 48)

Optional env vars:
  NON_ROOT_SERVICES         Comma-separated services that are never a legitimate
                            trace entry point (known callee-only, per app topology).
                            Roots inferred for these are dropped, not baselined —
                            typically needed when a callee's own instrumentation
                            leaks/loses parent context under async runtimes.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
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

# Load .env file from script directory if present (fallback for cron/non-shell contexts)
_ENV_FILE = Path(__file__).parent.parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN            = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN            = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM                   = os.environ.get("SPLUNK_REALM", "us1")
_DATA_DIR               = Path(__file__).parent.parent / "data"
BASELINE_PATH           = Path(os.environ.get("BASELINE_PATH", str(_DATA_DIR / "baseline.json")))
TOPOLOGY_LOOKBACK_HOURS = int(os.environ.get("TOPOLOGY_LOOKBACK_HOURS", "48"))
THRESHOLDS_PATH         = Path(os.environ.get("THRESHOLDS_PATH", str(_DATA_DIR / "thresholds.json")))

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# Minimum span count for a trace to be fingerprint-worthy.
MIN_SPANS = 2

# Grace period (microseconds) tolerated when checking whether a cross-service
# candidate ancestor has "ended" before a child starts. A child's real server-
# side span commonly starts a small amount after its client-side (parent)
# span's reported end — client instrumentation stops timing before the
# server has fully begun its own span (network latency + independent clocks
# between the two processes) — so without tolerance the parent gets popped
# off the stack a few dozen/hundred microseconds too early and the child
# wrongly attaches to an outer ancestor instead. 5ms is comfortably below the
# gap between genuinely distinct, unrelated calls in the same flow (tens of
# ms+), so it won't cause unrelated spans to be misattributed.
CROSS_SERVICE_CLOCK_SKEW_GRACE_US = 5000

# Traces to sample per service per learn run. 200 gives enough repetitions
# for each fingerprint hash to reach MIN_BASELINE_OCCURRENCES even for
# infrequent endpoints in a short learn window.
LEARN_SAMPLE_LIMIT = int(os.environ.get("LEARN_SAMPLE_LIMIT", "200"))

# Traces to sample per watch run — lower is faster; new patterns are detected
# after the first occurrence so high volume adds little signal.
WATCH_SAMPLE_LIMIT = int(os.environ.get("WATCH_SAMPLE_LIMIT", "50"))

# Fingerprints seen fewer times than this in baseline are treated as "rare"
# and excluded. Raising to 3 filters one-off structural variants (e.g. petclinic
# cache-miss/hit variations) that appear occasionally but not reliably enough to
# anchor MISSING_SERVICE detection. Overridable per-environment (e.g. lower for
# flows with legitimate high structural branching, like astroshop-local
# checkout, where timing-inferred fingerprints rarely repeat exactly even after
# noise-filtering fixes) via MIN_BASELINE_OCCURRENCES env var.
MIN_BASELINE_OCCURRENCES = int(os.environ.get("MIN_BASELINE_OCCURRENCES", "3"))

# Span count must exceed this multiple of baseline max to fire SPAN_COUNT_SPIKE
SPAN_COUNT_SPIKE_MULTIPLIER = 2

# Span count must fall below this fraction of baseline min to fire SPAN_COUNT_DROP
# e.g. 0.5 means fewer than half the minimum ever seen → alert
SPAN_COUNT_DROP_THRESHOLD = float(os.environ.get("SPAN_COUNT_DROP_THRESHOLD", "0.5"))

# Minimum baseline min span count before DROP detection activates.
# Avoids false positives on very simple traces (1-2 spans) where halving is meaningless.
SPAN_COUNT_DROP_MIN_BASELINE = int(os.environ.get("SPAN_COUNT_DROP_MIN_BASELINE", "4"))

# MISSING_SERVICE fires when a service is present in this fraction of baseline
# patterns for the same root_op (e.g. 0.6 = present in ≥60% of variants).
MISSING_SERVICE_DOMINANCE_THRESHOLD = float(
    os.environ.get("MISSING_SERVICE_DOMINANCE_THRESHOLD", "0.6")
)

# Auto-promotion: a NEW_FINGERPRINT seen in this many consecutive watch runs
# without manual intervention is auto-promoted to the baseline (stops alerting).
# Set to 0 to disable auto-promotion.
AUTO_PROMOTE_THRESHOLD = int(os.environ.get("AUTO_PROMOTE_THRESHOLD", "5"))

# Number of parallel threads for fetching trace details.
MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "20"))

# Services known to be callee-only per application topology (never a legitimate
# trace entry point). A span from one of these services with no resolved parent
# is a parent-inference/context-propagation artifact (e.g. an async-runtime
# context leak in the callee), not real root traffic — drop it rather than
# baseline it as a root. Comma-separated, e.g. NON_ROOT_SERVICES=quote,pricing
NON_ROOT_SERVICES: set[str] = {
    s.strip() for s in os.environ.get("NON_ROOT_SERVICES", "").split(",") if s.strip()
}

# ── Per-service threshold overrides (from adaptive_thresholds.py) ─────────────

def _load_service_thresholds() -> dict:
    """Load per-service threshold overrides from thresholds.json if present."""
    if THRESHOLDS_PATH.exists():
        try:
            return json.loads(THRESHOLDS_PATH.read_text()).get("services", {})
        except Exception:
            pass
    return {}

_SERVICE_THRESHOLDS: dict = _load_service_thresholds()


def _svc_threshold(service: str, key: str, default: float) -> float:
    """Return per-service threshold if set, else the global default."""
    return float(_SERVICE_THRESHOLDS.get(service, {}).get(key, default))


# ── Noise patterns ─────────────────────────────────────────────────────────────
# Matched case-insensitively as substrings of a trace's root operation name.
# Traces matching any of these are excluded from baselining and anomaly detection.
# These are universal across frameworks — no application-specific config needed.

REGISTRY_PATTERNS: list[str] = [
    "/eureka/",          # Netflix Eureka
    "/apps/delta",       # Eureka delta fetch
    "/apps/",            # Eureka app registration
    "/register",         # Generic registration
    "/peerreplication",  # Eureka peer replication
    "/v1/agent/",        # Consul agent
    "/v1/health/",       # Consul health
    "/v1/catalog/",      # Consul catalog
    "/v1/kv/",           # Consul KV
    "/registry/",        # Generic registry
    "service_discovery",
]

HEALTHCHECK_PATTERNS: list[str] = [
    "/actuator",         # Spring Boot actuator (health, info, metrics, env, etc.)
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

# Pure transport-layer wrapper spans: bare HTTP-verb spans with no route
# captured, and reverse-proxy/service-mesh relay hops (ingress/egress).
# These add no structural signal — they're 1:1 framing around the real
# operation — but when several such hops occur close together in time
# (e.g. back-to-back HTTP calls in one flow), their real proxy-level
# nesting can vary at the network layer independent of application
# behavior, fragmenting an otherwise-identical fingerprint into many
# hashes. Excluded from edge construction (not from span_count, which
# still reflects true span totals for spike/drop detection).
FRAMING_OPS: set[str] = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}


def _is_framing_span(span: dict) -> bool:
    op = span.get("operationName", "")
    if op in FRAMING_OPS:
        return True
    if op == "ingress" or "egress" in op.lower():
        return True
    return False

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
        "sf_environment":   environment,
    }


# ── Splunk APM helpers ─────────────────────────────────────────────────────────

def search_traces(services: list[str], start_ms: int, end_ms: int,
                  limit: int = 200,
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
                examples = section.get("legacyTraceExamples") or []
                if section.get("isComplete"):
                    return examples[:limit]
        time.sleep(delay)
        elapsed += delay
        delay = min(delay * 2, 2.0)
    return []


def get_trace_full(trace_id: str) -> dict | None:
    """
    Fetch full span details for a single trace via GraphQL.

    NOTE on hash compatibility with the OTel Go processor:
    The Splunk APM GraphQL API does not expose parentSpanId in span results,
    so this function omits it from the query and build_fingerprint() falls back
    to timing-containment parent inference for every span.

    The OTel Go processor (fingerprintprocessor/fingerprint.go) reads actual
    parentSpanID from the OTLP wire format and uses it directly, falling back
    to timing containment only for spans whose parent is not in the local buffer.

    For synchronous call chains (the common case) the two approaches produce
    the same parent assignments and thus identical hashes. For async operations
    (Kafka consumers, fire-and-forget HTTP) parentSpanID may cross a buffer
    boundary or point outside the trace window, causing the Go processor to
    fall back to timing containment too — so both paths converge on the same
    heuristic. Hash divergence is therefore rare in practice.

    If you observe frequent NEW_FINGERPRINT false positives only on the Python
    slow path for an async-heavy service, set AUTO_PROMOTE_THRESHOLD lower or
    use the OTel fast path exclusively for that environment.
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

    Uses a stack-based interval-nesting algorithm: spans are sorted by
    (startTime, -duration) — so an outer span starting at the same instant
    as its child is processed first — then walked in order while maintaining
    a stack of still-open ancestors. A span's parent is the innermost
    still-open span on the stack when it starts.

    This replaces a previous pairwise "smallest enclosing duration" approach
    that independently evaluated each span against every other span. That
    approach was sensitive to near-ties between concurrent/overlapping spans
    (e.g. an envoy proxy span and the app span it fronts, timestamped by two
    different processes with independent clocks) and could assign
    inconsistent parents for the same logical call shape across different
    trace instances — producing a different fingerprint hash every time even
    though the underlying flow was identical, which prevented fingerprints
    from ever reaching MIN_BASELINE_OCCURRENCES. The stack-based approach
    always produces one coherent tree per trace and is far less sensitive to
    single-span timing jitter.

    Same-service vs. cross-service containment strictness (2026-07-30 fix):
    a candidate ancestor is only eligible as parent if it "encloses" the new
    span, but what counts as enclosing differs by whether the two spans come
    from the same service (single process, single clock) or different
    services (independent clocks):
      - Cross-service: lenient — ancestor just needs to not have ended
        (by its recorded end, plus CROSS_SERVICE_CLOCK_SKEW_GRACE_US of
        tolerance) before the child starts. Tolerates the small clock skew
        you get between e.g. an envoy proxy span and the app span it fronts
        (the original motivating case for this rewrite), and between a
        client-side RPC span and the real server-side span it calls, whose
        reported end/start can be a few dozen-hundred microseconds apart
        due to network latency and independent per-process clocks.
      - Same-service: strict — ancestor must fully enclose the child
        (ancestor.end >= child.end too), not just still be open at the
        child's start. Same-process spans share one clock, so if a same-
        service "child" candidate actually outlasts its candidate parent,
        it isn't really nested inside it — it's a concurrent sibling.
        Without this, back-to-back pipelined same-service calls with
        overlapping-but-not-nested timing (e.g. cart's Redis HGET/HMSET/
        EXPIRE issued in quick succession per checkout request) get
        arbitrarily nested under each other depending on which one happened
        to start a hair earlier that particular request — producing a
        different edge set (and hash) on almost every trace, so the
        fingerprint never accumulated enough occurrences to be promoted into
        the baseline. Requiring full containment for same-service pairs
        makes the stack correctly walk past these siblings to the real
        (longer-lived, cross-service-reachable) enclosing call, so every
        instance of the same logical flow now resolves to the same edges.

    Returns: {spanID: parentSpanID or None}

    Note: this heuristic still breaks for async operations (fire-and-forget,
    Kafka consumers, async HTTP) where a child span starts after its logical
    parent ends — those spans get no parent and appear as roots. The
    resulting fingerprint will differ from the baseline only at the edge
    level, not the service level, so MISSING_SERVICE and NEW_SERVICE
    detection still work correctly. False NEW_FINGERPRINT alerts on
    async-heavy services can be reduced by increasing AUTO_PROMOTE_THRESHOLD
    or lowering MISSING_SERVICE_DOMINANCE_THRESHOLD for those services.
    """
    ordered = sorted(
        spans, key=lambda s: (s.get("startTime", 0), -s.get("duration", 0))
    )
    parents: dict[str, str | None] = {}
    stack: list[dict] = []
    for span in ordered:
        start = span.get("startTime", 0)
        end = start + span.get("duration", 0)
        while stack:
            top = stack[-1]
            top_end = top.get("startTime", 0) + top.get("duration", 0)
            if top.get("serviceName") == span.get("serviceName"):
                if top_end < end:
                    stack.pop()
                    continue
            elif top_end + CROSS_SERVICE_CLOCK_SKEW_GRACE_US <= start:
                stack.pop()
                continue
            break

        # Prefer the nearest still-open SAME-service ancestor over the
        # topmost stack entry, even if a cross-service span happens to sit
        # above it. A cross-service call (e.g. a client-side RPC span) can
        # be pushed onto the stack shortly before one of the current span's
        # real same-process siblings starts (e.g. Redis ops issued by a
        # cart request that overlap with an unrelated, later GetCart RPC),
        # and the naive top-of-stack check would wrongly attach the child
        # to that unrelated cross-service call instead of its real same-
        # service parent. Same-service children almost always belong to
        # their own service's call chain; only fall back to the nearest
        # open cross-service ancestor when no enclosing same-service one
        # exists on the stack at all.
        parent = None
        fallback = None
        for candidate in reversed(stack):
            c_end = candidate.get("startTime", 0) + candidate.get("duration", 0)
            if candidate.get("serviceName") == span.get("serviceName"):
                if c_end >= end:
                    parent = candidate
                    break
            elif fallback is None and c_end + CROSS_SERVICE_CLOCK_SKEW_GRACE_US > start:
                fallback = candidate
        if parent is None:
            parent = fallback

        parents[span["spanID"]] = parent["spanID"] if parent else None
        stack.append(span)
    return parents


def _log_alert(fields: dict, enabled: bool = True) -> None:
    """Write a DETECTION entry to the shared alerts.log via collect.log_alert.
    Only writes when enabled=True (i.e. running in --json / demo pipeline mode).
    """
    if not enabled:
        return
    try:
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from collect import log_alert
        log_alert("DETECTION", fields)
    except Exception:
        pass  # log failure is never fatal


# Splunk's /v2/event ingest API silently accepts (200 OK) but never indexes
# an event containing a string property value longer than 256 characters —
# confirmed via direct bisection (256 chars lands, 257 does not). Leave room
# for the "...(truncated)" suffix so the final value never exceeds the limit.
EVENT_PROPERTY_MAX_LEN = 256
_TRUNCATION_SUFFIX = "...(truncated)"


def send_custom_event(event_type: str, dimensions: dict, properties: dict) -> None:
    """Emit a custom event to Splunk Observability Cloud.

    Truncate long string properties defensively so events actually land
    (see EVENT_PROPERTY_MAX_LEN comment above).
    """
    safe_properties = {
        k: (v[:EVENT_PROPERTY_MAX_LEN - len(_TRUNCATION_SUFFIX)] + _TRUNCATION_SUFFIX
            if isinstance(v, str) and len(v) > EVENT_PROPERTY_MAX_LEN else v)
        for k, v in properties.items()
    }
    _request("POST", "/v2/event", [{
        "eventType": event_type,
        "category":  "USER_DEFINED",
        "dimensions": dimensions,
        "properties": safe_properties,
        "timestamp":  int(time.time() * 1000),
    }], base_url=INGEST_URL)


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


# ── Noise filtering ────────────────────────────────────────────────────────────

def _is_noise_trace(root_operation: str) -> bool:
    """
    Return True if the root operation matches a known noise pattern.
    Covers service-registry heartbeats and health-check probes universally.
    """
    op = root_operation.lower()
    return any(p in op for p in NOISE_PATTERNS)


# ── Fingerprinting ─────────────────────────────────────────────────────────────

def build_fingerprint(trace: dict, known_root_ops: set[str] | None = None) -> list[dict]:
    """
    Build stable structural fingerprints from a trace's span tree.

    Returns a (possibly empty) list of fingerprint dicts. Each fingerprint is
    the ordered parent->child edge sequence of one root's subtree, hashed to
    a stable 16-char ID, immune to timing and span ID variation.

    Multi-root decomposition (2026-07-30 fix):
    A single trace can contain multiple independent logical operations that
    happen to share one trace ID — e.g. an entire user session (browse pages,
    add-to-cart, checkout, order-confirmation email) correlated under one
    trace by the frontend. The previous implementation rooted a single
    fingerprint at the absolute earliest span in the trace, which conflated
    all of these into one fingerprint whose shape depended on how many pages
    were visited before checkout — so the checkout fingerprint never
    stabilized even though the checkout flow itself was identical every time
    (traces never reached MIN_BASELINE_OCCURRENCES for the same hash).

    Fixed generically (no hardcoded service/operation names): every span
    whose inferred parent is None is treated as an independent fingerprint
    root, and a separate fingerprint is built from just its own descendant
    subtree (via parent_map, not wall-clock proximity). For a normal
    single-operation trace this yields exactly one fingerprint — unchanged
    behavior. For a multi-operation session trace it yields one fingerprint
    per logical operation, each stable regardless of what else happened
    earlier/later in the shared session trace.

    known_root_ops: if provided, subtrees smaller than MIN_SPANS whose root
    op is in this set are fingerprinted anyway (enables MISSING_SERVICE
    detection when a downstream service is completely gone and that
    operation's subtree collapses to 1 span).
    """
    spans = trace.get("spans", [])
    if not spans:
        return []

    by_id      = {s["spanID"]: s for s in spans}
    parent_map = _infer_parent_id(spans)

    children: dict[str | None, list[dict]] = defaultdict(list)
    for s in spans:
        children[parent_map.get(s["spanID"])].append(s)

    root_spans = children.get(None) or [min(spans, key=lambda s: s.get("startTime", 0))]

    fingerprints: list[dict] = []
    for root_span in root_spans:
        # Walk parent_map (not timestamps) to collect this root's own subtree.
        subtree_ids: set[str] = set()
        stack = [root_span["spanID"]]
        while stack:
            sid = stack.pop()
            if sid in subtree_ids:
                continue
            subtree_ids.add(sid)
            stack.extend(c["spanID"] for c in children.get(sid, []))
        subtree_spans = [by_id[sid] for sid in subtree_ids]

        if _is_noise_trace(root_span["operationName"]):
            continue

        if root_span["serviceName"] in NON_ROOT_SERVICES:
            continue

        root_op = f"{root_span['serviceName']}:{root_span['operationName']}"

        # Allow collapsed subtrees through only if root op is a known operation —
        # otherwise they're likely fragments of async/fire-and-forget spans.
        if len(subtree_spans) < MIN_SPANS and root_op not in (known_root_ops or set()):
            continue

        # Filter out health/registry probes that are merely initiated by a non-noisy root
        # (e.g. admin-server polling /actuator/health on other services)
        if len(subtree_spans) <= 3:
            all_ops = " ".join(s["operationName"] for s in subtree_spans).lower()
            if any(p in all_ops for p in NOISE_PATTERNS):
                continue

        sorted_subtree = sorted(subtree_spans, key=lambda s: s.get("startTime", 0))
        edges = []
        for span in sorted_subtree:
            if _is_framing_span(span):
                continue
            # Walk up past any framing ancestors to find the nearest real
            # (non-framing) parent, so a business-logic span's edge attaches
            # to a stable ancestor rather than to a noisy transport wrapper.
            parent_id = parent_map.get(span["spanID"])
            while (parent_id and parent_id in subtree_ids
                   and _is_framing_span(by_id[parent_id])):
                parent_id = parent_map.get(parent_id)
            if parent_id and parent_id in subtree_ids:
                parent = by_id[parent_id]
                edges.append((
                    f"{parent['serviceName']}:{parent['operationName']}",
                    f"{span['serviceName']}:{span['operationName']}",
                ))

        services = sorted({s["serviceName"] for s in subtree_spans})
        # Canonicalize edge order before hashing. Multiple spans commonly share
        # near-identical microsecond start timestamps (fast local calls, coarse
        # instrumentation clocks), so the raw traversal order is not stable
        # across otherwise-identical traces — the same tree shape would hash
        # differently just because of tie-order. Sorting the edge list itself
        # makes the hash depend only on the (parent, child) edge multiset, not
        # on visitation order.
        canonical_edges = sorted(edges)
        path    = " -> ".join(f"{a} -> {b}" for a, b in canonical_edges) if canonical_edges else root_op
        fp_hash = hashlib.sha256(path.encode()).hexdigest()[:16]

        fingerprints.append({
            "hash":       fp_hash,
            "path":       path,
            "root_op":    root_op,
            "services":   services,
            "span_count": len(subtree_spans),
            "edge_count": len(edges),
        })

    return fingerprints


# ── Anomaly classification ─────────────────────────────────────────────────────

def _auto_learn_no_missing(root_op: str, missing: set[str],
                           environment: str | None = None) -> None:
    """
    Persist a per-service exemption for root_op when watch-window evidence
    shows the "missing" services were present in other traces this window.
    Stored as exempt_services (a list of specific service names), not a blanket
    no_missing_service flag — so an exemption for one service (e.g. a peer
    service that's optionally absent) never masks detection of a genuinely
    different, unrelated service going missing under the same root_op.
    Idempotent — won't re-add services already covered.
    """
    overrides = load_overrides(environment)
    root_op_flags = overrides.setdefault("root_op_flags", {})
    entry = root_op_flags.setdefault(root_op, {})
    exempt = set(entry.get("exempt_services", []))
    if missing.issubset(exempt):
        return  # already covered
    exempt |= missing
    entry["exempt_services"] = sorted(exempt)
    entry["reason"] = (f"auto: {sorted(missing)} seen in other traces this window — "
                        f"optional-path variant, not an outage")
    save_overrides(overrides, environment)


def _exempt_services_for_root(entries) -> set[str] | str:
    """
    Collect the set of services exempted from MISSING_SERVICE detection for a
    root_op, from an iterable of baseline entries.

    Returns:
      - "ALL": a legacy blanket no_missing_service=True entry exists — every
        service is exempt (full backward compat with pre-per-service overrides).
      - set[str]: the union of exempt_services across entries (possibly empty).
    """
    exempt: set[str] = set()
    for info in entries:
        if info.get("no_missing_service"):
            return "ALL"
        exempt |= set(info.get("exempt_services", []))
    return exempt


def classify_anomaly(fp: dict, baseline: dict,
                     watch_services: set[str] | None = None,
                     environment: str | None = None) -> dict | None:
    """
    Compare a fingerprint against the baseline.
    Returns an anomaly dict or None if the trace matches a known pattern.
    Auto-promoted fingerprints are treated as known — no alert fired.

    watch_services: set of all services seen across ALL traces for this root_op
    in the current watch window. Used to suppress MISSING_SERVICE when the
    "missing" service was observed in other traces this window (optional path).
    When a new optional-path suppression is detected, it is written to the
    overrides file so future learn runs preserve the flag automatically.
    """
    root_op = fp["root_op"]
    fp_hash = fp["hash"]

    baseline_for_root = {
        h: info for h, info in baseline.get("fingerprints", {}).items()
        if info.get("root_op") == root_op
        and info.get("occurrences", 0) >= MIN_BASELINE_OCCURRENCES
    }

    # Services exempted from MISSING_SERVICE checks for this root_op — either
    # "ALL" (legacy blanket flag) or a specific set of service names.
    _exempt = _exempt_services_for_root(baseline_for_root.values())

    # NEW_FINGERPRINT — but skip if already auto-promoted.
    # A fingerprint must be seen >= MIN_BASELINE_OCCURRENCES times to be
    # considered "established". Rare/unseen hashes still fire as NEW_FINGERPRINT
    # so they don't silently bypass MISSING_SERVICE detection.
    stored = baseline.get("fingerprints", {}).get(fp_hash)
    if stored and stored.get("auto_promoted"):
        return None

    if not stored or stored.get("occurrences", 0) < MIN_BASELINE_OCCURRENCES:
        # Before firing NEW_FINGERPRINT, check if this is actually a
        # MISSING_SERVICE case: same root_op as baseline but fewer services
        # (e.g. downstream service gone → trace collapses to 1 span).
        if baseline_for_root:
            total_patterns = len(baseline_for_root)
            service_counts: dict[str, int] = defaultdict(int)
            for info in baseline_for_root.values():
                for svc in info.get("services", []):
                    service_counts[svc] += 1
            root_svc = root_op.split(":")[0] if ":" in root_op else root_op
            dom_threshold = _svc_threshold(
                root_svc, "missing_service_dominance_threshold",
                MISSING_SERVICE_DOMINANCE_THRESHOLD
            )
            dominant_services = {
                s for s, c in service_counts.items()
                if c / total_patterns >= dom_threshold
            }
            missing = dominant_services - set(fp["services"])
            if _exempt != "ALL":
                missing -= _exempt
            if missing and _exempt != "ALL":
                # Watch-window suppression: if ALL missing services were seen in
                # other traces this window, this is an optional-path variant —
                # the services aren't down, just absent on this code path.
                # Auto-learn the suppression into the overrides file.
                if watch_services and missing.issubset(watch_services):
                    _auto_learn_no_missing(root_op, missing, environment)
                    return None
                return {
                    "type":    "MISSING_SERVICE",
                    "message": (f"Expected service(s) absent from '{root_op}': "
                                f"{sorted(missing)}"),
                    "detail":  f"Path: {fp['path']}",
                    "fp":      fp,
                }
        # Suppress NEW_FINGERPRINT if the trace path itself contains noise operations
        # (e.g. startup config fetches, actuator probes from admin-server).
        # This auto-handles any framework-specific startup/probe patterns without
        # needing explicit configuration.
        if _is_noise_trace(fp["path"]):
            return None

        # Suppress NEW_FINGERPRINT for "degraded-path" variants: same root_op as
        # established auto_promoted baseline entries, no new services introduced,
        # and fewer spans than the minimum known baseline entry. This handles
        # shallow single-span traces that occasionally appear for well-known root_ops
        # (e.g. static asset requests that sometimes complete before child spans are
        # emitted). These are not structural drift — just partial trace captures.
        auto_promoted_for_root = {
            h: info for h, info in baseline.get("fingerprints", {}).items()
            if info.get("root_op") == root_op and info.get("auto_promoted")
        }
        if auto_promoted_for_root:
            all_known_services: set[str] = set()
            for info in auto_promoted_for_root.values():
                all_known_services.update(info.get("services", []))
            new_services = set(fp["services"]) - all_known_services
            min_known_spans = min(
                info.get("span_count", 0) for info in auto_promoted_for_root.values()
            )
            if not new_services and fp["span_count"] <= min_known_spans:
                return None

        return {
            "type":    "NEW_FINGERPRINT",
            "message": f"Unknown execution path for '{root_op}'",
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # For established hashes: run SPAN_COUNT_SPIKE, NEW_SERVICE, MISSING_SERVICE
    # checks even when the hash is known — these detect anomalies on familiar paths.
    root_svc = root_op.split(":")[0] if ":" in root_op else root_op

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

    # SPAN_COUNT_SPIKE / SPAN_COUNT_DROP — use per-fingerprint min/max if available,
    # falling back to span_count for older baseline entries that pre-date this field.
    # Aggregate across all fingerprints for this root_op so that the range reflects
    # the full observed distribution, not just a single structural variant.
    root_span_max = max(
        (info.get("span_count_max") or info.get("span_count", 0)
         for info in baseline_for_root.values()),
        default=0,
    )
    root_span_min = min(
        (info.get("span_count_min") or info.get("span_count", 0)
         for info in baseline_for_root.values()
         if (info.get("span_count_min") or info.get("span_count", 0)) > 0),
        default=0,
    )

    span_multiplier = _svc_threshold(
        root_svc, "span_count_spike_multiplier", SPAN_COUNT_SPIKE_MULTIPLIER
    )
    if root_span_max > 0 and fp["span_count"] > root_span_max * span_multiplier:
        return {
            "type":    "SPAN_COUNT_SPIKE",
            "message": (f"Span count spike for '{root_op}': "
                        f"{fp['span_count']} spans vs baseline max {root_span_max}"),
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # SPAN_COUNT_DROP — fire when span count is suspiciously low vs baseline min.
    # Catches cases like a retry loop that normally runs 5× completing in just 1×,
    # or a pipeline that normally fans out to multiple services collapsing to one.
    # Only fires on established hashes (known paths) to avoid noise from new variants.
    drop_threshold = _svc_threshold(
        root_svc, "span_count_drop_threshold", SPAN_COUNT_DROP_THRESHOLD
    )
    drop_min_baseline = int(_svc_threshold(
        root_svc, "span_count_drop_min_baseline", SPAN_COUNT_DROP_MIN_BASELINE
    ))
    if (stored and root_span_min >= drop_min_baseline
            and fp["span_count"] < root_span_min * drop_threshold):
        return {
            "type":    "SPAN_COUNT_DROP",
            "message": (f"Span count drop for '{root_op}': "
                        f"{fp['span_count']} spans vs baseline min {root_span_min}"),
            "detail":  f"Path: {fp['path']}",
            "fp":      fp,
        }

    # MISSING_SERVICE — fire when a service is dominant (present in
    # >= MISSING_SERVICE_DOMINANCE_THRESHOLD fraction of baseline patterns)
    # but absent from the current trace. Using dominance rather than strict
    # intersection prevents a single rare variant (occurrences=1) without the
    # service from masking a genuine absence of an important service.
    if baseline_for_root:
        total_patterns = len(baseline_for_root)
        service_counts: dict[str, int] = defaultdict(int)
        for info in baseline_for_root.values():
            for svc in info.get("services", []):
                service_counts[svc] += 1
        dom_threshold2 = _svc_threshold(
            root_svc, "missing_service_dominance_threshold",
            MISSING_SERVICE_DOMINANCE_THRESHOLD
        )
        dominant_services = {
            s for s, c in service_counts.items()
            if c / total_patterns >= dom_threshold2
        }
        missing = dominant_services - set(fp["services"])
        if _exempt != "ALL":
            missing -= _exempt
        if missing and _exempt != "ALL":
            if watch_services and missing.issubset(watch_services):
                _auto_learn_no_missing(root_op, missing, environment)
                return None
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
        data = json.loads(path.read_text())
        # Normalize: ensure every entry has 'hash' == its dict key, and
        # strip stray "Path: " prefixes that external tools may have injected.
        for k, v in data.get("fingerprints", {}).items():
            if "hash" not in v:
                v["hash"] = k
            if isinstance(v.get("path"), str) and v["path"].startswith("Path: "):
                v["path"] = v["path"][6:]
        return data
    return {"fingerprints": {}, "topology": None,
            "created_at": None, "updated_at": None,
            "sf_environment": environment}


def save_baseline(baseline: dict, environment: str | None = None) -> None:
    path = _baseline_path(environment)
    baseline["updated_at"] = datetime.now(timezone.utc).isoformat()
    baseline["environment"] = environment
    path.write_text(json.dumps(baseline, indent=2))
    print(f"  Baseline saved -> {path}")


# ── Persistent baseline overrides ─────────────────────────────────────────────
# baseline_overrides.<env>.json stores per-root_op flag overrides that persist
# across learn/reset cycles. Flags are merged back into fingerprint entries by
# cmd_learn after every learn run, so they are never lost on re-baseline.
#
# Schema:
#   { "root_op_flags": { "<root_op>": { "no_missing_service": true, "reason": "..." } } }
#
# Manage with:
#   python3 trace_fingerprint.py --environment <env> overrides --set "root_op" no_missing_service true "reason text"
#   python3 trace_fingerprint.py --environment <env> overrides --clear "root_op"
#   python3 trace_fingerprint.py --environment <env> overrides --list

def _overrides_path(environment: str | None = None) -> Path:
    if environment:
        return _DATA_DIR / f"baseline_overrides.{environment}.json"
    return _DATA_DIR / "baseline_overrides.json"


def load_overrides(environment: str | None = None) -> dict:
    path = _overrides_path(environment)
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            pass
    return {"root_op_flags": {}}


def save_overrides(overrides: dict, environment: str | None = None) -> None:
    path = _overrides_path(environment)
    path.write_text(json.dumps(overrides, indent=2))
    print(f"  Overrides saved -> {path}")


def _auto_detect_no_missing_service(fingerprints: dict) -> dict[str, dict[str, str]]:
    """
    Automatically determine which services should be exempted from
    MISSING_SERVICE detection for each root_op.
    Returns {root_op: {service: reason}} — per-service, not a blanket flag, so
    exempting one service (e.g. a peer service) never masks a different,
    genuinely-missing service under the same root_op.

    Two patterns are detected — both are generic, no hardcoded service names:

    1. Infra peer: a service that would be flagged as "dominant missing" is itself
       a root service in the baseline (i.e. it initiates its own traces). Such
       services are peers, not dependencies — their absence on some paths is normal.
       Example: discovery-server has its own Eureka heartbeat traces, so it is a
       peer of api-gateway, not a downstream dependency.

    2. Optional-path variant: a root_op has multiple baseline fingerprints and the
       "would-be-dominant" service is absent from >= OPTIONAL_ABSENT_FRACTION of
       them. If the service is absent in 20%+ of known-good variants, absence is a
       normal steady-state condition, not an anomaly.
       Example: owners/{id} has variants with and without visits-service (owners
       who have no pets never trigger a visits-service call).
    """
    OPTIONAL_ABSENT_FRACTION = 0.20  # absent in ≥20% of variants → optional

    # Build set of services that substantially self-originate traces.
    # We sum occurrences across all root_ops for each service. A service
    # qualifies as a "peer" (not a dep) only when it has enough self-originated
    # traffic to be clearly self-driving — not just a single OTel auto-promoted
    # stub (occurrences=1). Threshold: ≥ MIN_BASELINE_OCCURRENCES * 3 total.
    PEER_MIN_OCCURRENCES = MIN_BASELINE_OCCURRENCES * 3
    root_svc_occurrences: dict[str, int] = defaultdict(int)
    for info in fingerprints.values():
        ro = info.get("root_op", "")
        if ":" in ro:
            root_svc_occurrences[ro.split(":")[0]] += info.get("occurrences", 0)
    root_services = {
        svc for svc, occ in root_svc_occurrences.items()
        if occ >= PEER_MIN_OCCURRENCES
    }

    # Group fingerprints by root_op for multi-variant analysis
    by_root: dict[str, list[dict]] = defaultdict(list)
    for info in fingerprints.values():
        root_op = info.get("root_op", "")
        if root_op and info.get("occurrences", 0) >= MIN_BASELINE_OCCURRENCES:
            by_root[root_op].append(info)

    auto_suppress: dict[str, dict[str, str]] = defaultdict(dict)

    for root_op, entries in by_root.items():
        if len(entries) < 2:
            # Single variant — can't distinguish optional from missing without
            # multi-variant evidence; skip auto-detection for this root_op.
            # (Infra-peer check still applies below.)
            pass

        total = len(entries)
        root_svc = root_op.split(":")[0] if ":" in root_op else root_op
        dom_threshold = _svc_threshold(
            root_svc, "missing_service_dominance_threshold",
            MISSING_SERVICE_DOMINANCE_THRESHOLD
        )

        # Count how often each service appears across variants
        service_counts: dict[str, int] = defaultdict(int)
        for entry in entries:
            for svc in entry.get("services", []):
                service_counts[svc] += 1

        dominant = {s for s, c in service_counts.items()
                    if c / total >= dom_threshold and s != root_svc}

        for svc in dominant:
            absent_count = total - service_counts[svc]

            # Pattern 1: infra peer — the "dominant" service is itself a root service
            if svc in root_services:
                auto_suppress[root_op][svc] = (
                    f"auto: '{svc}' is a peer service (has own root traces), "
                    f"not a downstream dependency"
                )
                continue

            # Pattern 2: optional-path variant — absent in ≥ OPTIONAL_ABSENT_FRACTION
            # of baseline variants, meaning absence is a known-good state
            if total >= 2 and absent_count / total >= OPTIONAL_ABSENT_FRACTION:
                auto_suppress[root_op][svc] = (
                    f"auto: '{svc}' absent in {absent_count}/{total} baseline variants "
                    f"({absent_count/total:.0%}) — optional path"
                )

    return dict(auto_suppress)


def apply_overrides(fingerprints: dict, environment: str | None = None) -> int:
    """
    Merge persistent root_op flag overrides into fingerprint entries, then
    auto-detect additional no_missing_service candidates from the baseline itself.
    Returns number of entries updated.

    Order of precedence (highest wins):
      1. Explicit overrides file (baseline_overrides.<env>.json) — always applied
      2. Auto-detection (_auto_detect_no_missing_service) — fills in the rest
         without requiring any human configuration

    Auto-detected suppressions are also written back to the overrides file so
    they are visible, auditable, and can be cleared with `overrides --clear`.
    """
    overrides = load_overrides(environment)
    root_op_flags = overrides.setdefault("root_op_flags", {})

    # Auto-detect per-service exemption candidates and merge into overrides
    # (won't overwrite an explicit blanket no_missing_service=True entry).
    auto = _auto_detect_no_missing_service(fingerprints)
    auto_added = 0
    for root_op, svc_reasons in auto.items():
        entry = root_op_flags.setdefault(root_op, {})
        if entry.get("no_missing_service"):
            continue  # explicit blanket exemption already covers everything
        exempt = set(entry.get("exempt_services", []))
        new_svcs = set(svc_reasons) - exempt
        if not new_svcs:
            continue
        exempt |= new_svcs
        entry["exempt_services"] = sorted(exempt)
        entry["reason"] = "; ".join(svc_reasons[s] for s in sorted(new_svcs))
        auto_added += 1

    if auto_added:
        save_overrides(overrides, environment)

    # Apply exempt_services / no_missing_service flags to fingerprint entries
    updated = 0
    for h, fp in fingerprints.items():
        root_op = fp.get("root_op", "")
        if root_op in root_op_flags:
            flags = root_op_flags[root_op]
            changed = False
            for flag, value in flags.items():
                if flag == "reason":
                    continue
                if fp.get(flag) != value:
                    fp[flag] = value
                    changed = True
            if changed:
                updated += 1
    return updated


# ── OTel baseline merge ────────────────────────────────────────────────────────

def _merge_otel_baseline(fingerprints: dict, environment: str | None) -> int:
    """
    Fetch the behavioral-baseline ConfigMap from the cluster and merge any
    OTel-promoted fingerprint hashes that are absent from the Python baseline.

    The OTel processor auto-promotes fingerprints after 10 detections and
    writes them back via the baseline-sync sidecar → ConfigMap. These cover
    paths the Python APM-query approach may miss (low-frequency endpoints,
    direct service-to-service calls routed through the cluster but sampled
    sparsely in Splunk). Merging them prevents watch from firing NEW_FINGERPRINT
    for paths the cluster-side processor already considers stable.

    Requires EC2_IP + EC2_PASSWORD (or EC2_PASS) in env — silently skips if
    not configured or if kubectl/sshpass are unavailable.

    Returns the number of fingerprints merged.
    """
    ec2_ip   = os.environ.get("EC2_IP", "")
    ec2_pass = os.environ.get("EC2_PASSWORD") or os.environ.get("EC2_PASS", "")
    ec2_port = os.environ.get("EC2_PORT", "2222")
    if not ec2_ip or not ec2_pass:
        return 0

    try:
        result = subprocess.run(
            ["sshpass", f"-p{ec2_pass}",
             "ssh", "-T", "-p", ec2_port,
             "-o", "StrictHostKeyChecking=no",
             "-o", "ConnectTimeout=10",
             f"splunk@{ec2_ip}",
             "kubectl get configmap behavioral-baseline "
             "-o jsonpath='{.data.baseline\\.json}' 2>/dev/null"],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return 0
        otel_data = json.loads(result.stdout.strip())
    except Exception:
        return 0

    merged = 0
    now_iso = datetime.now(timezone.utc).isoformat()
    for h, entry in otel_data.get("fingerprints", {}).items():
        if h in fingerprints:
            continue
        if not entry.get("auto_promoted"):
            continue
        # Ensure required fields present before merging
        if not entry.get("root_op") or not entry.get("path"):
            continue
        fingerprints[h] = {
            "hash":          h,
            "path":          entry.get("path", ""),
            "root_op":       entry.get("root_op", ""),
            "services":      entry.get("services", []),
            "span_count":    entry.get("span_count", 0),
            "edge_count":    entry.get("edge_count", 0),
            "occurrences":   entry.get("occurrences", 1),
            "watch_hits":    0,
            "auto_promoted": True,
            "promoted_at":   entry.get("updated_at") or now_iso,
            "first_seen":    entry.get("first_seen") or now_iso,
        }
        merged += 1
    return merged


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
              window_offset_minutes: int = 0,
              reset: bool = False,
              bootstrap: bool = False,
              environment: str | None = None) -> None:
    """Sample recent traces and build the baseline fingerprint DB."""
    # Bootstrap mode: accept every fingerprint seen at least once (no occurrence
    # gate). Intended for cold-start on a freshly deployed cluster where traffic
    # has been running for only 10-30 minutes and most paths haven't repeated
    # MIN_BASELINE_OCCURRENCES times yet. Always implies --reset.
    effective_min_occurrences = 1 if bootstrap else MIN_BASELINE_OCCURRENCES
    if bootstrap:
        reset = True
        print(f"[learn] Bootstrap mode — accepting fingerprints seen ≥ 1 time "
              f"(overrides MIN_BASELINE_OCCURRENCES={MIN_BASELINE_OCCURRENCES})")

    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[learn] Discovering services for {env_desc}...")
    topo = discover_topology(environment=environment)
    print(f"  Found {len(topo['services'])} services + "
          f"{len(topo['inferred'])} inferred nodes")
    if window_offset_minutes:
        print(f"  Sampling {window_minutes}m window ending {window_offset_minutes}m ago...")
    else:
        print(f"  Sampling last {window_minutes}m of traces...")

    now_ms   = int(time.time() * 1000) - window_offset_minutes * 60 * 1000
    start_ms = now_ms - window_minutes * 60 * 1000

    # Search per-service in parallel so each service gets its own 200-trace quota.
    # A single cross-service query dilutes rare services (e.g. vets-service) to
    # 1-2 slots out of 200, preventing them from reaching MIN_BASELINE_OCCURRENCES.
    services_to_search = topo["services"] or []
    if services_to_search:
        print(f"  Searching {len(services_to_search)} services in parallel...")
        all_trace_map: dict[str, dict] = {}
        with ThreadPoolExecutor(max_workers=len(services_to_search)) as _pool:
            _futures = {
                _pool.submit(search_traces, [svc], start_ms, now_ms,
                             LEARN_SAMPLE_LIMIT, environment): svc
                for svc in services_to_search
            }
            for _fut in as_completed(_futures):
                svc_name = _futures[_fut]
                try:
                    svc_traces = _fut.result()
                    before = len(all_trace_map)
                    for t in svc_traces:
                        all_trace_map[t["traceId"]] = t
                    print(f"    {svc_name}: {len(svc_traces)} traces "
                          f"(+{len(all_trace_map) - before} new)")
                except Exception as e:
                    print(f"  [warn] search failed for {svc_name}: {e}",
                          file=sys.stderr)
        traces = list(all_trace_map.values())
    else:
        traces = search_traces([], start_ms, now_ms, environment=environment)
    print(f"  Found {len(traces)} candidate traces (deduplicated)")

    baseline = load_baseline(environment)
    if reset:
        baseline = {}
        print("  [reset] Wiped existing baseline — starting fresh.")
    is_fresh = not baseline.get("created_at")
    if is_fresh:
        baseline["created_at"] = datetime.now(timezone.utc).isoformat()
    baseline["topology"] = topo

    fingerprints = baseline.setdefault("fingerprints", {})
    new_count = updated_count = skipped = 0
    observed_hashes: set[str] = set()

    # Stage new fingerprints separately — only graduate to baseline once they
    # reach MIN_BASELINE_OCCURRENCES within this learn window. This prevents
    # rare one-off traces from entering the baseline as seen=1 entries, which
    # would fire spurious NEW_FINGERPRINT alerts on every subsequent watch run.
    staged: dict[str, dict] = {}

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
            trace_fps = build_fingerprint(trace)
            if not trace_fps:
                skipped += 1
                continue
            for fp in trace_fps:
                h = fp["hash"]
                observed_hashes.add(h)
                if h in fingerprints:
                    # Already established — increment occurrence count and refresh last_seen
                    fingerprints[h]["occurrences"] = fingerprints[h].get("occurrences", 1) + 1
                    fingerprints[h]["last_seen"] = datetime.now(timezone.utc).isoformat()
                    # Update running min/max span counts across observations
                    sc = fp["span_count"]
                    fingerprints[h]["span_count_min"] = min(fingerprints[h].get("span_count_min", sc), sc)
                    fingerprints[h]["span_count_max"] = max(fingerprints[h].get("span_count_max", sc), sc)
                    updated_count += 1
                else:
                    # Stage until seen MIN_BASELINE_OCCURRENCES times this window
                    if h not in staged:
                        now_iso = datetime.now(timezone.utc).isoformat()
                        sc = fp["span_count"]
                        staged[h] = {
                            "hash":          h,
                            "path":          fp["path"],
                            "root_op":       fp["root_op"],
                            "services":      fp["services"],
                            "span_count":    sc,
                            "span_count_min": sc,
                            "span_count_max": sc,
                            "edge_count":    fp["edge_count"],
                            "occurrences":   0,
                            "watch_hits":    0,
                            "auto_promoted": False,
                            "promoted_at":   None,
                            "first_seen":    now_iso,
                            "last_seen":     now_iso,
                        }
                    else:
                        sc = fp["span_count"]
                        staged[h]["span_count_min"] = min(staged[h].get("span_count_min", sc), sc)
                        staged[h]["span_count_max"] = max(staged[h].get("span_count_max", sc), sc)
                    staged[h]["occurrences"] += 1
                    if staged[h]["occurrences"] >= effective_min_occurrences:
                        fingerprints[h] = staged[h]
                        new_count += 1
                        print(f"  [new] {fp['root_op']}  ->  "
                              f"{fp['path'][:80]}{'...' if len(fp['path']) > 80 else ''}")

    # Prune fingerprints not seen in this learn window (unless auto-promoted,
    # which means they were deliberately accepted and should persist).
    if observed_hashes or is_fresh:
        stale = [
            h for h, info in fingerprints.items()
            if h not in observed_hashes and not info.get("auto_promoted")
        ]
        if stale:
            for h in stale:
                del fingerprints[h]
            print(f"  Pruned {len(stale)} stale fingerprint(s) not seen in this window")

    # Filter one-directional infrastructure traces: fingerprints whose non-root
    # services never appear as a root service anywhere in the learned set are
    # startup/init-only calls (config fetch, service registration, etc.) that
    # won't appear in steady-state traffic. Keeping them causes false
    # MISSING_SERVICE alerts after every service restart.
    # This is generic — no hardcoded service names needed.
    # Skip in bootstrap mode: short windows may not yet have enough service
    # diversity for downstream services to appear as roots. The filter runs
    # correctly on subsequent regular learn runs once traffic stabilises.
    if not bootstrap:
        root_services = {
            info["root_op"].split(":")[0]
            for info in fingerprints.values()
            if ":" in info.get("root_op", "")
        }
        infra_only = []
        for h, info in fingerprints.items():
            if info.get("auto_promoted"):
                continue
            root_svc = info["root_op"].split(":")[0] if ":" in info.get("root_op", "") else ""
            non_root_svcs = {s for s in info.get("services", []) if s != root_svc}
            if non_root_svcs and non_root_svcs.isdisjoint(root_services):
                infra_only.append(h)
        if infra_only:
            for h in infra_only:
                del fingerprints[h]
            print(f"  Filtered {len(infra_only)} infra-only fingerprint(s) "
                  f"(non-root services never appear as roots — startup/init calls)")

    rare = len([h for h in staged if h not in fingerprints])
    if rare:
        print(f"  Excluded {rare} rare fingerprint(s) seen < {effective_min_occurrences}x in window")

    # Bootstrap consolidation pass: after accepting everything seen ≥ 1 time,
    # re-scan the staged set and drop any hashes seen exactly once — these are
    # one-off structural variants (cache miss, cold-start span) that won't
    # recur in steady state. Hashes seen ≥ 2 times stay. This gives a cleaner
    # baseline than min=1 without requiring a full second learn run.
    if bootstrap:
        single_hit = [h for h, info in fingerprints.items()
                      if not info.get("auto_promoted") and info.get("occurrences", 0) == 1]
        if single_hit:
            for h in single_hit:
                del fingerprints[h]
            print(f"  Bootstrap consolidation: dropped {len(single_hit)} seen-once "
                  f"fingerprint(s) — run regular learn to re-add if they recur")

    # Merge OTel-promoted hashes from the cluster ConfigMap. The OTel processor
    # auto-promotes fingerprints after 10 detections and writes them to
    # /baseline/baseline.json (synced to the behavioral-baseline ConfigMap by the
    # baseline-sync sidecar). These hashes represent confirmed-stable paths that
    # the Python APM-query approach may have missed (low-frequency endpoints,
    # direct service-to-service calls). Merging them closes the sync gap so
    # watch runs don't fire NEW_FINGERPRINT for paths the OTel layer already knows.
    otel_merged = _merge_otel_baseline(fingerprints, environment)
    if otel_merged:
        print(f"  Merged {otel_merged} OTel-promoted fingerprint(s) from cluster ConfigMap")

    print(f"  Summary: {new_count} new, {updated_count} updated, "
          f"{skipped} skipped (noise/shallow)")

    # Merge persistent overrides (no_missing_service etc.) back into fingerprints.
    # This runs after every learn so flags set via `overrides --set` survive re-learn.
    overrides_applied = apply_overrides(fingerprints, environment)
    if overrides_applied:
        print(f"  Applied overrides to {overrides_applied} fingerprint(s) "
              f"(from baseline_overrides.{environment}.json)")

    save_baseline(baseline, environment)


def cmd_watch(window_minutes: int = 10,
              environment: str | None = None,
              json_output: bool = False) -> list[dict]:
    """
    Compare recent traces to baseline. Emits Splunk custom events on drift.
    Also detects entirely new services that have appeared since baseline was built.
    Returns a list of anomaly dicts (also printed to stdout unless json_output=True,
    in which case the anomaly list is written as JSON to stdout for piping to agent.py).
    """
    env_desc = f"environment '{environment}'" if environment else "all environments"
    print(f"[watch] Discovering topology + searching traces in parallel ({env_desc})...")

    baseline = load_baseline(environment)
    if not baseline["fingerprints"]:
        print(f"  [warn] Baseline for {env_desc} is empty — run 'learn' first.",
              file=sys.stderr)
        sys.exit(1)

    # Apply persistent overrides in-memory so no_missing_service flags are
    # respected even when the baseline hasn't been re-learned since the override
    # was set. Does not write to disk — learn does the durable merge.
    apply_overrides(baseline["fingerprints"], environment)

    # Run topology discovery and trace search concurrently — they're independent.
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    # Seed the trace search with baseline services so we don't need to wait for topo.
    baseline_topo_services = list(
        set(baseline.get("topology", {}).get("services", []))
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        topo_future   = pool.submit(discover_topology, environment=environment)
        traces_future = pool.submit(search_traces, baseline_topo_services,
                                    start_ms, now_ms, WATCH_SAMPLE_LIMIT,
                                    environment)
        topo   = topo_future.result()
        traces = traces_future.result()

    print(f"  Topology: {len(topo['services'])} services | "
          f"Traces: {len(traces)} candidates")

    # Alert on new *instrumented* services not present at baseline time.
    # Inferred nodes (db nodes, gateways) are excluded — they vary by trace
    # sampling and should not trigger topology alerts.
    baseline_services = set(baseline.get("topology", {}).get("services", []))
    baseline_inferred = set(baseline.get("topology", {}).get("inferred", []))
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
                                "sf_environment": environment or "all"},
                    properties={
                        "message":       f"New service '{svc}' appeared in APM topology",
                        "sf_environment":   environment or "all",
                        "detector_tier": "tier1",
                        "detector_name": "topology-new-service",
                    },
                )
                print(f"    Event sent for {svc}")
            except Exception as e:
                print(f"    Failed to send event: {e}", file=sys.stderr)

    anomalies_found = checked = skipped = 0
    alerted_hashes: set[str] = set()
    anomaly_list: list[dict] = []
    # Track which new hashes were seen this run (for auto-promotion)
    new_hashes_seen: set[str] = set()
    # Per-service counters for summary
    svc_checked: dict[str, int] = defaultdict(int)
    svc_anomalies: dict[str, int] = defaultdict(int)
    all_downstream: set[str] = set()  # all services seen across all traces

    trace_ids = [m.get("traceId") for m in traces if m.get("traceId")]
    total = len(trace_ids)
    print(f"  Fetching {total} traces ({MAX_WORKERS} parallel)...")

    # Fetch all traces in parallel with inline progress updates
    fetched: list[tuple[str, dict]] = []
    done_count = 0
    PROGRESS_INTERVAL = max(1, total // 5)  # print ~5 updates
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_id = {pool.submit(get_trace_full, tid): tid for tid in trace_ids}
        for future in as_completed(future_to_id):
            tid = future_to_id[future]
            done_count += 1
            if done_count % PROGRESS_INTERVAL == 0 or done_count == total:
                print(f"    {done_count}/{total} fetched...", flush=True)
            try:
                trace = future.result()
            except Exception as e:
                print(f"  [warn] trace {tid}: {e}", file=sys.stderr)
                skipped += 1
                continue
            if not trace:
                skipped += 1
                continue
            fetched.append((tid, trace))

    # Pre-compute known root ops from baseline so collapsed 1-span traces
    # (e.g. when a downstream service is completely gone) can still be
    # fingerprinted and trigger MISSING_SERVICE detection.
    known_root_ops = {
        v["root_op"] for v in baseline.get("fingerprints", {}).values()
        if v.get("root_op")
    }

    # First pass: build per-root_op service presence map from the watch window.
    # Used to suppress MISSING_SERVICE when the "missing" service was seen in
    # other traces of the same root_op this window (optional-path variant).
    watch_root_op_services: dict[str, set[str]] = defaultdict(set)
    for _, trace in fetched:
        for fp_pre in build_fingerprint(trace, known_root_ops=known_root_ops):
            for svc in fp_pre.get("services", []):
                watch_root_op_services[fp_pre["root_op"]].add(svc)

    seen_root_ops: set[str] = set()
    for trace_id, trace in fetched:
        trace_fps = build_fingerprint(trace, known_root_ops=known_root_ops)
        if not trace_fps:
            skipped += 1
            continue

        for fp in trace_fps:
            checked += 1
            root_svc_key = fp["root_op"].split(":")[0] if ":" in fp["root_op"] else fp["root_op"]
            svc_checked[root_svc_key] += 1
            all_downstream.update(fp.get("services", []))
            seen_root_ops.add(fp["root_op"])
            if fp["hash"] in alerted_hashes:
                continue

            anomaly = classify_anomaly(fp, baseline,
                                       watch_services=watch_root_op_services.get(fp["root_op"], set()),
                                       environment=environment)
            if anomaly:
                alerted_hashes.add(fp["hash"])
                svc_anomalies[root_svc_key] += 1
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
                svc = root_svc_key
                # Extract missing services from the message for MISSING_SERVICE anomalies
                _missing = []
                if anomaly["type"] == "MISSING_SERVICE":
                    _m = re.search(r"absent from '[^']+': (\[.*?\])", anomaly["message"])
                    if _m:
                        try:
                            _missing = json.loads(_m.group(1).replace("'", '"'))
                        except Exception:
                            pass
                anomaly_list.append({
                    "anomaly_type":      anomaly["type"],
                    "service":           svc,
                    "root_op":           fp["root_op"],
                    "message":           anomaly["message"],
                    "detail":            anomaly["detail"],
                    "trace_id":          trace_id,
                    "services_in_trace": fp["services"],
                    "missing_services":  _missing,
                })
                print(f"\n  ANOMALY DETECTED")
                print(f"    Type:    {anomaly['type']}")
                print(f"    Message: {anomaly['message']}")
                print(f"    Detail:  {anomaly['detail']}")
                print(f"    TraceID: {trace_id}")
                _log_alert({
                    "anomaly_type": anomaly["type"],
                    "environment":  environment or "all",
                    "service":      svc,
                    "root_op":      fp["root_op"],
                    "message":      anomaly["message"],
                    "detail":       anomaly["detail"],
                    "trace_id":     trace_id,
                    "services_in_trace": ", ".join(fp["services"]),
                }, enabled=False)
                try:
                    root_svc_for_dims = fp["root_op"].split(":")[0] if ":" in fp["root_op"] else fp["root_op"]
                    dims = {
                        "anomaly_type":   anomaly["type"],
                        "root_operation": fp["root_op"],
                        "fp_hash":        fp["hash"],
                        "sf_environment": environment or "all",
                        "service":        root_svc_for_dims,
                    }
                    send_custom_event(
                        event_type="trace.path.drift",
                        dimensions=dims,
                        properties={
                            "message":       anomaly["message"],
                            "detail":        anomaly["detail"],
                            "trace_id":      trace_id,
                            "path":          fp["path"],
                            "services":      ",".join(fp["services"]),
                            "missing_services": ",".join(_missing or [root_svc_for_dims]),
                            "span_count":    fp["span_count"],
                            "sf_environment": environment or "all",
                            "detector_tier": "tier2",
                            "detector_name": "trace-path-drift",
                            # Dimensions (including "service") are searchable but never
                            # returned by /v2/event/find — the olly frontend's
                            # toBehavioralSignal() only resolves via metadata.service or
                            # properties.service, so it must be duplicated here too or the
                            # event gets silently dropped before it ever reaches the map.
                            # anomaly_type/root_operation need the same duplication:
                            # without them, signal.anomalyType stays undefined and
                            # mergeBehavioralSignalsIntoGraph() never takes the
                            # MISSING_SERVICE branch, so no ghost node is ever created.
                            "service":       root_svc_for_dims,
                            "anomaly_type":  anomaly["type"],
                            "root_operation": fp["root_op"],
                        },
                    )
                    # sf_service ties the alarm to the actual missing dependency's
                    # APM Service Map node (native detector-alert badge), not the
                    # caller — same convention provision_detectors.py already uses
                    # for Tier 3/4 detectors so they show up natively on the map.
                    for missing_svc in (_missing or [root_svc_for_dims]):
                        send_metric("behavioral_baseline.anomaly.count", 1, {
                            **dims, "sf_service": missing_svc,
                        })
                    print(f"    Event sent (trace.path.drift)")
                except Exception as e:
                    print(f"    Failed to send event: {e}", file=sys.stderr)

    # ── Silent root_op detection ───────────────────────────────────────────────
    # If a baseline root_op has zero traces in the watch window it means the
    # operation is completely absent — either the service is down and the caller
    # is returning a circuit-breaker fallback (generating no downstream span),
    # or traffic to that path has stopped entirely. Fire MISSING_SERVICE for
    # every dominant service in each silent root_op.
    # For silent detection, sum occurrences across all patterns for a root_op
    # and require a minimum total. This filters infrequent ops (e.g. user-triggered
    # edits) that don't appear in every watch window and would cause false positives.
    SILENT_MIN_OCCURRENCES = max(MIN_BASELINE_OCCURRENCES, 4)
    root_op_occurrences: dict[str, int] = defaultdict(int)
    for info in baseline.get("fingerprints", {}).values():
        root_op_occurrences[info["root_op"]] += info.get("occurrences", 0)
    fps_by_root: dict[str, list[dict]] = defaultdict(list)
    for info in baseline.get("fingerprints", {}).values():
        if root_op_occurrences[info["root_op"]] >= SILENT_MIN_OCCURRENCES:
            fps_by_root[info["root_op"]].append(info)

    # Root services known from the baseline — used to detect infra-only root_ops
    # (their non-root services never appear as roots = startup/init-only calls).
    bl_root_services = {
        info["root_op"].split(":")[0]
        for info in baseline.get("fingerprints", {}).values()
        if ":" in info.get("root_op", "")
    }

    for root_op, bl_entries in fps_by_root.items():
        if root_op in seen_root_ops:
            continue
        if _is_noise_trace(root_op.split(":", 1)[-1] if ":" in root_op else root_op):
            continue
        # Services exempted from MISSING_SERVICE for this root_op — a blanket
        # "ALL" skips the whole root_op (legacy); otherwise dominant_services
        # is filtered below so an exemption for one service never masks a
        # genuinely different missing service.
        _exempt_silent = _exempt_services_for_root(bl_entries)
        if _exempt_silent == "ALL":
            continue
        # Also skip if any span path in the baseline entries is a noise operation
        # (e.g. Eureka registration PUTs rooted at a service span like customers-service:PUT)
        if any(_is_noise_trace(info.get("path", "")) for info in bl_entries):
            continue
        # Skip root_ops whose baseline entries are infra-only: all non-root services
        # in every entry are absent from the set of known root services. These are
        # startup/init-only calls (config fetch, service registration, etc.) that
        # won't appear in steady-state — no hardcoded service names needed.
        root_svc_here = root_op.split(":")[0] if ":" in root_op else root_op
        if all(
            bool(non_root := {s for s in info.get("services", []) if s != root_svc_here})
            and non_root.isdisjoint(bl_root_services)
            for info in bl_entries
        ):
            continue
        total_patterns = len(bl_entries)
        service_counts: dict[str, int] = defaultdict(int)
        for info in bl_entries:
            for svc in info.get("services", []):
                service_counts[svc] += 1
        root_svc = root_op.split(":")[0] if ":" in root_op else root_op
        dom_threshold = _svc_threshold(
            root_svc, "missing_service_dominance_threshold",
            MISSING_SERVICE_DOMINANCE_THRESHOLD
        )
        dominant_services = {
            s for s, c in service_counts.items()
            if c / total_patterns >= dom_threshold
        } - _exempt_silent
        if not dominant_services:
            continue
        silent_hash = hashlib.sha256(f"SILENT:{root_op}".encode()).hexdigest()[:16]
        if silent_hash in alerted_hashes:
            continue
        alerted_hashes.add(silent_hash)
        anomalies_found += 1
        missing_svcs = sorted(dominant_services)
        root_svc_key = root_op.split(":")[0] if ":" in root_op else root_op
        anomaly_list.append({
            "anomaly_type":     "MISSING_SERVICE",
            "service":          root_svc_key,
            "root_op":          root_op,
            "message":          f"No traces for '{root_op}' in window — expected service(s) absent: {missing_svcs}",
            "detail":           f"Root op silent (0 traces in {window_minutes}m window)",
            "missing_services": missing_svcs,
        })
        print(f"\n  ANOMALY DETECTED")
        print(f"    Type:    MISSING_SERVICE")
        print(f"    Message: No traces for '{root_op}' in window — "
              f"expected service(s) absent: {missing_svcs}")
        print(f"    Detail:  Root op silent (0 traces in {window_minutes}m window)")
        _log_alert({
            "anomaly_type":    "MISSING_SERVICE",
            "environment":     environment or "all",
            "service":         root_svc,
            "root_op":         root_op,
            "message":         f"No traces for '{root_op}' in window — expected service(s) absent: {missing_svcs}",
            "detail":          f"Root op completely silent — 0 traces in {window_minutes}m window (circuit breaker likely engaged)",
            "missing_services": ", ".join(missing_svcs),
        }, enabled=False)
        try:
            dims = {
                "anomaly_type":   "MISSING_SERVICE",
                "root_operation": root_op,
                "fp_hash":        silent_hash,
                "sf_environment": environment or "all",
                "service":        root_svc,
            }
            send_custom_event(
                event_type="trace.path.drift",
                dimensions=dims,
                properties={
                    "message":       (f"No traces for '{root_op}' in window — "
                                      f"expected service(s) absent: {missing_svcs}"),
                    "detail":        f"Root op silent (0 traces in {window_minutes}m window)",
                    "path":          root_op,
                    "services":      ",".join(missing_svcs),
                    "missing_services": ",".join(missing_svcs),
                    "span_count":    0,
                    "sf_environment": environment or "all",
                    "detector_tier": "tier2",
                    "detector_name": "trace-path-drift",
                    # dimensions["service"] is searchable but never returned by
                    # /v2/event/find — must duplicate in properties or the
                    # frontend's toBehavioralSignal() silently drops the event.
                    # Same applies to anomaly_type/root_operation — without them
                    # signal.anomalyType stays undefined and
                    # mergeBehavioralSignalsIntoGraph() never creates the ghost node.
                    "service":       root_svc,
                    "anomaly_type":  "MISSING_SERVICE",
                    "root_operation": root_op,
                },
            )
            # sf_service ties the alarm to each actual missing dependency's APM
            # Service Map node (native detector-alert badge), not the caller —
            # same convention provision_detectors.py uses for Tier 3/4 detectors.
            for missing_svc in missing_svcs:
                send_metric("behavioral_baseline.anomaly.count", 1, {
                    **dims, "sf_service": missing_svc,
                })
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
    # Per-service breakdown
    all_svcs = sorted(set(list(svc_checked.keys()) + list(svc_anomalies.keys())))
    if all_svcs:
        print("  Per-service breakdown:")
        for svc_name in all_svcs:
            n_checked = svc_checked.get(svc_name, 0)
            n_anom    = svc_anomalies.get(svc_name, 0)
            flag = f"  [{n_anom} anomaly{'s' if n_anom != 1 else ''}]" if n_anom else ""
            print(f"    {svc_name:<35} {n_checked:>3} traces checked{flag}")
        downstream_only = sorted(all_downstream - set(all_svcs))
        if downstream_only:
            print(f"  Downstream services seen: {', '.join(downstream_only)}")
    if anomalies_found == 0:
        print("  All trace paths match baseline")

    if json_output:
        result = {
            "environment":    environment or "all",
            "timestamp":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "window_minutes": window_minutes,
            "checked":        checked,
            "anomalies":      anomaly_list,
        }
        sys.stdout.write(json.dumps(result) + "\n")

    return anomaly_list


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


def cmd_decay(stale_days: int = 14, prune_days: int = 30,
              dry_run: bool = False, environment: str | None = None) -> None:
    """Age out baseline entries that haven't been seen recently.

    Entries last seen more than `stale_days` days ago have their occurrence
    count halved (confidence decay) so they drift toward the promotion
    threshold and eventually fall below it during the next learn run.

    Entries last seen more than `prune_days` days ago are removed outright,
    unless they are auto_promoted (manually accepted), which are never pruned
    by decay — only by an explicit learn --reset.

    Intended to be run periodically (e.g. weekly via cron) to keep the
    baseline fresh as the application evolves.
    """
    baseline = load_baseline(environment)
    fps = baseline.get("fingerprints", {})
    if not fps:
        print("Baseline is empty — nothing to decay.")
        return

    now = datetime.now(timezone.utc)
    decayed: list[str] = []
    pruned:  list[str] = []

    for h, info in list(fps.items()):
        if info.get("auto_promoted"):
            continue  # never auto-decay manually promoted entries

        last_seen_str = info.get("last_seen") or info.get("promoted_at") or info.get("first_seen")
        if not last_seen_str:
            continue
        try:
            last_seen_dt = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

        age_days = (now - last_seen_dt).days

        if age_days >= prune_days:
            pruned.append(h)
            if not dry_run:
                del fps[h]
            print(f"  {'[dry-run] ' if dry_run else ''}PRUNE  {info['root_op']}  [{h[:12]}]"
                  f"  last_seen={age_days}d ago  occ={info.get('occurrences',1)}")
        elif age_days >= stale_days:
            decayed.append(h)
            if not dry_run:
                old_occ = info.get("occurrences", 1)
                fps[h]["occurrences"] = max(1, old_occ // 2)
            print(f"  {'[dry-run] ' if dry_run else ''}DECAY  {info['root_op']}  [{h[:12]}]"
                  f"  last_seen={age_days}d ago  occ={info.get('occurrences',1)}"
                  f"  -> {max(1, info.get('occurrences',1) // 2)}")

    print(f"\n  Decay run: {len(decayed)} decayed, {len(pruned)} pruned"
          f"{' (dry-run — no changes saved)' if dry_run else ''}")

    if not dry_run and (decayed or pruned):
        save_baseline(baseline, environment)


def cmd_overrides(action: str, root_op: str | None = None,
                  flag: str | None = None, value: str | None = None,
                  reason: str | None = None,
                  environment: str | None = None) -> None:
    """
    Manage persistent baseline overrides.

    Overrides are stored in data/baseline_overrides.<env>.json and survive
    every `learn --reset` and `--bootstrap` cycle. They are automatically
    merged back into fingerprint entries by `learn`.

    Usage:
      overrides --list
      overrides --set "api-gateway:GET" no_missing_service true "discovery-server is optional infra"
      overrides --clear "api-gateway:GET"
    """
    overrides = load_overrides(environment)
    root_op_flags = overrides.setdefault("root_op_flags", {})

    if action == "list":
        if not root_op_flags:
            print("  No overrides set.")
            return
        print(f"  Overrides ({_overrides_path(environment)}):")
        for op, flags in sorted(root_op_flags.items()):
            reason_str = f"  # {flags['reason']}" if flags.get("reason") else ""
            flag_strs = ", ".join(f"{k}={v}" for k, v in flags.items() if k != "reason")
            print(f"    {op!r}: {flag_strs}{reason_str}")
        return

    if action == "set":
        if not root_op or not flag or value is None:
            print("Error: --set requires root_op, flag, and value", file=sys.stderr)
            sys.exit(1)
        # Parse value: "true"/"false" → bool, else keep as string
        parsed_value: bool | str
        if value.lower() == "true":
            parsed_value = True
        elif value.lower() == "false":
            parsed_value = False
        else:
            parsed_value = value
        entry = root_op_flags.setdefault(root_op, {})
        entry[flag] = parsed_value
        if reason:
            entry["reason"] = reason
        save_overrides(overrides, environment)
        print(f"  Set override: {root_op!r} -> {flag}={parsed_value}"
              + (f" ({reason})" if reason else ""))
        print("  Run 'learn' to apply to current baseline, or push baseline manually.")
        return

    if action == "clear":
        if not root_op:
            print("Error: --clear requires root_op", file=sys.stderr)
            sys.exit(1)
        had_override = root_op in root_op_flags
        if had_override:
            del root_op_flags[root_op]
            save_overrides(overrides, environment)
            print(f"  Cleared override for {root_op!r}")
        else:
            print(f"  No override found for {root_op!r}")

        # The override-merge step (apply_overrides) bakes no_missing_service/
        # exempt_services directly onto matching fingerprint entries in the
        # baseline file, and clearing the override alone doesn't retroactively
        # strip that — so a cleared override would otherwise keep suppressing
        # MISSING_SERVICE forever via the stale baked-in flags. Strip them here.
        baseline = load_baseline(environment)
        cleared_entries = 0
        for fp in baseline.get("fingerprints", {}).values():
            if fp.get("root_op") != root_op:
                continue
            for stale_flag in ("no_missing_service", "exempt_services", "reason"):
                if stale_flag in fp:
                    del fp[stale_flag]
                    cleared_entries += 1
        if cleared_entries:
            save_baseline(baseline, environment)
            print(f"  Stripped stale flags from baseline entries for {root_op!r}")
        return


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
    p_learn.add_argument("--window-offset-minutes", type=int, default=0,
                         help="Shift the learn window back by N minutes (useful for re-baselining after an incident)")
    p_learn.add_argument("--reset", action="store_true",
                         help="Wipe the existing baseline before learning (start fresh)")
    p_learn.add_argument("--bootstrap", action="store_true",
                         help="Cold-start mode: accept every fingerprint seen ≥ 1 time. "
                              "Use on a freshly deployed cluster (implies --reset). "
                              "Run once, then switch to regular learn for ongoing updates.")
    p_watch = sub.add_parser("watch", help="Compare recent traces to baseline")
    p_watch.add_argument("--window-minutes", type=int, default=10)
    p_watch.add_argument("--json", action="store_true",
                         help="Output anomalies as JSON to stdout (for piping to agent.py)")
    sub.add_parser("show", help="Print current baseline")
    p_promote = sub.add_parser(
        "promote",
        help="Manually promote fingerprint(s) to baseline (stops alerting on them)",
    )
    p_promote.add_argument(
        "hashes", nargs="*",
        help="Fingerprint hash(es) to promote. Omit to promote all pending.",
    )
    p_overrides = sub.add_parser(
        "overrides",
        help="Manage persistent per-root_op flag overrides (survive learn --reset)",
    )
    _ov_group = p_overrides.add_mutually_exclusive_group(required=True)
    _ov_group.add_argument("--list", dest="ov_action", action="store_const",
                           const="list", help="List current overrides")
    _ov_group.add_argument("--set", dest="ov_action", action="store_const",
                           const="set", help="Set a flag override")
    _ov_group.add_argument("--clear", dest="ov_action", action="store_const",
                           const="clear", help="Clear all overrides for a root_op")
    p_overrides.add_argument("root_op", nargs="?", default=None,
                             help="root_op string (e.g. 'api-gateway:GET')")
    p_overrides.add_argument("flag", nargs="?", default=None,
                             help="Flag name (e.g. no_missing_service)")
    p_overrides.add_argument("value", nargs="?", default=None,
                             help="Flag value: true or false")
    p_overrides.add_argument("reason", nargs="?", default=None,
                             help="Optional explanation (stored as metadata)")

    p_decay = sub.add_parser(
        "decay",
        help="Age out stale baseline entries (run weekly to keep baseline fresh)",
    )
    p_decay.add_argument("--stale-days", type=int, default=14,
                         help="Entries not seen in this many days have occurrences halved (default: 14)")
    p_decay.add_argument("--prune-days", type=int, default=30,
                         help="Entries not seen in this many days are removed (default: 30)")
    p_decay.add_argument("--dry-run", action="store_true",
                         help="Print what would change without saving")

    args = parser.parse_args()
    env = args.environment

    if args.command == "discover":
        cmd_discover(environment=env)
    elif args.command == "learn":
        cmd_learn(args.window_minutes, args.window_offset_minutes, args.reset,
                  args.bootstrap, environment=env)
    elif args.command == "watch":
        cmd_watch(args.window_minutes, environment=env, json_output=args.json)
    elif args.command == "show":
        cmd_show(environment=env)
    elif args.command == "promote":
        cmd_promote(args.hashes or None, environment=env)
    elif args.command == "overrides":
        cmd_overrides(args.ov_action, args.root_op, args.flag, args.value,
                      args.reason, environment=env)
    elif args.command == "decay":
        cmd_decay(args.stale_days, args.prune_days, args.dry_run, environment=env)


if __name__ == "__main__":
    main()
