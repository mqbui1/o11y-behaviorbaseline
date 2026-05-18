#!/usr/bin/env python3
"""Topology server — serves live service dependency graph + SSE drift event stream.

Usage:
    python3 demo/topology_server.py --environment $ENV
    # Open http://localhost:8080 in browser

Requires: pip install fastapi uvicorn
"""
import argparse
import asyncio
import json
import os
import random
import re
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import AsyncGenerator

_REPO = Path(__file__).parent.parent

# Load .env
_env_file = _REPO / ".env"
if _env_file.exists():
    for line in _env_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

EC2_IP   = os.environ.get("EC2_IP", "")
EC2_PORT = os.environ.get("EC2_PORT", "2222")
EC2_PASS = os.environ.get("EC2_PASS", os.environ.get("EC2_PASSWORD", ""))
DAEMONSET_LABEL = os.environ.get("OTEL_POD_LABEL", "app=otelcol-fingerprint")
OTEL_CONTAINER  = os.environ.get("OTEL_CONTAINER", "otelcol")
_DATA_DIR = _REPO / "data"
_ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
_REALM        = os.environ.get("SPLUNK_REALM", "us1")

# ── Metrics cache (populated by _poll_processor_metrics background task) ──────
# Stores the last successful JSON response from GET /metrics on the aggregator.
_metrics_cache: dict = {}
_metrics_cache_ts: float = 0.0
_METRICS_POLL_INTERVAL = 15   # seconds between polls
_METRICS_PORT = 9090          # must match MetricsAddr in aggregator config

# ── APM liveness cache ────────────────────────────────────────────────────
# env -> True/False/None (None = not yet checked)
_env_liveness: dict[str, bool | None] = {}
_LIVENESS_CHECK_INTERVAL = 60   # seconds between rechecks
_LIVENESS_WINDOW_SECONDS = 300  # 5-minute window to detect recent traffic


def _check_env_liveness(env: str) -> bool:
    """Return True if APM topology has nodes for env in the last 5 minutes."""
    if not _ACCESS_TOKEN:
        return True  # can't check — assume live
    import urllib.request
    import urllib.error
    now = time.gmtime()
    then = time.gmtime(time.time() - _LIVENESS_WINDOW_SECONDS)
    fmt = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", t)
    body = json.dumps({
        "timeRange": f"{fmt(then)}/{fmt(now)}",
        "tagFilters": [{"name": "sf_environment", "operator": "equals",
                        "value": env, "scope": "global"}],
    }).encode()
    url = f"https://api.{_REALM}.signalfx.com/v2/apm/topology"
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"X-SF-Token": _ACCESS_TOKEN,
                                          "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            result = json.loads(r.read())
        nodes = (result.get("data") or {}).get("nodes", [])
        return len(nodes) > 0
    except Exception:
        return False  # treat errors as not live


def _refresh_liveness_cache() -> None:
    from concurrent.futures import ThreadPoolExecutor
    envs = _list_environments()
    with ThreadPoolExecutor(max_workers=min(len(envs), 6)) as ex:
        results = ex.map(_check_env_liveness, envs)
    for env, live in zip(envs, results):
        _env_liveness[env] = live

# ── Regex (shared with poll_drift_events.py) ──────────────────────────────────
drift_re   = re.compile(r'(trace drift detected|new trace fingerprint \(unknown root op\)|new error signature detected|missing service detected|latency anomaly detected|error rate anomaly detected)')
hash_re    = re.compile(r'"hash": "([^"]+)"')
op_re      = re.compile(r'"root_op": "([^"]+)"')
svc_re     = re.compile(r'"service": "([^"]+)"')
path_re    = re.compile(r'"path": "([^"]+)"')
tid_re     = re.compile(r'"trace_id": "([^"]+)"')
etype_re   = re.compile(r'"error_type": "([^"]+)"')
op2_re     = re.compile(r'"operation": "([^"]+)"')
missing_re = re.compile(r'"missing_services": \[([^\]]*)\]')
cur_ms_re  = re.compile(r'"current_mean_ms": "([^"]+)"')
base_ms_re = re.compile(r'"baseline_mean_ms": "([^"]+)"')
zscore_re  = re.compile(r'"z_score": "([^"]+)"')
erate_re   = re.compile(r'"error_pct": "([^"]+)"')
ecnt_re    = re.compile(r'"error_count": (\d+)')
tcnt_re    = re.compile(r'"total_count": (\d+)')
spm_re     = re.compile(r'"spans_per_min": "([^"]+)"')

_INFRA = {"discovery-server", "config-server", "eureka-server", "eureka", "admin-server"}
# DB_SPAN_PATTERNS: span operation prefixes that indicate a DB call.
# Used to inject a synthetic mysql:petclinic node into the topology.
_DB_SPAN_PATTERNS = ("SELECT", "INSERT", "UPDATE", "DELETE", "Transaction.commit")

# ── In-memory state ───────────────────────────────────────────────────────────
# Active anomalies: service -> list of anomaly dicts (cleared after ANOMALY_TTL)
_active_anomalies: dict[str, list[dict]] = defaultdict(list)
ANOMALY_TTL       = 300  # seconds — hard expiry
RECOVERY_QUIET    = 45   # seconds of no new drift events before declaring recovery
RECOVERY_LOCKOUT  = 30   # seconds after recovery to ignore new events (absorb pod log replay)

# SSE subscriber queues
_subscribers: list[asyncio.Queue] = []

# Tracks the last time any drift event arrived — used by recovery detector
_last_drift_time: float = 0.0
# Tracks when recovery was last declared — events during lockout window are ignored
_recovery_time: float = 0.0

# Topology + baseline cache
_topology_cache: dict = {}
_baseline_cache: dict = {}
# New nodes/edges discovered via drift events (not in baseline)
_new_nodes: dict[str, dict] = {}   # id -> {id, label}
_new_edges: list[dict] = []        # [{source, target, label}]

# Infra events: recent pod-level events from kubectl (OOMKill, BackOff, etc.)
# service -> list of {reason, message, count, timestamp_ms}
_infra_events: dict[str, list[dict]] = defaultdict(list)
INFRA_EVENT_TTL = 300  # seconds

# ── Problem records ────────────────────────────────────────────────────────────
# Keyed by problem_id (e.g. "P-1746123456").  Each record:
#   id, opened_ms, closed_ms|None, root_cause, services, events[]
_problems: dict[str, dict] = {}
_current_problem_id: str | None = None  # open problem, if any


def _next_problem_id() -> str:
    """Generate a short, human-readable problem ID."""
    suffix = "".join(random.choices("ABCDEFGHJKLMNPQRSTUVWXYZ23456789", k=4))
    return f"P-{suffix}"


def _open_problem(root_cause: str, services: list[str], event: dict) -> str:
    """Open a new problem record and return its ID."""
    global _current_problem_id
    pid = _next_problem_id()
    _problems[pid] = {
        "id":         pid,
        "opened_ms":  event["timestamp_ms"],
        "closed_ms":  None,
        "root_cause": root_cause,
        "services":   list(services),
        "events":     [event],
    }
    _current_problem_id = pid
    return pid


def _update_problem(pid: str, root_cause: str, services: list[str], event: dict) -> None:
    """Merge new info into an open problem."""
    p = _problems[pid]
    p["root_cause"] = root_cause
    p["events"].append(event)
    for svc in services:
        if svc not in p["services"]:
            p["services"].append(svc)


def _close_problem(pid: str, closed_ms: int) -> None:
    global _current_problem_id
    if pid in _problems:
        _problems[pid]["closed_ms"] = closed_ms
    if _current_problem_id == pid:
        _current_problem_id = None


# ── Baseline / topology helpers ───────────────────────────────────────────────

def _load_baseline(environment: str) -> dict:
    """Load OTel baseline fingerprints, prefer /tmp/otel_baseline.json on EC2 fallback."""
    # Try local data dir first
    local = _DATA_DIR / f"baseline.{environment}.json"
    if local.exists():
        try:
            b = json.loads(local.read_text())
            return b.get("fingerprints", {})
        except Exception:
            pass
    return {}


def _build_topology_from_baseline(fingerprints: dict) -> dict:
    """
    Build a directed service graph from baseline fingerprints.
    Returns {
      nodes:      [{"id": svc, "traffic": N}, ...],
      edges:      [{"source": a, "target": b, "weight": N}, ...],
      upstream:   {svc: [callers]},
      downstream: {svc: [callees]},
    }
    """
    edge_weights: dict[tuple, int] = defaultdict(int)
    node_traffic: dict[str, int]   = defaultdict(int)

    # Only inject synthetic mysql:petclinic node for PetClinic environments
    all_svcs_in_baseline = {
        p.split(":")[0] for fp in fingerprints.values()
        for p in fp.get("path", "").split("->") if p.strip()
    }
    is_petclinic_env = bool(all_svcs_in_baseline & _APP_GROUPS["petclinic"])

    for fp in fingerprints.values():
        path  = fp.get("path", "")
        occ   = fp.get("occurrences", 1)
        parts = [p.strip() for p in path.split("->")]
        svcs  = []
        last_app_svc = None  # track last non-DB service to wire DB edge
        for p in parts:
            op  = p.split(":", 1)[1].strip() if ":" in p else p
            svc = p.split(":")[0] if ":" in p else p
            # Only inject mysql:petclinic synthetic node for PetClinic environments
            if is_petclinic_env and any(op.startswith(pat) for pat in _DB_SPAN_PATTERNS):
                db_node = "mysql:petclinic"
                if last_app_svc and last_app_svc != db_node:
                    edge_weights[(last_app_svc, db_node)] += occ
                    node_traffic[db_node] += occ
                continue
            if not svcs or svcs[-1] != svc:
                svcs.append(svc)
            last_app_svc = svc
        for svc in svcs:
            node_traffic[svc] += occ
        # Only add forward edges — skip any edge whose target appeared earlier in the
        # path.  APM fan-out paths (api-gateway → customers-service → api-gateway →
        # visits-service) otherwise create cycles that corrupt root-cause traversal.
        seen_svcs: set[str] = set()
        for i in range(len(svcs) - 1):
            seen_svcs.add(svcs[i])
            if svcs[i + 1] not in seen_svcs:
                edge_weights[(svcs[i], svcs[i + 1])] += occ

    upstream:   dict[str, list[str]] = defaultdict(list)
    downstream: dict[str, list[str]] = defaultdict(list)
    for (src, dst) in edge_weights:
        downstream[src].append(dst)
        upstream[dst].append(src)

    def _valid(svc: str) -> bool:
        return svc not in _INFRA and bool(svc) and not svc.strip(".").strip() == ""

    nodes = [{"id": svc, "traffic": traffic}
             for svc, traffic in sorted(node_traffic.items(), key=lambda x: -x[1])
             if _valid(svc)]
    edges = [{"source": src, "target": dst, "weight": w}
             for (src, dst), w in sorted(edge_weights.items(), key=lambda x: -x[1])
             if _valid(src) and _valid(dst)]

    # Inject synthetic Kafka-mediated edges for astronomy shop.
    # fraud-detection and accounting are Kafka consumers — they have no upstream
    # service in their trace because Kafka sits between producer and consumer.
    # Wire: checkout -> kafka -> fraud-detection, checkout -> kafka -> accounting
    node_ids = {n["id"] for n in nodes}
    _KAFKA_EDGES = [
        ("checkout", "kafka"),
        ("kafka", "fraud-detection"),
        ("kafka", "accounting"),
    ]
    for src, dst in _KAFKA_EDGES:
        if src in node_ids or dst in node_ids:
            if src not in node_ids:
                nodes.append({"id": src, "traffic": 0})
                node_ids.add(src)
            if dst not in node_ids:
                nodes.append({"id": dst, "traffic": 0})
                node_ids.add(dst)
            edge_key = (src, dst)
            if not any(e["source"] == src and e["target"] == dst for e in edges):
                edges.append({"source": src, "target": dst, "weight": 1})
                edge_weights[edge_key] = 1
                downstream[src].append(dst)
                upstream[dst].append(src)

    return {
        "nodes":      nodes,
        "edges":      edges,
        "upstream":   dict(upstream),
        "downstream": dict(downstream),
    }


def _load_topology_json(environment: str) -> dict:
    """
    Load topology.json written by the OTel fingerprintprocessor.
    Returns edges as {caller->callee: {caller, callee, first_seen, count}}.
    Falls back to {} if file doesn't exist.
    """
    path = _DATA_DIR / f"topology.{environment}.json"
    if not path.exists():
        # Also check the generic topology.json (written by the processor to /baseline/)
        path = _DATA_DIR / "topology.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data.get("edges", {})
    except Exception:
        return {}


def _topology_edges_to_graph(edges: dict, baseline_topo: dict) -> dict:
    """
    Merge OTel-discovered edges into a topology dict.
    Returns {added_nodes, added_edges} relative to baseline_topo.
    """
    existing_ids  = {n["id"] for n in baseline_topo.get("nodes", [])}
    existing_keys = {f"{e['source']}->{e['target']}" for e in baseline_topo.get("edges", [])}

    added_nodes: list[dict] = []
    added_edges: list[dict] = []
    seen_new_ids: set[str]  = set()

    for key, edge in edges.items():
        caller = edge.get("caller", "")
        callee = edge.get("callee", "")
        if not caller or not callee:
            continue
        if caller in _INFRA or callee in _INFRA:
            continue
        if key not in existing_keys:
            added_edges.append({"source": caller, "target": callee, "weight": edge.get("count", 1)})
        for svc in (caller, callee):
            if svc not in existing_ids and svc not in seen_new_ids:
                added_nodes.append({"id": svc, "traffic": 0})
                seen_new_ids.add(svc)

    return {"added_nodes": added_nodes, "added_edges": added_edges}


# Anomaly type weights for confidence scoring (higher = stronger root cause signal)
_ANOMALY_WEIGHTS = {
    "MISSING_SERVICE":    1.0,
    "ERROR_RATE_ANOMALY": 0.85,
    "NEW_ERROR_SIGNATURE":0.7,
    "SPAN_COUNT_DROP":    0.65,
    "LATENCY_ANOMALY":    0.5,
    "SPAN_COUNT_SPIKE":   0.45,
    "NEW_FINGERPRINT":    0.3,
}


def _score_candidate(svc: str, active: dict, upstream: dict, downstream: dict,
                     affected: set, first_seen: dict) -> float:
    """
    Compute a confidence score [0, 1] for a root cause candidate.

    Factors:
      - anomaly_weight: type of anomaly (MISSING > ERROR_RATE > ERROR_SIG > LATENCY > DRIFT)
      - caller_fraction: fraction of total affected services that call this node
      - depth_bonus: leaf nodes (no affected downstream) score higher
      - timing_bonus: node that fired earliest gets a small bonus
    """
    anoms = active.get(svc, [])
    if not anoms:
        return 0.0

    # Highest-weight anomaly type on this node
    type_weight = max((_ANOMALY_WEIGHTS.get(a.get("anomaly_type", ""), 0.1)
                       for a in anoms), default=0.1)

    # Fraction of affected services that call THIS node (shared dep = more likely cause)
    callers = upstream.get(svc, [])
    callers_affected = sum(1 for c in callers if c in affected)
    total_affected = max(len(affected) - 1, 1)  # exclude self
    caller_fraction = callers_affected / total_affected

    # Fraction of affected services that THIS node calls (upstream orchestrator pattern)
    # An upstream service that triggered N downstream anomalies is also a strong candidate.
    callees = downstream.get(svc, [])
    callees_affected = sum(1 for c in callees if c in affected)
    callee_fraction = callees_affected / total_affected

    # Timing: earliest anomaly timestamp gets up to 0.1 bonus
    earliest_ts = min((a.get("timestamp_ms", 0) for a in anoms), default=0)
    all_ts = [a.get("timestamp_ms", 0)
              for anoms_list in active.values()
              for a in anoms_list if a.get("timestamp_ms", 0)]
    if all_ts:
        min_ts, max_ts = min(all_ts), max(all_ts)
        span = max_ts - min_ts or 1
        timing_bonus = 0.1 * (1.0 - (earliest_ts - min_ts) / span)
    else:
        timing_bonus = 0.0

    # MISSING_SERVICE is a strong structural signal — the service vanished.
    has_only_missing = all(a.get("anomaly_type") == "MISSING_SERVICE" for a in anoms)
    missing_bonus = 0.3 if has_only_missing else 0.0

    # Suppress topology fraction when there's a cycle between affected nodes
    # (e.g. checkout ↔ payment orchestrator pattern) — it produces false caller boosts.
    callers = set(upstream.get(svc, []))
    callees = set(downstream.get(svc, []))
    has_cycle_with_affected = any(
        c in affected and svc in (upstream.get(c, []) or [])
        for c in callees if c in affected
    )
    topo_fraction = 0.0 if has_cycle_with_affected else max(caller_fraction, callee_fraction)

    score = (type_weight * 0.6) + (topo_fraction * 0.25) + (timing_bonus * 0.1) + missing_bonus
    return min(score, 1.0)


def _find_root_cause(topology: dict,
                     active: dict[str, list[dict]]) -> tuple[list[str], dict[str, float]]:
    """
    Traverse the dependency graph to find root cause across all affected services.

    Returns:
      chain      — [root_cause, intermediate..., most_upstream_affected]
      confidence — {svc: score} for all candidates (0.0–1.0)

    Algorithm:
      - Start from all services with active anomalies
      - Walk downstream to find deepest affected nodes (root cause candidates)
      - Score each candidate probabilistically (type weight + caller fraction + timing)
      - Build chain from highest-scoring root cause upward
    """
    downstream = topology.get("downstream", {})
    upstream   = topology.get("upstream", {})
    affected   = {s for s, v in active.items() if v}

    if not affected:
        return [], {}

    def _find_deepest(svc: str, visited: set) -> str:
        if svc in visited:
            return svc
        visited.add(svc)
        for dep in downstream.get(svc, []):
            if dep in _INFRA:
                continue
            if dep in affected:
                return _find_deepest(dep, visited)
        return svc

    # Collect all first-seen timestamps per service
    first_seen: dict[str, int] = {
        svc: min((a.get("timestamp_ms", 0) for a in anoms), default=0)
        for svc, anoms in active.items() if anoms
    }

    # Find candidates (deepest reachable affected node from each affected service)
    candidate_svcs: set[str] = set()
    for svc in affected:
        candidate_svcs.add(_find_deepest(svc, set()))

    # Always include MISSING_SERVICE nodes as direct candidates — _find_deepest may
    # skip them when they call deeper affected nodes (e.g. checkout→payment cycle).
    for svc in affected:
        if any(a.get("anomaly_type") == "MISSING_SERVICE" for a in active.get(svc, [])):
            candidate_svcs.add(svc)

    # mysql:petclinic as candidate if multiple affected callers
    if "mysql:petclinic" in affected:
        callers_hit = sum(1 for svc in affected
                         if "mysql:petclinic" in downstream.get(svc, []))
        if callers_hit > 1:
            candidate_svcs.add("mysql:petclinic")

    # Timing override: if an upstream node fired significantly before ALL its
    # affected downstream nodes, it is more likely the root cause (the gateway
    # itself is slow, not its dependencies).  Add it as a candidate.
    # Threshold: upstream must predate every downstream by ≥5s.
    for svc in list(affected):
        svc_ts = first_seen.get(svc, 0)
        if not svc_ts:
            continue
        deps_affected = [d for d in downstream.get(svc, []) if d in affected]
        if not deps_affected:
            continue  # already a leaf — already a candidate
        all_deps_later = all(
            first_seen.get(d, svc_ts) >= svc_ts + 5_000
            for d in deps_affected
        )
        if all_deps_later:
            candidate_svcs.add(svc)

    # Score each candidate
    confidence: dict[str, float] = {
        svc: _score_candidate(svc, active, upstream, downstream, affected, first_seen)
        for svc in candidate_svcs
    }

    root_cause = max(candidate_svcs, key=lambda s: confidence.get(s, 0))

    # Build chain: root_cause → services that call it → their callers
    chain = [root_cause]
    visited_chain: set[str] = {root_cause}
    frontier = [c for c in upstream.get(root_cause, [])
                if c in affected and c not in visited_chain]
    while frontier:
        next_layer = []
        for svc in frontier:
            if svc not in visited_chain:
                chain.append(svc)
                visited_chain.add(svc)
                next_layer += [c for c in upstream.get(svc, [])
                               if c in affected and c not in visited_chain]
        frontier = next_layer

    return chain, confidence


def _downstream_suppressed(svc: str, root_cause: str, topology: dict,
                            active: dict) -> bool:
    """
    Return True if svc is purely a downstream effect of root_cause.
    Used to visually demote secondary services in the panel (#5 downstream suppression).

    A service is suppressed when:
      - It IS NOT the root cause
      - It has ONLY DRIFT/LATENCY anomalies (not ERROR/MISSING which are independent signals)
      - root_cause is reachable from svc via upstream links (i.e. svc calls root_cause)
    """
    if svc == root_cause:
        return False
    anoms = active.get(svc, [])
    independent = {"NEW_ERROR_SIGNATURE", "MISSING_SERVICE", "ERROR_RATE_ANOMALY"}
    if any(a.get("anomaly_type") in independent for a in anoms):
        return False
    # Check if root_cause is downstream of svc (svc → ... → root_cause)
    downstream = topology.get("downstream", {})
    visited: set[str] = set()
    frontier = list(downstream.get(svc, []))
    while frontier:
        node = frontier.pop()
        if node == root_cause:
            return True
        if node in visited:
            continue
        visited.add(node)
        frontier.extend(downstream.get(node, []))
    return False


# ── Event parsing (mirrors poll_drift_events.py) ──────────────────────────────

def _parse_event(line: str) -> dict | None:
    if not drift_re.search(line):
        return None
    is_error   = "error signature" in line
    is_missing = "missing service" in line
    h    = hash_re.search(line)
    op   = op_re.search(line)
    svc  = svc_re.search(line)
    et   = etype_re.search(line)
    op2  = op2_re.search(line)
    miss = missing_re.search(line)

    h_val   = h.group(1)   if h   else ""
    op_val  = op.group(1)  if op  else ""
    svc_val = svc.group(1) if svc else (op_val.split(":")[0] if ":" in op_val else op_val)

    is_latency    = "latency anomaly detected" in line
    is_error_rate = "error rate anomaly detected" in line

    if is_latency:
        op2  = op2_re.search(line)
        cur  = cur_ms_re.search(line)
        base = base_ms_re.search(line)
        zs   = zscore_re.search(line)
        spm  = spm_re.search(line)
        cur_ms       = cur.group(1)  if cur  else "?"
        base_ms      = base.group(1) if base else "?"
        z_score      = zs.group(1)   if zs   else "?"
        op2_val      = op2.group(1)  if op2  else ""
        spans_per_min = spm.group(1) if spm  else None
        return {
            "anomaly_type":      "LATENCY_ANOMALY",
            "service":           svc_val,
            "operation":         op2_val,
            "current_mean_ms":   cur_ms,
            "baseline_mean_ms":  base_ms,
            "z_score":           z_score,
            "spans_per_min":     spans_per_min,
            "message":           f"Latency spike: {svc_val} {cur_ms}ms (baseline {base_ms}ms, z={z_score})",
            "hash":              f"latency:{svc_val}:{op2_val}",
            "timestamp_ms":      int(time.time() * 1000),
        }
    elif is_error_rate:
        op2  = op2_re.search(line)
        er   = erate_re.search(line)
        ec   = ecnt_re.search(line)
        tc   = tcnt_re.search(line)
        spm  = spm_re.search(line)
        op2_val       = op2.group(1) if op2 else ""
        err_pct       = er.group(1)  if er  else "?"
        err_cnt       = int(ec.group(1)) if ec else 0
        tot_cnt       = int(tc.group(1)) if tc else 0
        spans_per_min = spm.group(1) if spm else None
        return {
            "anomaly_type": "ERROR_RATE_ANOMALY",
            "service":      svc_val,
            "operation":    op2_val,
            "error_pct":    err_pct,
            "error_count":  err_cnt,
            "total_count":  tot_cnt,
            "spans_per_min": spans_per_min,
            "message":      f"Error rate spike: {svc_val} {err_pct} ({err_cnt}/{tot_cnt} spans)",
            "hash":         f"errorrate:{svc_val}:{op2_val}",
            "timestamp_ms": int(time.time() * 1000),
        }
    elif is_missing:
        missing_svcs: list[str] = []
        if miss:
            missing_svcs = [s.strip().strip('"') for s in miss.group(1).split(",") if s.strip().strip('"')]
        leaf_svc = missing_svcs[-1] if missing_svcs else svc_val
        return {
            "anomaly_type":     "MISSING_SERVICE",
            "service":          leaf_svc,
            "root_op":          op_val,
            "missing_services": missing_svcs,
            "message":          f"MISSING_SERVICE: {', '.join(missing_svcs)} absent from traces",
            "hash":             h_val or f"missing:{op_val}",
            "timestamp_ms":     int(time.time() * 1000),
        }
    elif is_error:
        et_val  = et.group(1)  if et  else ""
        op2_val = op2.group(1) if op2 else ""
        return {
            "anomaly_type": "NEW_ERROR_SIGNATURE",
            "service":      svc_val,
            "message":      f"New error: {et_val} on {op2_val}",
            "error_type":   et_val,
            "operation":    op2_val,
            "hash":         h_val,
            "timestamp_ms": int(time.time() * 1000),
        }
    else:
        return {
            "anomaly_type": "NEW_FINGERPRINT",
            "service":      svc_val,
            "root_op":      op_val,
            "message":      f"Trace path drift on '{op_val}'",
            "hash":         h_val,
            "new_edges":    [],   # populated by caller if new node/edge is known
            "timestamp_ms": int(time.time() * 1000),
        }


# ── SSH log tail / topology polling (background tasks) ───────────────────────
# Dynamic versions that read environment from a mutable state dict are defined
# after the helper functions above (_tail_otel_logs_dynamic, _tail_topology_events_dynamic).


def _merge_topology_edges(added_nodes: list[dict], added_edges: list[dict]) -> None:
    """Merge newly discovered nodes/edges into _topology_cache in-place."""
    global _topology_cache
    existing_ids  = {n["id"] for n in _topology_cache.get("nodes", [])}
    existing_keys = {f"{e['source']}->{e['target']}" for e in _topology_cache.get("edges", [])}
    for n in added_nodes:
        if n["id"] not in existing_ids:
            _topology_cache["nodes"].append(n)
            existing_ids.add(n["id"])
    for e in added_edges:
        key = f"{e['source']}->{e['target']}"
        if key not in existing_keys:
            _topology_cache["edges"].append(e)
    # Rebuild upstream/downstream
    up: dict[str, list] = {}
    dn: dict[str, list] = {}
    for e in _topology_cache.get("edges", []):
        s, d = e["source"], e["target"]
        dn.setdefault(s, [])
        up.setdefault(d, [])
        if d not in dn[s]:
            dn[s].append(d)
        if s not in up[d]:
            up[d].append(s)
    _topology_cache["upstream"]   = up
    _topology_cache["downstream"] = dn


def _broadcast_topology_update(added_nodes: list[dict], added_edges: list[dict]) -> None:
    payload = {
        "type":        "topology_update",
        "nodes":       _topology_cache.get("nodes", []),
        "edges":       _topology_cache.get("edges", []),
        "added_nodes": added_nodes,
        "added_edges": added_edges,
    }
    dead = []
    for q in _subscribers:
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        _subscribers.remove(q)


async def _poll_infra_events() -> None:
    """Background task: poll kubectl warning events every 30s and correlate
    with active anomalies by matching pod names to service names.

    Looks for: OOMKilling, BackOff, Failed, Unhealthy, CrashLoopBackOff.
    Stores results in _infra_events for inclusion in SSE payloads.
    """
    POLL_INTERVAL = 30
    # kubectl event reasons we care about
    WARN_REASONS = {"OOMKilling", "BackOff", "Failed", "Unhealthy",
                    "CrashLoopBackOff", "FailedMount", "Evicted", "Killing"}

    while True:
        await asyncio.sleep(POLL_INTERVAL)
        if not EC2_IP or not EC2_PASS:
            continue
        try:
            ssh_cmd = (
                "exec bash -c '"
                "kubectl get events --field-selector type=Warning "
                "--sort-by=.lastTimestamp -o json 2>/dev/null'"
            )
            proc = await asyncio.create_subprocess_exec(
                "sshpass", f"-p{EC2_PASS}",
                "ssh", "-T", "-p", EC2_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "RequestTTY=no",
                f"splunk@{EC2_IP}",
                ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
            raw = stdout.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            data = json.loads(raw)
            items = data.get("items", [])
            now_ms = int(time.time() * 1000)
            cutoff_ms = now_ms - INFRA_EVENT_TTL * 1000

            new_infra: dict[str, list[dict]] = defaultdict(list)
            for item in items:
                reason = item.get("reason", "")
                if reason not in WARN_REASONS:
                    continue
                # Derive service name from involved object name
                # e.g. "visits-service-6d8f9c-abc" → "visits-service"
                obj_name = (item.get("involvedObject") or {}).get("name", "")
                svc = _pod_name_to_service(obj_name)
                if not svc or svc in _INFRA:
                    continue
                # Parse timestamp
                ts_str = (item.get("lastTimestamp") or item.get("eventTime") or "")
                try:
                    import datetime
                    ts_ms = int(datetime.datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00")).timestamp() * 1000)
                except Exception:
                    ts_ms = now_ms
                if ts_ms < cutoff_ms:
                    continue
                msg = item.get("message", "")
                count = item.get("count", 1)
                new_infra[svc].append({
                    "reason":       reason,
                    "message":      msg[:120],
                    "count":        count,
                    "timestamp_ms": ts_ms,
                    "object":       obj_name,
                })

            global _infra_events
            _infra_events = new_infra

            if new_infra:
                # Broadcast infra update so UI can decorate nodes
                affected_svcs = list(new_infra.keys())
                payload = {
                    "type":         "infra_events",
                    "infra_events": dict(new_infra),
                    "affected":     affected_svcs,
                    "timestamp_ms": now_ms,
                }
                dead = []
                for q in _subscribers:
                    try:
                        q.put_nowait(payload)
                    except asyncio.QueueFull:
                        dead.append(q)
                for q in dead:
                    _subscribers.remove(q)

        except asyncio.TimeoutError:
            print("[topology] infra poll timed out", flush=True)
        except Exception as e:
            print(f"[topology] infra poll error: {e}", flush=True)


def _pod_name_to_service(pod_name: str) -> str:
    """Strip pod hash suffixes to derive the service/deployment name.

    e.g. visits-service-6d8f9c-xkz9p → visits-service
         mysql-0 → mysql:petclinic (special case)
    """
    if not pod_name:
        return ""
    if "mysql" in pod_name or "petclinic-db" in pod_name:
        return "mysql:petclinic"
    # Strip up to two trailing hash segments (ReplicaSet hash + pod hash)
    parts = pod_name.rsplit("-", 2)
    if len(parts) == 3:
        return parts[0]
    if len(parts) == 2:
        return parts[0]
    return pod_name


async def _expire_anomalies() -> None:
    """Background task: recovery detection + hard TTL expiry.

    Recovery: if no new drift events have arrived for RECOVERY_QUIET seconds
    AND there are active anomalies, broadcast a 'recovered' event and clear state.

    Hard expiry: individual anomalies older than ANOMALY_TTL are pruned regardless.
    """
    _recovered_announced = False

    while True:
        await asyncio.sleep(5)
        now = time.time()
        now_ms = now * 1000
        any_active = any(v for v in _active_anomalies.values())

        # ── Recovery detection ────────────────────────────────────────────────
        quiet_secs = now - _last_drift_time if _last_drift_time else 0
        if any_active and _last_drift_time and quiet_secs >= RECOVERY_QUIET and not _recovered_announced:
            print(f"[topology] recovery detected — {quiet_secs:.0f}s quiet", flush=True)
            _active_anomalies.clear()
            _recovered_announced = True
            global _recovery_time
            _recovery_time = now
            closed_ms = int(now * 1000)
            if _current_problem_id:
                _close_problem(_current_problem_id, closed_ms)
            payload = {
                "type":   "recovered",
                "active": {},
                "message": f"Services recovered — no drift events for {quiet_secs:.0f}s",
            }
            for q in _subscribers:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    pass
            continue

        # Reset recovered flag when new events arrive
        if _last_drift_time and quiet_secs < RECOVERY_QUIET:
            _recovered_announced = False

        # ── Hard TTL expiry ───────────────────────────────────────────────────
        changed = False
        for svc in list(_active_anomalies.keys()):
            before = len(_active_anomalies[svc])
            _active_anomalies[svc] = [
                a for a in _active_anomalies[svc]
                if now_ms - a.get("timestamp_ms", 0) < ANOMALY_TTL * 1000
            ]
            if len(_active_anomalies[svc]) != before:
                changed = True
        if changed:
            payload = {
                "type":   "state",
                "active": {k: v for k, v in _active_anomalies.items() if v},
            }
            for q in _subscribers:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    pass


# ── FastAPI app ───────────────────────────────────────────────────────────────

def _list_environments() -> list[str]:
    """Return sorted list of environment names that have a local baseline file."""
    envs = []
    for p in sorted(_DATA_DIR.glob("baseline.*.json")):
        name = p.stem[len("baseline."):]
        if name and name != "unknown":
            envs.append(name)
    return envs


# ── Dynamic wrappers for background tasks that respect env switching ──────────

async def _tail_otel_logs_dynamic(state: dict) -> None:
    """Wrapper around _tail_otel_logs that reads environment from mutable state dict."""
    seen_hashes: dict[str, float] = {}
    DEDUP_TTL = 90
    RECONNECT_DELAY = 5

    while True:
        environment = state["environment"]
        ssh_cmd = (
            "exec bash -c '"
            f"for p in $(kubectl get pods -l {DAEMONSET_LABEL} -o jsonpath=\"{{.items[*].metadata.name}}\");"
            f" do kubectl logs -f --since=5s $p -c {OTEL_CONTAINER} 2>/dev/null & done;"
            " wait'"
        )
        try:
            proc = await asyncio.create_subprocess_exec(
                "sshpass", f"-p{EC2_PASS}",
                "ssh", "-T", "-p", EC2_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "RequestTTY=no",
                "-o", "ServerAliveInterval=10",
                "-o", "ServerAliveCountMax=3",
                f"splunk@{EC2_IP}",
                ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception as exc:
            print(f"[topology] SSH connect failed: {exc} — retrying in {RECONNECT_DELAY}s", flush=True)
            await asyncio.sleep(RECONNECT_DELAY)
            continue

        print(f"[topology] tailing OTel logs for env={environment}", flush=True)
        async for raw in proc.stdout:
            # If environment switched, kill stream and reconnect
            if state["environment"] != environment:
                proc.terminate()
                break
            line = raw.decode("utf-8", errors="replace").rstrip()
            event = _parse_event(line)
            if event is None:
                continue

            h = event.get("hash", "")
            svc = event.get("service", "")
            atype = event.get("anomaly_type", "")
            now = time.time()

            dedup_key = h if h else f"{atype}:{svc}"
            if now - seen_hashes.get(dedup_key, 0) < DEDUP_TTL:
                continue
            seen_hashes[dedup_key] = now

            if svc in _INFRA:
                continue
            if atype == "NEW_FINGERPRINT":
                root_svc = event.get("root_op", "").split(":")[0]
                if root_svc not in {"api-gateway"}:
                    continue

            global _last_drift_time, _recovery_time
            if _recovery_time and now - _recovery_time < RECOVERY_LOCKOUT:
                continue

            print(f"[topology] event: {atype} on {svc}", flush=True)
            _last_drift_time = now
            _active_anomalies[svc].append(event)
            if atype == "MISSING_SERVICE":
                caller = event.get("root_op", "").split(":")[0]
                if caller and caller != svc and caller not in _INFRA:
                    if not _active_anomalies[caller]:
                        caller_event = dict(event,
                            service=caller,
                            anomaly_type="NEW_FINGERPRINT",
                            message=f"Trace path changed — {svc} no longer reachable from {caller}",
                        )
                        _active_anomalies[caller].append(caller_event)

            chain, confidence = _find_root_cause(_topology_cache, _active_anomalies)
            root_cause = chain[0] if chain else svc
            affected_svcs = [s for s, v in _active_anomalies.items() if v]

            if _current_problem_id is None:
                pid = _open_problem(root_cause, affected_svcs, event)
            else:
                pid = _current_problem_id
                _update_problem(pid, root_cause, affected_svcs, event)
            event["problem_id"] = pid

            suppressed = [s for s in affected_svcs
                          if _downstream_suppressed(s, root_cause, _topology_cache, _active_anomalies)]
            payload = {
                "type":            "drift",
                "event":           event,
                "active":          {k: v for k, v in _active_anomalies.items() if v},
                "causality_chain": chain,
                "root_cause":      root_cause,
                "confidence":      confidence,
                "suppressed":      suppressed,
                "timestamp_ms":    int(now * 1000),
                "problem":         _problems[pid],
            }
            dead = []
            for q in _subscribers:
                try:
                    q.put_nowait(payload)
                except asyncio.QueueFull:
                    dead.append(q)
            for q in dead:
                _subscribers.remove(q)

        await proc.wait()
        print(f"[topology] SSH stream ended — reconnecting in {RECONNECT_DELAY}s", flush=True)
        await asyncio.sleep(RECONNECT_DELAY)


async def _tail_topology_events_dynamic(state: dict) -> None:
    """Wrapper around _tail_topology_events that reads environment from mutable state dict."""
    POLL_INTERVAL = 15
    while True:
        await asyncio.sleep(POLL_INTERVAL)
        environment = state["environment"]
        try:
            ssh_cmd = (
                "exec bash -c '"
                f"for p in $(kubectl get pods -l {DAEMONSET_LABEL}"
                " -o jsonpath=\"{.items[*].metadata.name}\");"
                " do kubectl exec $p -c otelcol -- cat /baseline/topology.json 2>/dev/null"
                " && echo \"---EOF---\"; done'"
            )
            proc = await asyncio.create_subprocess_exec(
                "sshpass", f"-p{EC2_PASS}",
                "ssh", "-T", "-p", EC2_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "RequestTTY=no",
                f"splunk@{EC2_IP}",
                ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=20)
            output = stdout.decode("utf-8", errors="replace")

            all_edges: dict[str, dict] = {}
            for chunk in output.split("---EOF---"):
                chunk = chunk.strip()
                if not chunk:
                    continue
                try:
                    data = json.loads(chunk)
                    for key, edge in data.get("edges", {}).items():
                        if key not in all_edges:
                            all_edges[key] = edge
                        else:
                            if edge.get("count", 0) > all_edges[key].get("count", 0):
                                all_edges[key] = edge
                except Exception:
                    continue

            if not all_edges:
                continue

            existing_keys = {
                f"{e['source']}->{e['target']}"
                for e in _topology_cache.get("edges", [])
            }
            existing_ids = {n["id"] for n in _topology_cache.get("nodes", [])}
            added_nodes: list[dict] = []
            added_edges: list[dict] = []
            seen_new_ids: set[str] = set()

            for key, edge in all_edges.items():
                caller = edge.get("caller", "")
                callee = edge.get("callee", "")
                if not caller or not callee:
                    continue
                if caller in _INFRA or callee in _INFRA:
                    continue
                edge_key = f"{caller}->{callee}"
                if edge_key not in existing_keys:
                    added_edges.append({"source": caller, "target": callee,
                                        "weight": edge.get("count", 1)})
                for svc in (caller, callee):
                    if svc not in existing_ids and svc not in seen_new_ids:
                        added_nodes.append({"id": svc, "traffic": 0})
                        seen_new_ids.add(svc)

            if added_nodes or added_edges:
                _merge_topology_edges(added_nodes, added_edges)
                _broadcast_topology_update(added_nodes, added_edges)

        except asyncio.TimeoutError:
            print("[topology] SSH poll timed out", flush=True)
        except Exception as e:
            print(f"[topology] poll error: {e}", flush=True)


# Known service groups for app filtering within a mixed environment
_APP_GROUPS: dict[str, set[str]] = {
    "petclinic": {
        "api-gateway", "customers-service", "vets-service", "visits-service",
        "mysql:petclinic", "admin-server",
    },
    "otel-demo": {
        "frontend", "frontendproxy", "cartservice", "checkoutservice",
        "productcatalogservice", "currencyservice", "paymentservice",
        "emailservice", "shippingservice", "recommendationservice",
        "adservice", "loadgenerator", "accountingservice", "flagd",
        "kafka", "fraud-detection-1.0-all", "quoteservice",
        "featureflagservice", "Accounting", "fraud-detection",
    },
}

# Prefix-based fallback for otel-demo services not in the explicit set
_OTEL_DEMO_PREFIXES = ("cart", "checkout", "product", "currency", "payment",
                       "email", "shipping", "recommendation", "ad", "quote",
                       "feature", "fraud", "accounting", "load", "frontend",
                       "flagd", "kafka")
_PETCLINIC_SUFFIXES = ("-service", ":petclinic")


def _classify_service(svc: str) -> str:
    """Return 'petclinic', 'otel-demo', or 'unknown' for a service name."""
    if not svc or svc.startswith("unknown"):
        return "unknown"
    sl = svc.lower()
    # Explicit sets take priority
    if svc in _APP_GROUPS["petclinic"]:
        return "petclinic"
    if svc in _APP_GROUPS["otel-demo"]:
        return "otel-demo"
    # Prefix match for otel-demo before suffix match for petclinic
    # (avoids misclassifying e.g. "checkoutservice" as petclinic via -service suffix)
    if sl.startswith(_OTEL_DEMO_PREFIXES):
        return "otel-demo"
    if any(sl.endswith(s) for s in _PETCLINIC_SUFFIXES):
        return "petclinic"
    return "unknown"


def _classify_service_env(env: str) -> str:
    """Return 'otel-demo' or 'petclinic' based on environment name heuristic."""
    el = (env or "").lower()
    if "astronomy" in el or "otel" in el or "demo" in el:
        return "otel-demo"
    return "petclinic"


async def _poll_processor_metrics() -> None:
    """Background task: poll GET /metrics on the aggregator pod every 15s.

    Uses `kubectl exec` via SSH to curl the in-process metrics server.
    The aggregator pod exposes MetricsAddr=:9090 by default.
    Falls back gracefully when the pod is unavailable or the port is not open
    (e.g. older image without metricsserver.go — just leaves cache empty).
    """
    global _metrics_cache, _metrics_cache_ts

    while True:
        await asyncio.sleep(_METRICS_POLL_INTERVAL)
        if not EC2_IP or not EC2_PASS:
            continue
        try:
            # Pick the first running aggregator pod
            get_pod_cmd = (
                "exec bash -c '"
                "kubectl get pods -l app=otelcol-aggregator "
                "--field-selector=status.phase=Running "
                "-o jsonpath=\"{.items[0].metadata.name}\" 2>/dev/null'"
            )
            proc = await asyncio.create_subprocess_exec(
                "sshpass", f"-p{EC2_PASS}",
                "ssh", "-T", "-p", EC2_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "RequestTTY=no",
                f"splunk@{EC2_IP}",
                get_pod_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
            pod = stdout.decode("utf-8", errors="replace").strip()
            if not pod:
                continue

            # Curl the metrics server inside the pod
            curl_cmd = (
                "exec bash -c '"
                f"kubectl exec {pod} -c otelcol -- "
                f"wget -qO- http://localhost:{_METRICS_PORT}/metrics 2>/dev/null'"
            )
            proc2 = await asyncio.create_subprocess_exec(
                "sshpass", f"-p{EC2_PASS}",
                "ssh", "-T", "-p", EC2_PORT,
                "-o", "StrictHostKeyChecking=no",
                "-o", "RequestTTY=no",
                f"splunk@{EC2_IP}",
                curl_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout2, _ = await asyncio.wait_for(proc2.communicate(), timeout=10)
            raw = stdout2.decode("utf-8", errors="replace").strip()
            if not raw:
                continue
            data = json.loads(raw)
            _metrics_cache = data
            _metrics_cache_ts = time.time()
        except asyncio.TimeoutError:
            pass
        except Exception as exc:
            print(f"[metrics] poll error: {exc}", flush=True)


def _make_app(environment: str):
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    except ImportError:
        print("ERROR: fastapi not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)

    # Mutable state shared with background tasks
    _state = {"environment": environment}

    app = FastAPI()
    html_file = Path(__file__).parent / "topology.html"

    def _reload_environment(env: str) -> None:
        """Reload baseline + topology cache for env. Clears active anomaly state."""
        global _topology_cache, _baseline_cache, _active_anomalies, _new_nodes, _new_edges
        global _problems, _current_problem_id, _last_drift_time, _recovery_time
        _state["environment"] = env
        fps = _load_baseline(env)
        _baseline_cache = fps
        _topology_cache = _build_topology_from_baseline(fps)
        topo_edges = _load_topology_json(env)
        if topo_edges:
            result = _topology_edges_to_graph(topo_edges, _topology_cache)
            if result["added_nodes"] or result["added_edges"]:
                _merge_topology_edges(result["added_nodes"], result["added_edges"])
        _active_anomalies.clear()
        _new_nodes.clear()
        _new_edges.clear()
        _problems.clear()
        _current_problem_id = None
        _last_drift_time = 0.0
        _recovery_time = 0.0
        print(f"[topology] switched to env={env}: "
              f"{len(fps)} fingerprints, "
              f"{len(_topology_cache['nodes'])} nodes, "
              f"{len(_topology_cache['edges'])} edges", flush=True)

    @app.on_event("startup")
    async def _startup():
        _reload_environment(environment)
        asyncio.create_task(_tail_otel_logs_dynamic(_state))
        asyncio.create_task(_expire_anomalies())
        asyncio.create_task(_tail_topology_events_dynamic(_state))
        asyncio.create_task(_poll_infra_events())
        asyncio.create_task(_poll_processor_metrics())

    @app.get("/", response_class=HTMLResponse)
    async def _index():
        return HTMLResponse(html_file.read_text())

    @app.get("/api/topology")
    async def _get_topology():
        env = _state["environment"]
        cur = _problems.get(_current_problem_id) if _current_problem_id else None
        chain, confidence = _find_root_cause(_topology_cache, _active_anomalies)
        root_cause = chain[0] if chain else None
        affected_svcs = [s for s, v in _active_anomalies.items() if v]
        suppressed = [s for s in affected_svcs
                      if _downstream_suppressed(s, root_cause, _topology_cache, _active_anomalies)] if root_cause else []
        # Annotate each node with its app group
        nodes = _topology_cache.get("nodes", [])
        for n in nodes:
            n["app_group"] = _classify_service(n["id"])
        return JSONResponse({
            "environment":     env,
            "nodes":           nodes,
            "edges":           _topology_cache.get("edges", []),
            "active":          {k: v for k, v in _active_anomalies.items() if v},
            "new_nodes":       list(_new_nodes.values()),
            "new_edges":       list(_new_edges),
            "problem":         cur,
            "causality_chain": chain,
            "root_cause":      root_cause,
            "confidence":      confidence,
            "suppressed":      suppressed,
            "infra_events":    dict(_infra_events),
        })

    @app.get("/api/metrics")
    async def _get_metrics():
        """Return the latest processor metrics snapshot from the aggregator pod.

        Sourced from the in-process HTTP server (metricsserver.go :9090).
        Returns the cached payload (refreshed every 15s by _poll_processor_metrics).
        If the cache is empty (pod unavailable or old image), returns an empty services map.
        """
        age = time.time() - _metrics_cache_ts if _metrics_cache_ts else None
        return JSONResponse({
            "ok":        bool(_metrics_cache),
            "age_s":     round(age, 1) if age is not None else None,
            "data":      _metrics_cache,
        })

    @app.get("/api/environments")
    async def _get_environments():
        envs = _list_environments()
        return JSONResponse({
            "environments": [
                {"name": e, "live": _env_liveness.get(e)}
                for e in envs
            ],
            "current": _state["environment"],
        })

    @app.get("/api/environments/liveness")
    async def _get_liveness():
        return JSONResponse({
            "liveness": {e: _env_liveness.get(e) for e in _list_environments()}
        })

    @app.on_event("startup")
    async def _start_liveness_loop():
        async def _loop():
            while True:
                await asyncio.get_event_loop().run_in_executor(None, _refresh_liveness_cache)
                await asyncio.sleep(_LIVENESS_CHECK_INTERVAL)
        asyncio.create_task(_loop())

    @app.post("/api/switch")
    async def _switch_environment(body: dict):
        from fastapi import HTTPException
        env = body.get("environment", "")
        if not env:
            raise HTTPException(400, "environment required")
        avail = _list_environments()
        if env not in avail:
            raise HTTPException(404, f"No baseline found for '{env}'. Available: {avail}")
        _reload_environment(env)
        # Notify all connected clients to reload
        payload = {
            "type":        "env_switched",
            "environment": env,
            "nodes":       _topology_cache.get("nodes", []),
            "edges":       _topology_cache.get("edges", []),
        }
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)
        return JSONResponse({"ok": True, "environment": env,
                             "nodes": len(_topology_cache.get("nodes", [])),
                             "edges": len(_topology_cache.get("edges", []))})

    @app.get("/api/clear")
    async def _clear():
        global _new_nodes, _new_edges, _current_problem_id
        _active_anomalies.clear()
        _new_nodes.clear()
        _new_edges.clear()
        if _current_problem_id:
            _close_problem(_current_problem_id, int(time.time() * 1000))
        payload = {"type": "state", "active": {}, "new_nodes": [], "new_edges": [], "problem": None}
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return JSONResponse({"ok": True})

    @app.get("/api/problems")
    async def _get_problems():
        return JSONResponse({"problems": list(_problems.values())})

    @app.post("/api/rca")
    async def _rca():
        """Run Claude/Bedrock RCA against current active anomalies.

        Builds a watch_result dict from _active_anomalies and calls agent.reason()
        directly (bypasses stdin/stdout, reuses hypothesis engine + topology context).
        Returns the structured triage plan as JSON.
        """
        import asyncio
        from fastapi import HTTPException

        affected = {k: v for k, v in _active_anomalies.items() if v}
        if not affected:
            return JSONResponse({"ok": False, "error": "No active anomalies to triage"}, status_code=400)

        # Build anomaly list deduped by hash
        anomalies = []
        seen_hashes: set[str] = set()
        for svc, anom_list in affected.items():
            for a in anom_list:
                h = a.get("hash", f"{a.get('anomaly_type')}:{svc}")
                if h in seen_hashes:
                    continue
                seen_hashes.add(h)
                anomalies.append(a)

        watch_result = {
            "anomalies":   anomalies,
            "environment": _state["environment"],
            "window":      {"minutes": 5},
            "summary":     {"total": len(anomalies), "services": list(affected.keys())},
        }

        # Import agent lazily (adds repo root to sys.path so its deps resolve)
        import importlib
        if str(_REPO) not in sys.path:
            sys.path.insert(0, str(_REPO))
        try:
            agent = importlib.import_module("agent")
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"Cannot import agent.py: {e}"}, status_code=500)

        # Inject topology context (mirrors what agent.main() does)
        try:
            topo_ctx = agent._build_topology_context(_state["environment"])
            if topo_ctx:
                watch_result["topology_context"] = topo_ctx
        except Exception:
            pass

        # Inject hypothesis context
        try:
            hyp_ctx = agent._build_hypothesis_context(anomalies, _state["environment"])
            if hyp_ctx:
                watch_result["hypothesis_context"] = hyp_ctx
        except Exception:
            pass

        # Call Claude in a thread (boto3 is synchronous)
        loop = asyncio.get_event_loop()
        try:
            plan = await asyncio.wait_for(
                loop.run_in_executor(None, lambda: agent.reason(watch_result, env=_state["environment"])),
                timeout=60,
            )
        except asyncio.TimeoutError:
            return JSONResponse({"ok": False, "error": "Claude triage timed out (60s)"}, status_code=504)
        except Exception as e:
            return JSONResponse({"ok": False, "error": f"Claude call failed: {e}"}, status_code=502)

        return JSONResponse({
            "ok":        True,
            "plan":      plan,
            "anomalies": len(anomalies),
        })

    def _broadcast_event(event: dict) -> None:
        """Insert a synthetic event into the active state and broadcast to SSE subscribers."""
        global _new_nodes, _new_edges
        svc   = event.get("service", "")
        atype = event.get("anomaly_type", "")
        _active_anomalies[svc].append(event)
        if atype == "MISSING_SERVICE":
            caller = event.get("root_op", "").split(":")[0]
            # Only inject a DRIFT marker on the caller if:
            #   1. It directly calls the missing service in the topology (not just an upstream router)
            #   2. It has no own anomaly yet (ERROR/MISSING events tell the story better)
            direct_callers = _topology_cache.get("upstream", {}).get(svc, [])
            if caller and caller != svc and caller not in _INFRA and caller in direct_callers:
                if not _active_anomalies[caller]:
                    caller_event = dict(event,
                        service=caller,
                        anomaly_type="NEW_FINGERPRINT",
                        message=f"Trace path changed — {svc} no longer reachable from {caller}",
                    )
                    _active_anomalies[caller].append(caller_event)
        # If the affected service isn't in the baseline topology, surface it as a new node
        # so it renders on the graph rather than being invisible.
        baseline_svcs = {n["id"] for n in _topology_cache.get("nodes", [])}
        if svc and svc not in baseline_svcs and svc not in _new_nodes:
            _new_nodes[svc] = {"id": svc, "label": svc}
            # Wire a new edge from its likely caller (root_op service) if known
            caller = event.get("root_op", "").split(":")[0]
            if caller and caller in baseline_svcs:
                key = f"{caller}->{svc}"
                if not any(f"{e['source']}->{e['target']}" == key for e in _new_edges):
                    _new_edges.append({"source": caller, "target": svc, "label": ""})

        # Accumulate new nodes/edges from NEW_FINGERPRINT events
        for edge in event.get("new_edges", []):
            src, dst = edge.get("source", ""), edge.get("target", "")
            if src and dst:
                if dst not in _new_nodes:
                    _new_nodes[dst] = {"id": dst, "label": edge.get("label", dst)}
                key = f"{src}->{dst}"
                if not any(f"{e['source']}->{e['target']}" == key for e in _new_edges):
                    _new_edges.append({"source": src, "target": dst,
                                       "label": edge.get("label", "")})
        chain, confidence = _find_root_cause(_topology_cache, _active_anomalies)
        root_cause = chain[0] if chain else svc
        affected_svcs = [s for s, v in _active_anomalies.items() if v]

        # ── Problem lifecycle ──────────────────────────────────────────────────
        if _current_problem_id is None:
            pid = _open_problem(root_cause, affected_svcs, event)
        else:
            pid = _current_problem_id
            _update_problem(pid, root_cause, affected_svcs, event)
        event["problem_id"] = pid

        suppressed = [s for s in affected_svcs
                      if _downstream_suppressed(s, root_cause, _topology_cache, _active_anomalies)]
        payload = {
            "type":            "drift",
            "event":           event,
            "active":          {k: v for k, v in _active_anomalies.items() if v},
            "causality_chain": chain,
            "root_cause":      root_cause,
            "confidence":      confidence,
            "suppressed":      suppressed,
            "timestamp_ms":    event["timestamp_ms"],
            "new_nodes":       list(_new_nodes.values()),
            "new_edges":       list(_new_edges),
            "problem":         _problems[pid],
        }
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)

    @app.post("/api/inject")
    async def _inject(body: dict):
        """Inject a synthetic anomaly event for testing.

        Body fields:
          anomaly_type  — MISSING_SERVICE | NEW_ERROR_SIGNATURE | NEW_FINGERPRINT | LATENCY_ANOMALY | ERROR_RATE_ANOMALY
          service       — affected service name
          root_op       — root operation (e.g. "api-gateway:GET /owners")
          message       — human-readable description (optional)
          error_type    — for NEW_ERROR_SIGNATURE (optional)
          operation     — for NEW_ERROR_SIGNATURE / LATENCY_ANOMALY / ERROR_RATE_ANOMALY (optional)
          missing_services — list of strings for MISSING_SERVICE (optional)
          current_mean_ms, baseline_mean_ms, z_score — for LATENCY_ANOMALY (optional)
          error_pct, error_count, total_count — for ERROR_RATE_ANOMALY (optional)
        """
        from fastapi import HTTPException
        valid_types = {"MISSING_SERVICE", "NEW_ERROR_SIGNATURE", "NEW_FINGERPRINT",
                       "LATENCY_ANOMALY", "ERROR_RATE_ANOMALY",
                       "SPAN_COUNT_DROP", "SPAN_COUNT_SPIKE"}
        atype = body.get("anomaly_type", "")
        if atype not in valid_types:
            raise HTTPException(400, f"anomaly_type must be one of {valid_types}")
        event = {
            "anomaly_type": atype,
            "service":      body.get("service", "unknown"),
            "root_op":      body.get("root_op", ""),
            "message":      body.get("message", atype),
            "hash":         body.get("hash", f"synthetic:{atype}:{body.get('service','')}:{int(time.time())}"),
            "timestamp_ms": int(time.time() * 1000),
        }
        if atype == "NEW_ERROR_SIGNATURE":
            event["error_type"] = body.get("error_type", "Exception")
            event["operation"]  = body.get("operation", "")
        if atype == "MISSING_SERVICE":
            event["missing_services"] = body.get("missing_services", [body.get("service", "")])
        if atype == "LATENCY_ANOMALY":
            event["operation"]         = body.get("operation", "")
            event["current_mean_ms"]   = body.get("current_mean_ms", "?")
            event["baseline_mean_ms"]  = body.get("baseline_mean_ms", "?")
            event["z_score"]           = body.get("z_score", "?")
        if atype == "ERROR_RATE_ANOMALY":
            event["operation"]    = body.get("operation", "")
            event["error_pct"]    = body.get("error_pct", "?")
            event["error_count"]  = body.get("error_count", 0)
            event["total_count"]  = body.get("total_count", 0)
        if atype == "SPAN_COUNT_DROP":
            event["span_count"]                = body.get("span_count", "?")
            event["span_count_baseline_min"]   = body.get("span_count_baseline_min", "?")
            event["span_count_baseline_max"]   = body.get("span_count_baseline_max", "?")
        if atype == "SPAN_COUNT_SPIKE":
            event["span_count"]                = body.get("span_count", "?")
            event["span_count_baseline_max"]   = body.get("span_count_baseline_max", "?")
        _broadcast_event(event)
        return JSONResponse({"ok": True, "event": event})

    # ── Named demo scenarios ───────────────────────────────────────────────────
    _DEMO_SCENARIOS: dict[str, list[dict]] = {
        # 1. Service killed: vets-service disappears from traces
        "kill-service": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "vets-service",
                "root_op":          "api-gateway:GET /vets",
                "missing_services": ["vets-service"],
                "message":          "MISSING_SERVICE: vets-service absent from traces",
                "hash":             "synthetic:missing:vets-service",
            },
        ],
        # 2. Trace path change: visits-service now calls notification-service (new node/edge)
        "new-call-path": [
            {
                "anomaly_type": "NEW_FINGERPRINT",
                "service":      "visits-service",
                "root_op":      "api-gateway:GET /owners/{ownerId}/pets/{petId}/visits",
                "message":      "Trace path drift — visits-service calling notification-service (new edge)",
                "hash":         "synthetic:fp:visits-new-edge",
                "new_edges": [
                    {"source": "visits-service", "target": "notification-service",
                     "label": "new call"},
                ],
            },
        ],
        # 3. New error signature on visits-service
        "new-error": [
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "visits-service",
                "root_op":      "api-gateway:POST /owners/{ownerId}/pets/{petId}/visits",
                "error_type":   "DataAccessException",
                "operation":    "POST /owners/{ownerId}/pets/{petId}/visits",
                "message":      "New error: DataAccessException on POST /owners/{ownerId}/pets/{petId}/visits",
                "hash":         "synthetic:err:visits-DataAccessException",
            },
        ],
        # 4. DB caller no longer calls the DB (visits-service stops reaching mysql:petclinic)
        # DB down: structural drift (MISSING_SERVICE) + error drift (JDBC) fire together —
        # same root cause, two tiers of signal, as happens in production.
        "db-incident": [
            # Structural tier: mysql:petclinic disappears from all callers' trace paths.
            # Each event is emitted twice — once attributed to mysql:petclinic (so it
            # enters `active` and wins root-cause scoring) and once to the caller (so
            # the caller shows a MISSING badge alongside its ERROR badge).
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "mysql:petclinic",
                "root_op":          "visits-service:POST /owners/{ownerId}/pets/{petId}/visits",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from visits-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-visits",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "visits-service",
                "root_op":          "visits-service:POST /owners/{ownerId}/pets/{petId}/visits",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from visits-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-visits-caller",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "mysql:petclinic",
                "root_op":          "api-gateway:GET /owners",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from customers-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-customers",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "customers-service",
                "root_op":          "api-gateway:GET /owners",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from customers-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-customers-caller",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "mysql:petclinic",
                "root_op":          "api-gateway:GET /vets",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from vets-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-vets",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "vets-service",
                "root_op":          "api-gateway:GET /vets",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent from vets-service traces",
                "hash":             "synthetic:missing:mysql-petclinic-vets-caller",
            },
            # Error tier: all three callers throw JDBC connection errors
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "visits-service",
                "root_op":      "api-gateway:POST /owners/{ownerId}/pets/{petId}/visits",
                "error_type":   "CannotGetJdbcConnectionException",
                "operation":    "Transaction.commit",
                "message":      "New error: CannotGetJdbcConnectionException on Transaction.commit",
                "hash":         "synthetic:err:visits-jdbc",
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "vets-service",
                "root_op":      "api-gateway:GET /vets",
                "error_type":   "CannotGetJdbcConnectionException",
                "operation":    "SELECT vets",
                "message":      "New error: CannotGetJdbcConnectionException on SELECT vets",
                "hash":         "synthetic:err:vets-jdbc",
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "error_type":   "CannotGetJdbcConnectionException",
                "operation":    "SELECT owners",
                "message":      "New error: CannotGetJdbcConnectionException on SELECT owners",
                "hash":         "synthetic:err:customers-jdbc",
            },
        ],
        # Demo 7: Latency spike on visits-service (tc-netem 3s delay → z-score >>3σ)
        "latency-spike": [
            {
                "anomaly_type":     "LATENCY_ANOMALY",
                "service":          "visits-service",
                "root_op":          "api-gateway:GET /owners/{ownerId}/pets/{petId}/visits",
                "operation":        "GET /owners/{ownerId}/pets/{petId}/visits",
                "current_mean_ms":  "753.4",
                "baseline_mean_ms": "3.1",
                "z_score":          "8496.2",
                "spans_per_min":    "47",
                "message":          "Latency spike: visits-service 753ms (baseline 3ms, z=8496)",
                "hash":             "synthetic:latency:visits-service",
            },
        ],
        # Demo 8: Error rate spike on customers-service (DB killed → every DB call fails)
        "error-rate-spike": [
            {
                "anomaly_type": "ERROR_RATE_ANOMALY",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "operation":    "SELECT owners",
                "error_pct":    "100.0%",
                "error_count":  42,
                "total_count":  42,
                "spans_per_min": "83",
                "message":      "Error rate spike: customers-service 100.0% (42/42 spans)",
                "hash":         "synthetic:errorrate:customers-service",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "error_type":   "CannotCreateTransactionException",
                "operation":    "SELECT owners",
                "message":      "New error: CannotCreateTransactionException on SELECT owners",
                "hash":         "synthetic:err:customers-cannotcreate",
                "_delay_ms":    800,
            },
        ],
        # Demo 9: Combined structural + metric anomaly
        # vets-service killed (MISSING_SERVICE) + DB killed (ERROR_RATE_ANOMALY + NEW_ERROR_SIGNATURE)
        "combined-metric": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "vets-service",
                "root_op":          "api-gateway:GET /vets",
                "missing_services": ["vets-service"],
                "message":          "MISSING_SERVICE: vets-service absent from traces",
                "hash":             "synthetic:missing:vets-combined",
                "_delay_ms":        0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "error_type":   "CannotCreateTransactionException",
                "operation":    "SELECT owners",
                "message":      "New error: CannotCreateTransactionException on SELECT owners",
                "hash":         "synthetic:err:customers-combined",
                "_delay_ms":    800,
            },
            {
                "anomaly_type": "ERROR_RATE_ANOMALY",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "operation":    "SELECT owners",
                "error_pct":    "97.6%",
                "error_count":  41,
                "total_count":  42,
                "message":      "Error rate spike: customers-service 97.6% (41/42 spans)",
                "hash":         "synthetic:errorrate:customers-combined",
                "_delay_ms":    2000,
            },
        ],
        # Demo: OOMKill on visits-service pod → latency spike + infra event correlation
        "oom-latency": [
            {
                "anomaly_type":     "LATENCY_ANOMALY",
                "service":          "visits-service",
                "root_op":          "api-gateway:GET /owners/{ownerId}/pets/{petId}/visits",
                "operation":        "GET /owners/{ownerId}/pets/{petId}/visits",
                "current_mean_ms":  "1243.0",
                "baseline_mean_ms": "3.1",
                "z_score":          "14200.0",
                "spans_per_min":    "52",
                "message":          "Latency spike: visits-service 1243ms (baseline 3ms, z=14200)",
                "hash":             "synthetic:latency:visits-oom",
                "_delay_ms":        0,
            },
        ],
        # Cascading failure: vets-service killed → its caller (api-gateway) starts
        # erroring → customers-service also errors (shared upstream dependency).
        # Events fire with increasing delay to show propagation unfolding over time.
        "cascading": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "vets-service",
                "root_op":          "api-gateway:GET /vets",
                "missing_services": ["vets-service"],
                "message":          "MISSING_SERVICE: vets-service absent from traces",
                "hash":             "synthetic:missing:vets-cascade",
                "_delay_ms":        0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "api-gateway",
                "root_op":      "api-gateway:GET /vets",
                "error_type":   "ServiceUnavailableException",
                "operation":    "GET /vets",
                "message":      "New error: ServiceUnavailableException on GET /vets",
                "hash":         "synthetic:err:api-gateway-vets",
                "_delay_ms":    2000,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "error_type":   "TimeoutException",
                "operation":    "GET /owners",
                "message":      "New error: TimeoutException on GET /owners — upstream pressure",
                "hash":         "synthetic:err:customers-timeout",
                "_delay_ms":    2000,
            },
        ],

        # Slow DB: mysql:petclinic responds but is overloaded → all callers get
        # correlated LATENCY_ANOMALY simultaneously.  No structural drift (DB still
        # reachable), but shared-dep latency root cause should be identified.
        "slow-db": [
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "mysql:petclinic",
                "root_op":      "customers-service:GET /owners",
                "operation":    "SELECT owners",
                "current_mean_ms": "4200",
                "baseline_mean_ms": "12",
                "z_score":      "18.4",
                "message":      "Latency spike: mysql:petclinic 4200ms (baseline 12ms, z=18.4)",
                "hash":         "synthetic:latency:mysql-slow",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "operation":    "GET /owners",
                "current_mean_ms": "4350",
                "baseline_mean_ms": "38",
                "z_score":      "14.2",
                "message":      "Latency spike: customers-service 4350ms (baseline 38ms, z=14.2)",
                "hash":         "synthetic:latency:customers-slow",
                "_delay_ms":    500,
            },
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "vets-service",
                "root_op":      "api-gateway:GET /vets",
                "operation":    "SELECT vets",
                "current_mean_ms": "4180",
                "baseline_mean_ms": "15",
                "z_score":      "16.9",
                "message":      "Latency spike: vets-service 4180ms (baseline 15ms, z=16.9)",
                "hash":         "synthetic:latency:vets-slow",
                "_delay_ms":    500,
            },
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "visits-service",
                "root_op":      "api-gateway:GET /visits",
                "operation":    "SELECT visits",
                "current_mean_ms": "4290",
                "baseline_mean_ms": "22",
                "z_score":      "15.7",
                "message":      "Latency spike: visits-service 4290ms (baseline 22ms, z=15.7)",
                "hash":         "synthetic:latency:visits-slow",
                "_delay_ms":    500,
            },
        ],

        # Span count drop: visits-service normally produces 12–18 spans per trace
        # (includes DB calls, method instrumentation).  A silent failure — connection
        # pool exhaustion short-circuits DB calls — causes each trace to complete with
        # only 3 spans (just the HTTP layer, no DB fan-out).
        # Story: framework fires SPAN_COUNT_DROP immediately; no error signal, no MISSING,
        # no latency change.  Invisible to threshold-based alerting.
        "span-count-drop": [
            {
                "anomaly_type": "SPAN_COUNT_DROP",
                "service":      "visits-service",
                "root_op":      "api-gateway:GET /owners/{ownerId}/pets/{petId}/visits",
                "message":      "Span count drop: visits-service 3 spans (baseline min 12) — DB calls silently missing",
                "hash":         "synthetic:spandrop:visits-service",
                "span_count":   3,
                "span_count_baseline_min": 12,
                "span_count_baseline_max": 18,
                "_delay_ms":    0,
            },
        ],

        # Span count spike: customers-service normally produces 8–12 spans per trace.
        # A retry storm (connection timeout → retry × 7) inflates each trace to 58 spans —
        # 7× the baseline max.  No new error signature (same exception, already known),
        # no MISSING_SERVICE.  SPAN_COUNT_SPIKE catches the retry-storm pattern.
        "span-count-spike": [
            {
                "anomaly_type": "SPAN_COUNT_SPIKE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "message":      "Span count spike: customers-service 58 spans (baseline max 12, ×4.8) — retry storm",
                "hash":         "synthetic:spanspike:customers-service",
                "span_count":   58,
                "span_count_baseline_max": 12,
                "_delay_ms":    0,
            },
        ],

        # OOM / crash sequence: service degrades under memory pressure before dying.
        # Phase 1 (t=0): LATENCY spike — requests slowing as GC pressure mounts.
        # Phase 2 (t=4s): MISSING — service crashes, disappears from traces entirely.
        # Two separate signals, one root cause, time-ordered causality.
        "oom-crash": [
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "operation":    "GET /owners",
                "current_mean_ms": "3800",
                "baseline_mean_ms": "38",
                "z_score":      "12.6",
                "message":      "Latency spike: customers-service 3800ms (baseline 38ms, z=12.6) — GC pressure",
                "hash":         "synthetic:latency:customers-oom",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "MISSING_SERVICE",
                "service":      "customers-service",
                "root_op":      "api-gateway:GET /owners",
                "missing_services": ["customers-service"],
                "message":      "MISSING_SERVICE: customers-service absent — OOM crash after latency spike",
                "hash":         "synthetic:missing:customers-oom",
                "_delay_ms":    4000,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "api-gateway",
                "root_op":      "api-gateway:GET /owners",
                "error_type":   "ServiceUnavailableException",
                "operation":    "GET /owners",
                "message":      "New error: ServiceUnavailableException on GET /owners — customers-service crashed",
                "hash":         "synthetic:err:api-gw-customers-oom",
                "_delay_ms":    1000,
            },
        ],
    }

    @app.post("/api/inject/infra")
    async def _inject_infra(body: dict):
        """Inject synthetic infra events (kubectl warning events) for demo/testing.

        Body: { "service": "visits-service", "reason": "OOMKilling",
                "message": "...", "count": 1 }
        """
        svc    = body.get("service", "unknown")
        reason = body.get("reason", "OOMKilling")
        msg    = body.get("message", f"Container killed due to OOM in pod {svc}-xxx")
        count  = body.get("count", 1)
        ev = {
            "reason":       reason,
            "message":      msg[:120],
            "count":        count,
            "timestamp_ms": int(time.time() * 1000),
            "object":       f"{svc}-synthetic",
        }
        _infra_events[svc].append(ev)
        payload = {
            "type":         "infra_events",
            "infra_events": dict(_infra_events),
            "affected":     [svc],
            "timestamp_ms": ev["timestamp_ms"],
        }
        dead = []
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            _subscribers.remove(q)
        return JSONResponse({"ok": True, "event": ev})

    # ── Astronomy Shop scenario variants ──────────────────────────────────────
    _DEMO_SCENARIOS_OTEL: dict[str, list[dict]] = {
        # 1. checkout killed — disappears from traces
        "kill-service": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "checkout",
                "root_op":          "load-generator:user_checkout_single",
                "missing_services": ["checkout"],
                "message":          "MISSING_SERVICE: checkout absent from traces",
                "hash":             "synthetic:missing:checkout",
            },
        ],
        # 2. product-catalog starts calling recommendation (new edge)
        "new-call-path": [
            {
                "anomaly_type": "NEW_FINGERPRINT",
                "service":      "product-catalog",
                "root_op":      "load-generator:user_browse_product",
                "message":      "Trace path drift — product-catalog calling recommendation (new edge)",
                "hash":         "synthetic:fp:productcatalog-new-edge",
                "new_edges": [
                    {"source": "product-catalog", "target": "recommendation", "label": "new call"},
                ],
            },
        ],
        # 3. New error signature on product-catalog
        "new-error": [
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "product-catalog",
                "root_op":      "load-generator:user_browse_product",
                "error_type":   "DataAccessException",
                "operation":    "GET /hipstershop.ProductCatalogService/GetProduct",
                "message":      "New error: DataAccessException on GetProduct",
                "hash":         "synthetic:err:productcatalog-DataAccessException",
            },
        ],
        # 4. Shared cache down: valkey-cart disappears from cart traces + errors propagate
        "db-incident": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "valkey-cart",
                "root_op":          "load-generator:user_add_to_cart",
                "missing_services": ["valkey-cart"],
                "message":          "MISSING_SERVICE: valkey-cart absent from cart traces",
                "hash":             "synthetic:missing:valkey-cart",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "cart",
                "root_op":          "load-generator:user_add_to_cart",
                "missing_services": ["valkey-cart"],
                "message":          "MISSING_SERVICE: valkey-cart absent from cart traces",
                "hash":             "synthetic:missing:valkey-cart-caller",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "valkey-cart",
                "root_op":          "load-generator:user_view_cart",
                "missing_services": ["valkey-cart"],
                "message":          "MISSING_SERVICE: valkey-cart absent from checkout traces",
                "hash":             "synthetic:missing:valkey-cart-checkout",
            },
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "checkout",
                "root_op":          "load-generator:user_checkout_single",
                "missing_services": ["valkey-cart"],
                "message":          "MISSING_SERVICE: valkey-cart absent from checkout traces",
                "hash":             "synthetic:missing:valkey-cart-checkout-caller",
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "error_type":   "RedisConnectionException",
                "operation":    "AddItem",
                "message":      "New error: RedisConnectionException on AddItem",
                "hash":         "synthetic:err:cart-redis",
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "checkout",
                "root_op":      "load-generator:user_checkout_single",
                "error_type":   "RedisConnectionException",
                "operation":    "PlaceOrder",
                "message":      "New error: RedisConnectionException on PlaceOrder",
                "hash":         "synthetic:err:checkout-redis",
            },
        ],
        # 5. Cascading failure: checkout killed → frontend errors → cart errors
        "cascading": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "checkout",
                "root_op":          "load-generator:user_checkout_single",
                "missing_services": ["checkout"],
                "message":          "MISSING_SERVICE: checkout absent from traces",
                "hash":             "synthetic:missing:checkout-cascade",
                "_delay_ms":        0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "frontend",
                "root_op":      "frontend-proxy:ingress",
                "error_type":   "ServiceUnavailableException",
                "operation":    "POST /api/checkout",
                "message":      "New error: ServiceUnavailableException on POST /api/checkout",
                "hash":         "synthetic:err:frontend-checkout",
                "_delay_ms":    2000,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "error_type":   "TimeoutException",
                "operation":    "AddItem",
                "message":      "New error: TimeoutException on AddItem — upstream pressure",
                "hash":         "synthetic:err:cart-timeout",
                "_delay_ms":    2000,
            },
        ],
        # 6. Latency spike on product-catalog
        "latency-spike": [
            {
                "anomaly_type":     "LATENCY_ANOMALY",
                "service":          "product-catalog",
                "root_op":          "load-generator:user_browse_product",
                "operation":        "GET /hipstershop.ProductCatalogService/GetProduct",
                "current_mean_ms":  "892.4",
                "baseline_mean_ms": "4.2",
                "z_score":          "7340.0",
                "spans_per_min":    "52",
                "message":          "Latency spike: product-catalog 892ms (baseline 4ms, z=7340)",
                "hash":             "synthetic:latency:product-catalog",
            },
        ],
        # 7. Error rate spike on payment
        "error-rate-spike": [
            {
                "anomaly_type": "ERROR_RATE_ANOMALY",
                "service":      "payment",
                "root_op":      "load-generator:user_checkout_single",
                "operation":    "hipstershop.PaymentService/Charge",
                "error_pct":    "100.0%",
                "error_count":  38,
                "total_count":  38,
                "spans_per_min": "61",
                "message":      "Error rate spike: payment 100.0% (38/38 spans)",
                "hash":         "synthetic:errorrate:payment",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "payment",
                "root_op":      "load-generator:user_checkout_single",
                "error_type":   "PaymentServiceException",
                "operation":    "hipstershop.PaymentService/Charge",
                "message":      "New error: PaymentServiceException on Charge",
                "hash":         "synthetic:err:payment-exception",
                "_delay_ms":    800,
            },
        ],
        # 8. Combined: checkout missing + payment error rate
        "combined-metric": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "checkout",
                "root_op":          "load-generator:user_checkout_single",
                "missing_services": ["checkout"],
                "message":          "MISSING_SERVICE: checkout absent from traces",
                "hash":             "synthetic:missing:checkout-combined",
                "_delay_ms":        0,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "payment",
                "root_op":      "load-generator:user_checkout_single",
                "error_type":   "PaymentServiceException",
                "operation":    "hipstershop.PaymentService/Charge",
                "message":      "New error: PaymentServiceException on Charge",
                "hash":         "synthetic:err:payment-combined",
                "_delay_ms":    800,
            },
            {
                "anomaly_type": "ERROR_RATE_ANOMALY",
                "service":      "payment",
                "root_op":      "load-generator:user_checkout_single",
                "operation":    "hipstershop.PaymentService/Charge",
                "error_pct":    "97.4%",
                "error_count":  37,
                "total_count":  38,
                "message":      "Error rate spike: payment 97.4% (37/38 spans)",
                "hash":         "synthetic:errorrate:payment-combined",
                "_delay_ms":    2000,
            },
        ],
        # 9. Slow shared cache: valkey-cart overloaded → cart + checkout latency
        # Slow shared cache: cart's Redis (valkey) is overloaded but untraced.
        # Cart is the first instrumented service to show latency — it's the shared
        # dependency that checkout and frontend both route through.
        "slow-db": [
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "operation":    "AddItem",
                "current_mean_ms": "3950",
                "baseline_mean_ms": "32",
                "z_score":      "15.8",
                "message":      "Latency spike: cart 3950ms (baseline 32ms, z=15.8) — cache overloaded",
                "hash":         "synthetic:latency:cart-slow",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "checkout",
                "root_op":      "load-generator:user_checkout_single",
                "operation":    "PlaceOrder",
                "current_mean_ms": "4100",
                "baseline_mean_ms": "45",
                "z_score":      "13.4",
                "message":      "Latency spike: checkout 4100ms (baseline 45ms, z=13.4)",
                "hash":         "synthetic:latency:checkout-slow",
                "_delay_ms":    500,
            },
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "frontend",
                "root_op":      "frontend-proxy:ingress",
                "operation":    "POST /api/checkout",
                "current_mean_ms": "4250",
                "baseline_mean_ms": "55",
                "z_score":      "11.9",
                "message":      "Latency spike: frontend 4250ms (baseline 55ms, z=11.9)",
                "hash":         "synthetic:latency:frontend-slow",
                "_delay_ms":    500,
            },
        ],
        # 10. OOM crash: cart latency (GC pressure) → cart disappears
        "oom-crash": [
            {
                "anomaly_type": "LATENCY_ANOMALY",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "operation":    "AddItem",
                "current_mean_ms": "3600",
                "baseline_mean_ms": "32",
                "z_score":      "11.8",
                "message":      "Latency spike: cart 3600ms (baseline 32ms, z=11.8) — GC pressure",
                "hash":         "synthetic:latency:cart-oom",
                "_delay_ms":    0,
            },
            {
                "anomaly_type": "MISSING_SERVICE",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "missing_services": ["cart"],
                "message":      "MISSING_SERVICE: cart absent — OOM crash after latency spike",
                "hash":         "synthetic:missing:cart-oom",
                "_delay_ms":    4000,
            },
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "frontend",
                "root_op":      "frontend-proxy:ingress",
                "error_type":   "ServiceUnavailableException",
                "operation":    "POST /api/cart",
                "message":      "New error: ServiceUnavailableException on POST /api/cart — cart crashed",
                "hash":         "synthetic:err:frontend-cart-oom",
                "_delay_ms":    1000,
            },
        ],
        # 11. Span count drop on product-catalog
        "span-count-drop": [
            {
                "anomaly_type": "SPAN_COUNT_DROP",
                "service":      "product-catalog",
                "root_op":      "load-generator:user_browse_product",
                "message":      "Span count drop: product-catalog 2 spans (baseline min 9) — DB calls silently missing",
                "hash":         "synthetic:spandrop:product-catalog",
                "span_count":   2,
                "span_count_baseline_min": 9,
                "span_count_baseline_max": 14,
                "_delay_ms":    0,
            },
        ],
        # 12. Span count spike on cart (retry storm)
        "span-count-spike": [
            {
                "anomaly_type": "SPAN_COUNT_SPIKE",
                "service":      "cart",
                "root_op":      "load-generator:user_add_to_cart",
                "message":      "Span count spike: cart 64 spans (baseline max 10, ×6.4) — retry storm",
                "hash":         "synthetic:spanspike:cart",
                "span_count":   64,
                "span_count_baseline_max": 10,
                "_delay_ms":    0,
            },
        ],
    }

    @app.get("/api/demo/{scenario}")
    async def _demo(scenario: str, delay_ms: int = 800):
        """Fire a named demo scenario, broadcasting events with delay_ms between them.

        Scenarios: kill-service | new-call-path | new-error | db-incident |
                   cascading | latency-spike | error-rate-spike | combined-metric |
                   slow-db | oom-crash
        """
        from fastapi import HTTPException
        # Pick scenario set based on current environment
        env = _state.get("environment", "")
        app_type = _classify_service_env(env)
        scenarios = _DEMO_SCENARIOS_OTEL if app_type == "otel-demo" else _DEMO_SCENARIOS
        if scenario not in scenarios:
            raise HTTPException(400, f"Unknown scenario. Valid: {list(scenarios)}")
        events = scenarios[scenario]

        async def _fire():
            for ev in events:
                wait = ev.get("_delay_ms", delay_ms if len(events) > 1 else 0)
                if wait:
                    await asyncio.sleep(wait / 1000)
                full = {k: v for k, v in ev.items() if not k.startswith("_")}
                full["timestamp_ms"] = int(time.time() * 1000)
                _broadcast_event(full)

        asyncio.create_task(_fire())
        return JSONResponse({"ok": True, "scenario": scenario, "events": len(events)})

    @app.get("/api/demo")
    async def _demo_list():
        return JSONResponse({"scenarios": list(_DEMO_SCENARIOS)})

    @app.get("/api/events")
    async def _sse():
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        _subscribers.append(q)

        async def _stream() -> AsyncGenerator[bytes, None]:
            try:
                # Send current state immediately on connect
                cur = _problems.get(_current_problem_id) if _current_problem_id else None
                _chain, _conf = _find_root_cause(_topology_cache, _active_anomalies)
                _rc = _chain[0] if _chain else None
                _aff = [s for s, v in _active_anomalies.items() if v]
                _sup = [s for s in _aff
                        if _downstream_suppressed(s, _rc, _topology_cache, _active_anomalies)] if _rc else []
                snapshot = {
                    "type":            "state",
                    "active":          {k: v for k, v in _active_anomalies.items() if v},
                    "problem":         cur,
                    "causality_chain": _chain,
                    "root_cause":      _rc,
                    "confidence":      _conf,
                    "suppressed":      _sup,
                    "infra_events":    dict(_infra_events),
                }
                yield f"data: {json.dumps(snapshot)}\n\n".encode()
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=15.0)
                        yield f"data: {json.dumps(msg)}\n\n".encode()
                    except asyncio.TimeoutError:
                        yield b": keepalive\n\n"
            finally:
                if q in _subscribers:
                    _subscribers.remove(q)

        return StreamingResponse(
            _stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--environment", default=os.environ.get("ENV", ""),
                        help="Environment name")
    parser.add_argument("--port", type=int, default=8080,
                        help="HTTP port (default: 8080)")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Bind host (default: 0.0.0.0)")
    args = parser.parse_args()

    if not args.environment:
        print("ERROR: --environment or ENV env var required")
        sys.exit(1)
    if not EC2_IP or not EC2_PASS:
        print("ERROR: EC2_IP and EC2_PASSWORD must be set in .env")
        sys.exit(1)

    try:
        import uvicorn
    except ImportError:
        print("ERROR: uvicorn not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)

    app = _make_app(args.environment)
    print(f"[topology] starting on http://localhost:{args.port}  env={args.environment}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
