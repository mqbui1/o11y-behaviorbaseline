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

# ── Regex (shared with poll_drift_events.py) ──────────────────────────────────
drift_re   = re.compile(r'(trace drift detected|new trace fingerprint \(unknown root op\)|new error signature detected|missing service detected)')
hash_re    = re.compile(r'"hash": "([^"]+)"')
op_re      = re.compile(r'"root_op": "([^"]+)"')
svc_re     = re.compile(r'"service": "([^"]+)"')
path_re    = re.compile(r'"path": "([^"]+)"')
tid_re     = re.compile(r'"trace_id": "([^"]+)"')
etype_re   = re.compile(r'"error_type": "([^"]+)"')
op2_re     = re.compile(r'"operation": "([^"]+)"')
missing_re = re.compile(r'"missing_services": \[([^\]]*)\]')

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

    for fp in fingerprints.values():
        path  = fp.get("path", "")
        occ   = fp.get("occurrences", 1)
        parts = [p.strip() for p in path.split("->")]
        svcs  = []
        last_app_svc = None  # track last non-DB service to wire DB edge
        for p in parts:
            op  = p.split(":", 1)[1].strip() if ":" in p else p
            svc = p.split(":")[0] if ":" in p else p
            # If this span is a DB operation, inject mysql:petclinic as a synthetic node
            if any(op.startswith(pat) for pat in _DB_SPAN_PATTERNS):
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
        for i in range(len(svcs) - 1):
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

    return {
        "nodes":      nodes,
        "edges":      edges,
        "upstream":   dict(upstream),
        "downstream": dict(downstream),
    }


def _find_root_cause(topology: dict,
                     active: dict[str, list[dict]]) -> list[str]:
    """
    Traverse the dependency graph to find root cause across all affected services.
    Returns causality chain: [root_cause, intermediate..., most_upstream_affected]

    Algorithm:
      - Start from all services with active anomalies
      - Walk their downstream dependencies
      - A node with anomalies and no anomalous deps is a root cause candidate
      - If multiple candidates, prefer the one with most callers affected (shared dep)
      - Build chain from root cause up to the most upstream affected service
    """
    downstream = topology.get("downstream", {})
    upstream   = topology.get("upstream", {})
    affected   = {s for s, v in active.items() if v}

    if not affected:
        return []

    def _find_deepest(svc: str, visited: set) -> str:
        """Recursively find the deepest downstream node that also has anomalies."""
        if svc in visited:
            return svc
        visited.add(svc)
        for dep in downstream.get(svc, []):
            if dep in _INFRA:
                continue
            if dep in affected:
                deeper = _find_deepest(dep, visited)
                return deeper
        return svc

    # Find root cause: deepest affected node reachable from any affected service
    candidates: dict[str, int] = {}
    for svc in affected:
        root = _find_deepest(svc, set())
        callers_hit = sum(1 for c in upstream.get(root, []) if c in affected)
        candidates[root] = max(candidates.get(root, 0), callers_hit)

    # mysql:petclinic as root cause only if it has its OWN anomalies AND multiple
    # affected services call it (shared dep = high confidence DB is the cause)
    if "mysql:petclinic" in affected:
        callers_hit = sum(1 for svc in affected
                         if "mysql:petclinic" in downstream.get(svc, []))
        if callers_hit > 1:
            candidates["mysql:petclinic"] = callers_hit

    # Pick candidate with most affected callers (shared dep = highest confidence)
    root_cause = max(candidates, key=lambda k: candidates[k])

    # Build chain: root_cause → services that call it (affected) → their callers
    chain = [root_cause]
    visited_chain: set[str] = {root_cause}
    frontier = [c for c in upstream.get(root_cause, []) if c in affected and c not in visited_chain]
    while frontier:
        next_layer = []
        for svc in frontier:
            if svc not in visited_chain:
                chain.append(svc)
                visited_chain.add(svc)
                next_layer += [c for c in upstream.get(svc, [])
                               if c in affected and c not in visited_chain]
        frontier = next_layer

    return chain


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

    if is_missing:
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


# ── SSH log tail (background task) ───────────────────────────────────────────

async def _tail_otel_logs(environment: str) -> None:
    """Background task: tail OTel collector pod logs and broadcast drift events.

    Auto-reconnects when the SSH stream dies (e.g. after pods are cycled by
    demo-between.sh). Each reconnect refreshes pod names so new pods are picked up.
    """
    seen_hashes: dict[str, float] = {}
    DEDUP_TTL = 90
    RECONNECT_DELAY = 5  # seconds between reconnect attempts

    while True:
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
            line = raw.decode("utf-8", errors="replace").rstrip()
            event = _parse_event(line)
            if event is None:
                continue

            h = event.get("hash", "")
            svc = event.get("service", "")
            atype = event.get("anomaly_type", "")
            now = time.time()

            # Deduplicate
            dedup_key = h if h else f"{atype}:{svc}"
            if now - seen_hashes.get(dedup_key, 0) < DEDUP_TTL:
                continue
            seen_hashes[dedup_key] = now

            # Skip infra noise
            if svc in _INFRA:
                continue
            # Skip direct-service NEW_FINGERPRINT (OTel auto-promotion noise)
            if atype == "NEW_FINGERPRINT":
                root_svc = event.get("root_op", "").split(":")[0]
                if root_svc not in {"api-gateway"}:
                    continue

            # Ignore events during post-recovery lockout (absorbs pod log replay after pod cycling)
            if _recovery_time and now - _recovery_time < RECOVERY_LOCKOUT:
                print(f"[topology] suppressed (lockout {RECOVERY_LOCKOUT - (now - _recovery_time):.0f}s remaining): {atype} on {svc}", flush=True)
                continue

            print(f"[topology] event: {atype} on {svc}", flush=True)

            # Update active anomalies and last-drift timestamp
            global _last_drift_time
            _last_drift_time = now
            _active_anomalies[svc].append(event)
            # For MISSING_SERVICE, also mark the caller (root_op service) as DRIFT
            # (not MISSING) — it's still running but its dependency is gone.
            if atype == "MISSING_SERVICE":
                caller = event.get("root_op", "").split(":")[0]
                if caller and caller != svc and caller not in _INFRA:
                    caller_event = dict(event,
                        service=caller,
                        anomaly_type="NEW_FINGERPRINT",
                        message=f"Trace path changed — {svc} no longer reachable from {caller}",
                    )
                    _active_anomalies[caller].append(caller_event)

            # Build causality chain
            chain = _find_root_cause(_topology_cache, _active_anomalies)

            # Build broadcast payload
            payload = {
                "type":           "drift",
                "event":          event,
                "active":         {k: v for k, v in _active_anomalies.items() if v},
                "causality_chain": chain,
                "root_cause":     chain[0] if chain else svc,
                "timestamp_ms":   int(now * 1000),
            }

            # Broadcast to all SSE subscribers
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

def _make_app(environment: str):
    try:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
    except ImportError:
        print("ERROR: fastapi not installed. Run: pip install fastapi uvicorn")
        sys.exit(1)

    app = FastAPI()
    html_file = Path(__file__).parent / "topology.html"

    @app.on_event("startup")
    async def _startup():
        global _topology_cache, _baseline_cache
        fps = _load_baseline(environment)
        _baseline_cache = fps
        _topology_cache = _build_topology_from_baseline(fps)
        print(f"[topology] baseline: {len(fps)} fingerprints, "
              f"{len(_topology_cache['nodes'])} nodes, "
              f"{len(_topology_cache['edges'])} edges")
        asyncio.create_task(_tail_otel_logs(environment))
        asyncio.create_task(_expire_anomalies())

    @app.get("/", response_class=HTMLResponse)
    async def _index():
        return HTMLResponse(html_file.read_text())

    @app.get("/api/topology")
    async def _get_topology():
        return JSONResponse({
            "environment": environment,
            "nodes":       _topology_cache.get("nodes", []),
            "edges":       _topology_cache.get("edges", []),
            "active":      {k: v for k, v in _active_anomalies.items() if v},
            "new_nodes":   list(_new_nodes.values()),
            "new_edges":   list(_new_edges),
        })

    @app.get("/api/clear")
    async def _clear():
        global _new_nodes, _new_edges
        _active_anomalies.clear()
        _new_nodes.clear()
        _new_edges.clear()
        payload = {"type": "state", "active": {}, "new_nodes": [], "new_edges": []}
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return JSONResponse({"ok": True})

    def _broadcast_event(event: dict) -> None:
        """Insert a synthetic event into the active state and broadcast to SSE subscribers."""
        global _new_nodes, _new_edges
        svc   = event.get("service", "")
        atype = event.get("anomaly_type", "")
        _active_anomalies[svc].append(event)
        if atype == "MISSING_SERVICE":
            caller = event.get("root_op", "").split(":")[0]
            if caller and caller != svc and caller not in _INFRA:
                # Caller gets TRACE DRIFT (not MISSING) — it's still running but
                # its dependency is gone, so its trace path changed.
                caller_event = dict(event,
                    service=caller,
                    anomaly_type="NEW_FINGERPRINT",
                    message=f"Trace path changed — {svc} no longer reachable from {caller}",
                )
                _active_anomalies[caller].append(caller_event)
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
        chain = _find_root_cause(_topology_cache, _active_anomalies)
        payload = {
            "type":            "drift",
            "event":           event,
            "active":          {k: v for k, v in _active_anomalies.items() if v},
            "causality_chain": chain,
            "root_cause":      chain[0] if chain else svc,
            "timestamp_ms":    event["timestamp_ms"],
            "new_nodes":       list(_new_nodes.values()),
            "new_edges":       list(_new_edges),
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
          anomaly_type  — MISSING_SERVICE | NEW_ERROR_SIGNATURE | NEW_FINGERPRINT
          service       — affected service name
          root_op       — root operation (e.g. "api-gateway:GET /owners")
          message       — human-readable description (optional)
          error_type    — for NEW_ERROR_SIGNATURE (optional)
          operation     — for NEW_ERROR_SIGNATURE (optional)
          missing_services — list of strings for MISSING_SERVICE (optional)
        """
        from fastapi import HTTPException
        valid_types = {"MISSING_SERVICE", "NEW_ERROR_SIGNATURE", "NEW_FINGERPRINT"}
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
        # 3. New error signature on pets-service
        "new-error": [
            {
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service":      "pets-service",
                "root_op":      "api-gateway:POST /owners/{ownerId}/pets",
                "error_type":   "DataAccessException",
                "operation":    "POST /owners/{ownerId}/pets",
                "message":      "New error: DataAccessException on POST /owners/{ownerId}/pets",
                "hash":         "synthetic:err:pets-DataAccessException",
            },
        ],
        # 4. DB caller no longer calls the DB (visits-service stops reaching mysql:petclinic)
        "db-dropped": [
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "mysql:petclinic",
                "root_op":          "api-gateway:POST /owners/{ownerId}/pets/{petId}/visits",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic absent — visits-service no longer writes to DB",
                "hash":             "synthetic:missing:mysql-petclinic-visits",
            },
        ],
        # Full incident: DB down → multiple callers affected
        "db-incident": [
            # First fire mysql:petclinic as MISSING so it enters `affected` and
            # the causality algorithm can identify it as the shared root cause.
            {
                "anomaly_type":     "MISSING_SERVICE",
                "service":          "mysql:petclinic",
                "root_op":          "api-gateway:GET /owners",
                "missing_services": ["mysql:petclinic"],
                "message":          "MISSING_SERVICE: mysql:petclinic unreachable — DB down",
                "hash":             "synthetic:missing:mysql-petclinic",
            },
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
                "service":      "pets-service",
                "root_op":      "api-gateway:GET /owners/{ownerId}/pets",
                "error_type":   "CannotGetJdbcConnectionException",
                "operation":    "SELECT pets",
                "message":      "New error: CannotGetJdbcConnectionException on SELECT pets",
                "hash":         "synthetic:err:pets-jdbc",
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
    }

    @app.get("/api/demo/{scenario}")
    async def _demo(scenario: str, delay_ms: int = 800):
        """Fire a named demo scenario, broadcasting events with delay_ms between them.

        Scenarios: kill-service | new-call-path | new-error | db-dropped | db-incident
        """
        from fastapi import HTTPException
        if scenario not in _DEMO_SCENARIOS:
            raise HTTPException(400, f"Unknown scenario. Valid: {list(_DEMO_SCENARIOS)}")
        events = _DEMO_SCENARIOS[scenario]

        async def _fire():
            for ev in events:
                full = {**ev, "timestamp_ms": int(time.time() * 1000)}
                _broadcast_event(full)
                if len(events) > 1:
                    await asyncio.sleep(delay_ms / 1000)

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
                snapshot = {
                    "type":   "state",
                    "active": {k: v for k, v in _active_anomalies.items() if v},
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
