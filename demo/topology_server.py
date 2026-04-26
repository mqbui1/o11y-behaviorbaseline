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

_INFRA = {"discovery-server", "config-server", "eureka-server", "eureka"}

# ── In-memory state ───────────────────────────────────────────────────────────
# Active anomalies: service -> list of anomaly dicts (cleared after ANOMALY_TTL)
_active_anomalies: dict[str, list[dict]] = defaultdict(list)
ANOMALY_TTL = 300  # seconds — anomalies auto-clear after 5 minutes

# SSE subscriber queues
_subscribers: list[asyncio.Queue] = []

# Topology + baseline cache
_topology_cache: dict = {}
_baseline_cache: dict = {}


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
        for p in parts:
            svc = p.split(":")[0] if ":" in p else p
            if not svcs or svcs[-1] != svc:
                svcs.append(svc)
        for svc in svcs:
            node_traffic[svc] += occ
        for i in range(len(svcs) - 1):
            edge_weights[(svcs[i], svcs[i + 1])] += occ

    upstream:   dict[str, list[str]] = defaultdict(list)
    downstream: dict[str, list[str]] = defaultdict(list)
    for (src, dst) in edge_weights:
        downstream[src].append(dst)
        upstream[dst].append(src)

    nodes = [{"id": svc, "traffic": traffic}
             for svc, traffic in sorted(node_traffic.items(), key=lambda x: -x[1])
             if svc not in _INFRA]
    edges = [{"source": src, "target": dst, "weight": w}
             for (src, dst), w in sorted(edge_weights.items(), key=lambda x: -x[1])
             if src not in _INFRA and dst not in _INFRA]

    return {
        "nodes":      nodes,
        "edges":      edges,
        "upstream":   dict(upstream),
        "downstream": dict(downstream),
    }


def _find_root_cause(affected_service: str, topology: dict,
                     active: dict[str, list[dict]]) -> list[str]:
    """
    Traverse the dependency graph upstream from affected_service.
    Returns the causality chain as an ordered list: [root_cause, ..., affected_service]

    Algorithm:
      1. Walk downstream dependencies of affected_service
      2. If any dependency also has active anomalies, recurse into it
      3. The deepest node with anomalies and no anomalous dependencies is root cause
    """
    downstream = topology.get("downstream", {})

    def _find(svc: str, visited: set) -> list[str]:
        if svc in visited:
            return [svc]
        visited.add(svc)
        # Check if any callees also have anomalies
        for dep in downstream.get(svc, []):
            if dep in _INFRA:
                continue
            if active.get(dep):
                chain = _find(dep, visited)
                return chain + [svc] if chain[-1] != svc else chain
        return [svc]  # this node is the root cause

    chain = _find(affected_service, set())
    # Prepend any services that call into affected_service and are also affected
    upstream = topology.get("upstream", {})
    callers_affected = [c for c in upstream.get(affected_service, [])
                        if active.get(c) and c not in _INFRA and c not in chain]
    return chain + callers_affected


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
            "timestamp_ms": int(time.time() * 1000),
        }


# ── SSH log tail (background task) ───────────────────────────────────────────

async def _tail_otel_logs(environment: str) -> None:
    """Background task: tail OTel collector pod logs and broadcast drift events."""
    global _active_anomalies

    ssh_cmd = (
        "exec bash -c '"
        f"for p in $(kubectl get pods -l {DAEMONSET_LABEL} -o jsonpath=\"{{.items[*].metadata.name}}\");"
        f" do kubectl logs -f --since=5s $p -c {OTEL_CONTAINER} 2>/dev/null & done;"
        " tail -f /dev/null'"
    )
    proc = await asyncio.create_subprocess_exec(
        "sshpass", f"-p{EC2_PASS}",
        "ssh", "-T", "-p", EC2_PORT,
        "-o", "StrictHostKeyChecking=no",
        "-o", "RequestTTY=no",
        f"splunk@{EC2_IP}",
        ssh_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )

    seen_hashes: dict[str, float] = {}
    DEDUP_TTL = 90

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

        print(f"[topology] event: {atype} on {svc}", flush=True)

        # Update active anomalies
        _active_anomalies[svc].append(event)

        # Build causality chain
        chain = _find_root_cause(svc, _topology_cache, _active_anomalies)

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

    print("[topology] SSH process ended — log tail stopped", flush=True)


async def _expire_anomalies() -> None:
    """Background task: expire old anomalies and broadcast cleared state."""
    while True:
        await asyncio.sleep(10)
        now_ms = time.time() * 1000
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
        })

    @app.get("/api/clear")
    async def _clear():
        _active_anomalies.clear()
        payload = {"type": "state", "active": {}}
        for q in _subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return JSONResponse({"ok": True})

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
