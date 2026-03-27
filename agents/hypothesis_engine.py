#!/usr/bin/env python3
"""
Behavioral Baseline — Root Cause Hypothesis Engine
====================================================
Walks the service dependency graph when a correlated anomaly fires and
produces a ranked list of root cause hypotheses before Claude is called.

Used by triage_agent.py to enrich context. Can also run standalone.

Algorithm:
  1. Fetch live topology graph (edges = caller → callee)
  2. For the affected service, find: upstream callers, downstream callees,
     and shared dependencies (nodes with multiple affected callers)
  3. Gather anomaly signals per graph node from recent events
  4. Score each candidate root cause by how many affected services it explains
  5. Return ranked hypotheses with evidence for Claude to reason over

Usage:
  python hypothesis_engine.py --environment petclinicmbtest --service api-gateway
  python hypothesis_engine.py --environment petclinicmbtest --service api-gateway --window-minutes 30
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
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent.parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# How many hops to walk in each direction from the affected service
MAX_GRAPH_DEPTH = 3

# Anomaly event types that carry service-level signals
ANOMALY_EVENT_TYPES = ["trace.path.drift", "error.signature.drift"]

# db/infra keywords for shared-dependency detection
_DB_KEYWORDS = {
    "mysql", "postgres", "postgresql", "mongodb", "redis", "cassandra",
    "elasticsearch", "dynamo", "sqlite", "oracle", "sqlserver", "mssql",
    "mariadb", "cockroach", "config", "discovery", "eureka", "consul",
    "zookeeper", "kafka", "rabbitmq", "activemq",
}


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL, timeout: float = 30.0) -> Any:
    url     = f"{base_url}{path}"
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"API {e.code}: {raw[:200]}")


def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 12.0) -> list[dict]:
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url, data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data_lines: list[str] = []
            for raw_line in resp:
                line     = raw_line.decode()
                stripped = line.strip()
                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    payload    = "".join(data_lines)
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
        print(f"  [warn] SignalFlow {event_type}: {e}", file=sys.stderr)
    return results


# ── Topology graph ─────────────────────────────────────────────────────────────

def fetch_topology(environment: str | None,
                   lookback_hours: int = 2) -> dict:
    """
    Fetch the live service dependency graph.
    Returns {
      edges: [(caller, callee), ...],
      upstream:   {service: [callers]},
      downstream: {service: [callees]},
      shared_deps: {dep: [callers]}  # nodes called by 2+ services
    }
    """
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - lookback_hours * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [{"name": "sf_environment", "operator": "equals",
                               "value": environment, "scope": "global"}]
    try:
        result = _request("POST", "/v2/apm/topology", body)
    except Exception as e:
        print(f"  [warn] topology fetch: {e}", file=sys.stderr)
        return {"edges": [], "upstream": {}, "downstream": {}, "shared_deps": {}}

    edges_raw = (result.get("data") or {}).get("edges", [])
    edges = [(e["fromNode"], e["toNode"]) for e in edges_raw
             if e["fromNode"] != e["toNode"]]

    upstream:   dict[str, list[str]] = defaultdict(list)
    downstream: dict[str, list[str]] = defaultdict(list)
    callers_of: dict[str, list[str]] = defaultdict(list)

    for caller, callee in edges:
        downstream[caller].append(callee)
        upstream[callee].append(caller)
        callers_of[callee].append(caller)

    # Shared dependencies: nodes called by 2+ distinct services
    shared_deps = {
        dep: callers
        for dep, callers in callers_of.items()
        if len(set(callers)) >= 2
    }

    return {
        "edges":       edges,
        "upstream":    dict(upstream),
        "downstream":  dict(downstream),
        "shared_deps": shared_deps,
    }


def walk_graph(service: str, topology: dict,
               max_depth: int = MAX_GRAPH_DEPTH) -> dict:
    """
    BFS from the affected service in both directions.
    Returns {
      affected_upstream:   [services that call into the affected service],
      affected_downstream: [services the affected service calls],
      reachable:           set of all reachable nodes within max_depth,
      shared_deps_in_blast_radius: {dep: [affected callers]}
    }
    """
    downstream = topology["downstream"]
    upstream   = topology["upstream"]

    # Walk downstream (callees)
    visited_down: set[str] = set()
    frontier = [service]
    for _ in range(max_depth):
        next_frontier = []
        for svc in frontier:
            for callee in downstream.get(svc, []):
                if callee not in visited_down:
                    visited_down.add(callee)
                    next_frontier.append(callee)
        frontier = next_frontier

    # Walk upstream (callers)
    visited_up: set[str] = set()
    frontier = [service]
    for _ in range(max_depth):
        next_frontier = []
        for svc in frontier:
            for caller in upstream.get(svc, []):
                if caller not in visited_up:
                    visited_up.add(caller)
                    next_frontier.append(caller)
        frontier = next_frontier

    reachable = visited_down | visited_up | {service}

    # Shared deps within blast radius
    shared_in_blast: dict[str, list[str]] = {}
    for dep, callers in topology["shared_deps"].items():
        callers_in_blast = [c for c in callers if c in reachable]
        if len(set(callers_in_blast)) >= 2:
            shared_in_blast[dep] = callers_in_blast

    return {
        "affected_upstream":               sorted(visited_up),
        "affected_downstream":             sorted(visited_down),
        "reachable":                       reachable,
        "shared_deps_in_blast_radius":     shared_in_blast,
    }


# ── Anomaly signal gathering ───────────────────────────────────────────────────

def gather_node_signals(services: set[str], start_ms: int, end_ms: int,
                        environment: str | None) -> dict[str, dict]:
    """
    For each service in the graph, collect which anomaly types fired recently.
    Returns {service: {anomaly_types: [str], event_count: int, messages: [str]}}
    """
    node_signals: dict[str, dict] = defaultdict(
        lambda: {"anomaly_types": set(), "event_count": 0, "messages": []}
    )

    def _fetch(event_type: str) -> list[dict]:
        return _signalflow_events(event_type, start_ms, end_ms)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {pool.submit(_fetch, et): et for et in ANOMALY_EVENT_TYPES}
        for future in as_completed(futures):
            for msg in future.result():
                dims  = msg.get("metadata", {})
                props = msg.get("properties", {})
                event_env = dims.get("environment") or props.get("environment", "all")
                if environment and event_env not in (environment, "all"):
                    continue

                # Extract service
                svc = (
                    dims.get("service")
                    or props.get("service")
                    or (dims.get("root_operation", "").split(":")[0]
                        if ":" in dims.get("root_operation", "") else None)
                    or (props.get("services", "").split(",")[0].strip() or None)
                )
                if not svc or svc not in services:
                    continue

                atype = dims.get("anomaly_type", futures[future])
                node_signals[svc]["anomaly_types"].add(atype)
                node_signals[svc]["event_count"] += 1
                msg_text = props.get("message", "")
                if msg_text and msg_text not in node_signals[svc]["messages"]:
                    node_signals[svc]["messages"].append(msg_text)

    # Freeze sets to sorted lists
    return {
        svc: {
            "anomaly_types": sorted(s["anomaly_types"]),
            "event_count":   s["event_count"],
            "messages":      s["messages"][:3],
        }
        for svc, s in node_signals.items()
    }


# ── Hypothesis generation ──────────────────────────────────────────────────────

def _is_infra(service: str) -> bool:
    s = service.lower()
    return any(k in s for k in _DB_KEYWORDS)


def generate_hypotheses(service: str, graph: dict, signals: dict[str, dict],
                        corr: dict) -> list[dict]:
    """
    Produce a ranked list of root cause hypotheses.
    Each hypothesis: {rank, candidate, hypothesis_type, evidence, explains_services, confidence}

    hypothesis_type values:
      SHARED_DEPENDENCY  — a common dep (DB, config) explains multi-service impact
      DOWNSTREAM_FAILURE — a service the affected node calls is down/degraded
      UPSTREAM_CHANGE    — a caller changed behavior and is sending bad traffic
      SELF_CHANGE        — the affected service itself changed (deployment, config)
      CASCADING_FAILURE  — chain of failures spreading from one node
    """
    hypotheses: list[dict] = []

    downstream = graph["affected_downstream"]
    upstream   = graph["affected_upstream"]
    shared     = graph["shared_deps_in_blast_radius"]
    deployment = corr.get("deployment")
    anomaly_types = set(corr.get("anomaly_types", []))

    # ── H1: Shared dependency failure ─────────────────────────────────────────
    for dep, callers in shared.items():
        dep_signals = signals.get(dep, {})
        caller_signals = [c for c in callers if c in signals]
        explains = sorted(set(callers) | {service})

        evidence = []
        if dep_signals.get("anomaly_types"):
            evidence.append(
                f"{dep} has its own anomalies: "
                f"{', '.join(dep_signals['anomaly_types'])}"
            )
        if "MISSING_SERVICE" in anomaly_types:
            evidence.append(
                f"MISSING_SERVICE detected — {dep} may be unreachable"
            )
        for caller in caller_signals:
            s = signals[caller]
            evidence.append(
                f"{caller} also affected: {', '.join(s['anomaly_types'])}"
            )
        if not evidence:
            evidence.append(
                f"{dep} is a shared dependency of {len(explains)} affected services"
            )

        # Confidence: higher if dep has its own signals or is infra
        confidence = "High" if dep_signals.get("event_count", 0) > 0 else "Medium"
        if len(explains) >= 3:
            confidence = "High"

        hypotheses.append({
            "hypothesis_type": "SHARED_DEPENDENCY",
            "candidate":       dep,
            "summary":         (
                f"{dep} is a shared dependency of {len(explains)} affected service(s). "
                f"Its failure would explain anomalies across all of them."
            ),
            "evidence":        evidence,
            "explains_services": explains,
            "confidence":      confidence,
        })

    # ── H2: Downstream service failure ────────────────────────────────────────
    missing_svcs = set()
    for msg in corr.get("messages", []):
        if "absent" in msg.lower() or "missing" in msg.lower():
            # Extract service names from "Expected service(s) absent from ...: ['x']"
            import re
            found = re.findall(r"'([a-z0-9_\-]+)'", msg)
            missing_svcs.update(found)

    for dep in downstream:
        dep_signals = signals.get(dep, {})
        is_missing  = dep in missing_svcs
        is_degraded = dep_signals.get("event_count", 0) > 0

        if not (is_missing or is_degraded):
            continue

        evidence = []
        if is_missing:
            evidence.append(f"{dep} not appearing in traces (MISSING_SERVICE)")
        if dep_signals.get("anomaly_types"):
            evidence.append(
                f"{dep} has anomalies: {', '.join(dep_signals['anomaly_types'])}"
            )
        evidence.append(
            f"{service} calls {dep} — its failure would cause "
            f"new execution paths (NEW_FINGERPRINT) in {service}"
        )

        hypotheses.append({
            "hypothesis_type": "DOWNSTREAM_FAILURE",
            "candidate":       dep,
            "summary":         (
                f"{dep} (downstream of {service}) appears to be down or degraded. "
                f"{service} is executing fallback paths in response."
            ),
            "evidence":        evidence,
            "explains_services": [service, dep],
            "confidence":      "High" if is_missing else "Medium",
        })

    # ── H3: Deployment / self-change ──────────────────────────────────────────
    if deployment and (deployment.get("version") or deployment.get("commit")):
        ver = deployment.get("version") or deployment.get("commit") or "unknown"
        evidence = [
            f"Deployment of {service} version {ver} correlated with anomaly onset",
            f"NEW_FINGERPRINT signals consistent with changed routing/code paths",
        ]
        if deployment.get("deployer"):
            evidence.append(f"Deployed by: {deployment['deployer']}")
        if deployment.get("desc"):
            evidence.append(f"Description: {deployment['desc']}")

        hypotheses.append({
            "hypothesis_type": "SELF_CHANGE",
            "candidate":       service,
            "summary":         (
                f"A deployment of {service} (version {ver}) is the most likely cause. "
                f"Timing correlates directly with the anomaly onset."
            ),
            "evidence":        evidence,
            "explains_services": [service],
            "confidence":      "High",
        })
    elif "NEW_FINGERPRINT" in anomaly_types and not downstream:
        # Service changed itself with no downstream failures
        hypotheses.append({
            "hypothesis_type": "SELF_CHANGE",
            "candidate":       service,
            "summary":         (
                f"{service} is executing new internal code paths not seen in baseline. "
                f"Likely a config change, feature flag flip, or untracked deployment."
            ),
            "evidence":        [
                "NEW_FINGERPRINT without MISSING_SERVICE — no downstream failures",
                "Traces terminate at service boundary with new paths",
            ],
            "explains_services": [service],
            "confidence":      "Medium",
        })

    # ── H4: Upstream change sending bad/new traffic ────────────────────────────
    for caller in upstream:
        caller_sigs = signals.get(caller, {})
        if "NEW_FINGERPRINT" not in caller_sigs.get("anomaly_types", []):
            continue
        hypotheses.append({
            "hypothesis_type": "UPSTREAM_CHANGE",
            "candidate":       caller,
            "summary":         (
                f"{caller} (upstream of {service}) changed its call patterns. "
                f"It may be sending new request types that {service} isn't handling correctly."
            ),
            "evidence":        [
                f"{caller} has NEW_FINGERPRINT anomalies",
                f"{caller} → {service} edge in dependency graph",
            ] + caller_sigs.get("messages", [])[:2],
            "explains_services": [service, caller],
            "confidence":      "Low",
        })

    # ── H5: Cascading failure ─────────────────────────────────────────────────
    affected_nodes = [s for s in signals if signals[s]["event_count"] > 0]
    if len(affected_nodes) >= 3:
        # Find the node with most downstream affected services
        max_explains = 0
        cascade_root = None
        for node in affected_nodes:
            # How many other affected nodes are downstream of this one?
            node_down = set(graph.get("affected_downstream", []))
            explained = len([a for a in affected_nodes if a in node_down or a == node])
            if explained > max_explains:
                max_explains = explained
                cascade_root = node

        if cascade_root and cascade_root != service:
            hypotheses.append({
                "hypothesis_type": "CASCADING_FAILURE",
                "candidate":       cascade_root,
                "summary":         (
                    f"Failure may have originated at {cascade_root} and cascaded "
                    f"downstream. {len(affected_nodes)} services show anomalies."
                ),
                "evidence":        [
                    f"{len(affected_nodes)} services affected: "
                    f"{', '.join(sorted(affected_nodes))}",
                    f"{cascade_root} is upstream of most affected services",
                ],
                "explains_services": sorted(affected_nodes),
                "confidence":      "Medium",
            })

    # ── Rank by: confidence, then explains_services count ─────────────────────
    conf_order = {"High": 0, "Medium": 1, "Low": 2}
    hypotheses.sort(key=lambda h: (
        conf_order.get(h["confidence"], 9),
        -len(h["explains_services"]),
    ))
    for i, h in enumerate(hypotheses, 1):
        h["rank"] = i

    return hypotheses


# ── Main entry point ───────────────────────────────────────────────────────────

def analyze(service: str, corr: dict, environment: str | None,
            window_minutes: int = 30) -> dict:
    """
    Full hypothesis analysis for a correlated anomaly.
    Returns {topology, graph, signals, hypotheses} — ready for Claude.

    corr: the correlated anomaly dict (same schema as correlate.py output or
          triage_agent's fetch_correlated_anomaly_events result)
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    print(f"  [hypothesis] Fetching topology...")
    topology = fetch_topology(environment, lookback_hours=2)

    print(f"  [hypothesis] Walking dependency graph from '{service}'...")
    graph = walk_graph(service, topology)

    all_nodes = graph["reachable"]
    print(f"  [hypothesis] Graph: {len(graph['affected_upstream'])} upstream, "
          f"{len(graph['affected_downstream'])} downstream, "
          f"{len(graph['shared_deps_in_blast_radius'])} shared deps")

    print(f"  [hypothesis] Gathering anomaly signals for {len(all_nodes)} nodes...")
    signals = gather_node_signals(all_nodes, start_ms, now_ms, environment)
    print(f"  [hypothesis] {len(signals)} nodes have anomaly signals")

    hypotheses = generate_hypotheses(service, graph, signals, corr)
    print(f"  [hypothesis] Generated {len(hypotheses)} hypotheses")

    return {
        "topology_summary": {
            "total_services": len(topology["edges"]),
            "upstream":       graph["affected_upstream"],
            "downstream":     graph["affected_downstream"],
            "shared_deps":    list(graph["shared_deps_in_blast_radius"].keys()),
        },
        "node_signals": signals,
        "hypotheses":   hypotheses,
    }


def format_for_prompt(analysis: dict) -> str:
    """
    Format hypothesis analysis as a markdown section for the Claude prompt.
    """
    lines = ["## Dependency Graph Analysis", ""]

    topo = analysis["topology_summary"]
    if topo["upstream"]:
        lines.append(f"**Upstream callers:** {', '.join(topo['upstream'])}")
    if topo["downstream"]:
        lines.append(f"**Downstream callees:** {', '.join(topo['downstream'])}")
    if topo["shared_deps"]:
        lines.append(f"**Shared dependencies:** {', '.join(topo['shared_deps'])}")

    signals = analysis["node_signals"]
    if signals:
        lines += ["", "**Anomaly signals across graph:**"]
        for svc, s in sorted(signals.items(), key=lambda x: -x[1]["event_count"]):
            lines.append(
                f"- {svc}: {s['event_count']} events "
                f"({', '.join(s['anomaly_types'])})"
            )

    lines += ["", "## Root Cause Hypotheses (ranked)"]
    for h in analysis["hypotheses"]:
        lines += [
            "",
            f"### #{h['rank']} [{h['confidence']}] {h['hypothesis_type']} — {h['candidate']}",
            h["summary"],
            f"Explains: {', '.join(h['explains_services'])}",
            "Evidence:",
        ]
        for ev in h["evidence"]:
            lines.append(f"- {ev}")

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Root Cause Hypothesis Engine — graph-aware incident analysis"
    )
    parser.add_argument("--service",     required=True,
                        help="Primary affected service (e.g. api-gateway)")
    parser.add_argument("--environment", default=None)
    parser.add_argument("--window-minutes", type=int, default=30)
    args = parser.parse_args()

    # Minimal corr dict for standalone use
    corr = {
        "service":      args.service,
        "anomaly_types": [],
        "messages":     [],
        "deployment":   None,
    }
    result = analyze(args.service, corr, args.environment, args.window_minutes)
    print()
    print(format_for_prompt(result))


if __name__ == "__main__":
    main()
