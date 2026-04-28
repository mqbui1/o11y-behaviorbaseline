#!/usr/bin/env python3
"""
Behavioral Baseline — Infrastructure Correlator
================================================
When a service anomaly fires, the first on-call question is:
"Is this a code problem or a host problem?"

This module answers that by:
  1. Finding which k8s node(s) the affected service's pods run on
     (via Splunk dimension search on k8s.pod.name / k8s.node.name)
  2. Querying CPU and memory utilization for those nodes over the
     anomaly window using SignalFlow
  3. Returning a structured summary for injection into the Claude prompt

Output injected into triage_agent.py:
  "## Infrastructure Context
   vets-service runs on node k3d-...agent-1
   - CPU: 78% (elevated — normal ~15%)
   - Memory: 62% (normal)
   Hypothesis: host CPU pressure may be contributing to latency."

Usage (standalone):
  python agents/infra_correlator.py --service vets-service --environment petclinictest-2d77-workshop

Usage (from triage_agent.py):
  from agents.infra_correlator import correlate_infra
  result = correlate_infra("vets-service", "petclinictest-2d77-workshop", window_minutes=10)

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM  (default: us1)
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
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
REALM        = os.environ.get("SPLUNK_REALM", "us1")

BASE_URL   = f"https://api.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Thresholds for "elevated" classification
CPU_ELEVATED_PCT    = 70.0   # % — above this = elevated
MEMORY_ELEVATED_PCT = 85.0   # % — above this = elevated
CPU_CRITICAL_PCT    = 90.0
MEMORY_CRITICAL_PCT = 95.0

DEFAULT_WINDOW_MINUTES = 10


# ── API helpers ───────────────────────────────────────────────────────────────

def _request(path: str, params: dict | None = None) -> Any:
    url = BASE_URL + path
    if params:
        qs = "&".join(f"{k}={urllib.parse.quote(str(v))}" for k, v in params.items())
        url += "?" + qs
    req = urllib.request.Request(
        url,
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"  [infra] API {path}: {e}", file=sys.stderr)
        return None


def _run_signalflow(program: str, start_ms: int, end_ms: int,
                    timeout: float = 15.0) -> list[dict]:
    """Execute a SignalFlow data() program, return all messages."""
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true&resolution=60000")
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
                    results.append(msg)
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [infra] SignalFlow: {e}", file=sys.stderr)
    return results


def _extract_mean(messages: list[dict]) -> float | None:
    values = []
    for msg in messages:
        if msg.get("type") == "data":
            for v in msg.get("data", {}).values():
                if isinstance(v, (int, float)) and v >= 0:
                    values.append(float(v))
    return sum(values) / len(values) if values else None


def _extract_max(messages: list[dict]) -> float | None:
    values = []
    for msg in messages:
        if msg.get("type") == "data":
            for v in msg.get("data", {}).values():
                if isinstance(v, (int, float)) and v >= 0:
                    values.append(float(v))
    return max(values) if values else None


# ── Node discovery ────────────────────────────────────────────────────────────

def _find_nodes_for_service(service: str, environment: str | None,
                             window_minutes: int) -> list[str]:
    """
    Find k8s node names hosting pods for the given service.

    Strategy: search Splunk dimensions for k8s.pod.name where
    k8s.deployment.name or sf_service matches the service name,
    then extract the k8s.node.name property from those MTS.
    Falls back to SignalFlow if dimension search returns nothing.
    """
    import urllib.parse

    nodes: set[str] = set()

    # Strategy 1: dimension search for pods matching the service
    query = f"sf_service:{service}"
    if environment:
        query += f" AND deployment.environment:{environment}"

    resp = _request("/v2/dimension", {
        "query": query,
        "limit": "20",
        "type":  "k8s.pod.name",
    })
    if resp and "results" in resp:
        for dim in resp["results"]:
            node = dim.get("customProperties", {}).get("k8s.node.name") or \
                   dim.get("properties", {}).get("k8s.node.name")
            if node:
                nodes.add(node)

    # Strategy 2: if strategy 1 found nothing, query via k8s.deployment.name dimension
    if not nodes:
        resp2 = _request("/v2/dimension", {
            "query": f"k8s.deployment.name:{service}",
            "limit": "20",
            "type":  "k8s.pod.name",
        })
        if resp2 and "results" in resp2:
            for dim in resp2["results"]:
                node = dim.get("customProperties", {}).get("k8s.node.name") or \
                       dim.get("properties", {}).get("k8s.node.name")
                if node:
                    nodes.add(node)

    # Strategy 3: SignalFlow — find node names from container CPU metric
    if not nodes:
        now_ms   = int(time.time() * 1000)
        start_ms = now_ms - window_minutes * 60 * 1000
        svc_filter = f"filter('k8s.deployment.name', '{service}')"
        program = (
            f"data('k8s.pod.cpu.utilization', filter={svc_filter})"
            f".dimensions('k8s.node.name').publish()"
        )
        msgs = _run_signalflow(program, start_ms, now_ms, timeout=10.0)
        for msg in msgs:
            if msg.get("type") == "metadata":
                node = msg.get("properties", {}).get("k8s.node.name")
                if node:
                    nodes.add(node)

    return sorted(nodes)


# ── Node metric queries ───────────────────────────────────────────────────────

def _query_node_cpu(node: str, start_ms: int, end_ms: int) -> float | None:
    """Query mean CPU utilization % for a node over the window."""
    program = (
        f"data('k8s.node.cpu.utilization', filter=filter('k8s.node.name', '{node}'))"
        f".mean().scale(100).publish()"
    )
    msgs = _run_signalflow(program, start_ms, end_ms)
    val  = _extract_mean(msgs)
    # Also try host.cpu.utilization (some OTel configs emit this)
    if val is None:
        program2 = (
            f"data('cpu.utilization', filter=filter('host.name', '{node}'))"
            f".mean().scale(100).publish()"
        )
        msgs2 = _run_signalflow(program2, start_ms, end_ms)
        val   = _extract_mean(msgs2)
    return round(val, 1) if val is not None else None


def _query_node_memory(node: str, start_ms: int, end_ms: int) -> float | None:
    """Query mean memory utilization % for a node over the window."""
    program = (
        f"data('k8s.node.memory.utilization', filter=filter('k8s.node.name', '{node}'))"
        f".mean().scale(100).publish()"
    )
    msgs = _run_signalflow(program, start_ms, end_ms)
    val  = _extract_mean(msgs)
    if val is None:
        # Fallback: compute from working_set / capacity
        for metric in ["k8s.node.memory.working_set", "k8s.node.memory.usage"]:
            program2 = (
                f"A = data('{metric}', filter=filter('k8s.node.name', '{node}')).mean()\n"
                f"B = data('k8s.node.memory.limit', filter=filter('k8s.node.name', '{node}')).mean()\n"
                f"(A / B).scale(100).publish()"
            )
            msgs2 = _run_signalflow(program2, start_ms, end_ms)
            val   = _extract_mean(msgs2)
            if val is not None:
                break
    return round(val, 1) if val is not None else None


def _query_node_pod_count(node: str, start_ms: int, end_ms: int) -> int | None:
    """Query number of running pods on the node."""
    program = (
        f"data('k8s.node.condition_ready', filter=filter('k8s.node.name', '{node}'))"
        f".publish()"
    )
    # Use pod count metric if available
    program = (
        f"data('k8s.pod.phase', filter=filter('k8s.node.name', '{node}')"
        f" and filter('phase', 'Running')).count().publish()"
    )
    msgs = _run_signalflow(program, start_ms, end_ms)
    val  = _extract_mean(msgs)
    return int(val) if val is not None else None


# ── Main entry point ──────────────────────────────────────────────────────────

def correlate_infra(service: str, environment: str | None,
                    window_minutes: int = DEFAULT_WINDOW_MINUTES) -> dict:
    """
    Correlate service anomaly with host/node infrastructure metrics.

    Returns:
      {
        "nodes":        ["node-name", ...],
        "metrics":      {node: {cpu_pct, memory_pct, status}},
        "verdict":      "host_issue" | "host_ok" | "no_data",
        "one_liner":    "vets-service node at 91% CPU — likely host pressure",
        "prompt_block": "## Infrastructure Context\n...",
      }
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    # Step 1: find nodes
    nodes = _find_nodes_for_service(service, environment, window_minutes)
    if not nodes:
        return {
            "nodes":       [],
            "metrics":     {},
            "verdict":     "no_data",
            "one_liner":   f"No k8s node data found for {service}",
            "prompt_block": "",
        }

    # Step 2: query CPU + memory for all nodes in parallel
    metrics: dict[str, dict] = {}

    def _fetch_node(node: str) -> tuple[str, dict]:
        cpu = _query_node_cpu(node, start_ms, now_ms)
        mem = _query_node_memory(node, start_ms, now_ms)
        return node, {"cpu_pct": cpu, "memory_pct": mem}

    with ThreadPoolExecutor(max_workers=len(nodes)) as pool:
        for node, m in pool.map(_fetch_node, nodes):
            metrics[node] = m

    # Step 3: classify
    host_issue = False
    elevated_signals: list[str] = []

    for node, m in metrics.items():
        cpu = m.get("cpu_pct")
        mem = m.get("memory_pct")
        short = node.split("-")[-1] if "-" in node else node   # last segment for readability

        if cpu is not None and cpu >= CPU_ELEVATED_PCT:
            level = "critical" if cpu >= CPU_CRITICAL_PCT else "elevated"
            elevated_signals.append(f"node {short}: CPU {cpu}% ({level})")
            host_issue = True
        if mem is not None and mem >= MEMORY_ELEVATED_PCT:
            level = "critical" if mem >= MEMORY_CRITICAL_PCT else "elevated"
            elevated_signals.append(f"node {short}: memory {mem}% ({level})")
            host_issue = True

    verdict = "host_issue" if host_issue else (
        "no_data" if all(
            m.get("cpu_pct") is None and m.get("memory_pct") is None
            for m in metrics.values()
        ) else "host_ok"
    )

    # Step 4: build one_liner
    if verdict == "host_issue":
        one_liner = f"{service} host pressure: {'; '.join(elevated_signals)}"
    elif verdict == "host_ok":
        # Summarise normal values
        parts = []
        for node, m in metrics.items():
            short = node.split("-")[-1] if "-" in node else node
            if m.get("cpu_pct") is not None:
                parts.append(f"node {short}: CPU {m['cpu_pct']}%, mem {m.get('memory_pct', 'n/a')}%")
        one_liner = f"{service} host healthy — {'; '.join(parts)}"
    else:
        one_liner = f"No node metrics available for {service}"

    # Step 5: build prompt block
    lines = ["## Infrastructure Context"]
    lines.append(f"Service `{service}` runs on: {', '.join(nodes)}")
    lines.append("")

    any_data = False
    for node, m in metrics.items():
        cpu = m.get("cpu_pct")
        mem = m.get("memory_pct")
        if cpu is None and mem is None:
            continue
        any_data = True
        cpu_str = f"{cpu}%" if cpu is not None else "n/a"
        mem_str = f"{mem}%" if mem is not None else "n/a"
        cpu_flag = " ⚠ ELEVATED" if (cpu or 0) >= CPU_ELEVATED_PCT else ""
        mem_flag = " ⚠ ELEVATED" if (mem or 0) >= MEMORY_ELEVATED_PCT else ""
        lines.append(f"**{node}**")
        lines.append(f"- CPU utilization: {cpu_str}{cpu_flag}")
        lines.append(f"- Memory utilization: {mem_str}{mem_flag}")

    if not any_data:
        lines.append("No node metric data available (node metrics may not be collected).")

    if verdict == "host_issue":
        lines += [
            "",
            f"**Host pressure detected.** Consider whether the infrastructure is the "
            f"root cause before assuming a code or dependency issue.",
        ]
    elif verdict == "host_ok":
        lines += [
            "",
            "Host resources are within normal range — infra is likely not the cause.",
        ]

    prompt_block = "\n".join(lines) if any_data else ""

    return {
        "nodes":        nodes,
        "metrics":      metrics,
        "verdict":      verdict,
        "one_liner":    one_liner,
        "prompt_block": prompt_block,
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    if not ACCESS_TOKEN:
        print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service",     required=True)
    parser.add_argument("--environment", default=None)
    parser.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES)
    args = parser.parse_args()

    result = correlate_infra(args.service, args.environment, args.window_minutes)
    print(f"Verdict : {result['verdict']}")
    print(f"Nodes   : {result['nodes']}")
    print(f"One-liner: {result['one_liner']}")
    if result["prompt_block"]:
        print()
        print(result["prompt_block"])
    else:
        print("(no metric data returned)")


if __name__ == "__main__":
    # Need urllib.parse for _find_nodes_for_service
    import urllib.parse
    main()
