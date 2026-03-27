#!/usr/bin/env python3
"""
Behavioral Baseline — Drift Explainer
======================================
Explains *why* a trace path changed in plain English, edge by edge.

When trace_fingerprint.py fires NEW_FINGERPRINT or SIGNATURE_VANISHED,
you get a hash diff but no explanation. This agent bridges that gap:

  Before: "New fingerprint abc123 detected for api-gateway:GET vets-service"
  After:  "api-gateway:GET vets-service now routes through discovery-server
            before reaching vets-service. This edge (api-gateway:GET →
            discovery-server:GET /eureka/apps/vets-service) did not exist in
            baseline. Likely a Eureka re-registration triggered by a restart,
            or a new load-balancing retry path added in the latest deploy."

How it works:
  1. Load stored baseline fingerprints for a service
  2. Sample recent live traces and fingerprint them
  3. Diff: identify added edges, removed edges, span count delta
  4. For drifted fingerprints: call Claude (Bedrock) with edge-level diff
     and full context (topology, deployment events, anomaly history)
  5. Emit plain-English explanation as Splunk custom event + stdout

Usage:
  python drift_explainer.py --service api-gateway --environment petclinicmbtest
  python drift_explainer.py --service vets-service --environment petclinicmbtest --window-minutes 30
  python drift_explainer.py --environment petclinicmbtest  # explain ALL drifted services

  # Dry run (no events emitted, no Bedrock call):
  python drift_explainer.py --service api-gateway --environment petclinicmbtest --dry-run

  # Skip Claude explanation, just print the structural diff:
  python drift_explainer.py --service api-gateway --environment petclinicmbtest --diff-only

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)

Optional:
  AWS_REGION                (default: us-west-2, for Bedrock)
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

AWS_REGION   = os.environ.get("AWS_REGION", "us-west-2")
_BEDROCK_MODEL = "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7"

# Trace sampling window for live fingerprints
DEFAULT_WINDOW_MINUTES = 20
# Max traces to sample for diff
TRACES_SAMPLE_LIMIT = 150
# Similarity threshold — fingerprints sharing > this fraction of edges are
# considered "same path variant" rather than completely new
SIMILARITY_THRESHOLD = 0.5
# Recent deployment lookback for context
DEPLOY_LOOKBACK_HOURS = 6


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL, timeout: float = 20.0) -> Any:
    url     = f"{base_url}{path}"
    token   = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"API {e.code}: {raw[:200]}")


# ── Import trace_fingerprint internals ────────────────────────────────────────

# We reuse the fingerprinting logic without re-implementing it
_TF_DIR = Path(__file__).parent
sys.path.insert(0, str(_TF_DIR))
try:
    from trace_fingerprint import (
        build_fingerprint,
        discover_topology,
        search_traces,
        get_trace_full,
        load_baseline,
        _is_noise_trace,
    )
    _TF_AVAILABLE = True
except ImportError as _e:
    print(f"  [warn] trace_fingerprint import failed: {_e}", file=sys.stderr)
    _TF_AVAILABLE = False


# ── Bedrock / Claude ──────────────────────────────────────────────────────────

def _bedrock_request(messages: list[dict], system: str = "") -> str:
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 not installed")
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "messages": messages,
    }
    if system:
        body["system"] = system
    resp = client.invoke_model(
        modelId=_BEDROCK_MODEL,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json",
    )
    result = json.loads(resp["body"].read())
    return result["content"][0]["text"]


# ── Baseline loading ──────────────────────────────────────────────────────────

def _baseline_path(environment: str | None) -> Path:
    script_dir = Path(__file__).parent
    for pattern in [f"baseline.{environment}.json", "baseline.json"]:
        fp = script_dir / pattern
        if fp.exists():
            return fp
    return script_dir / "baseline.json"


def _load_baseline(environment: str | None) -> dict:
    p = _baseline_path(environment)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"fingerprints": {}}


# ── Live fingerprint sampling ─────────────────────────────────────────────────

def sample_live_fingerprints(service: str, environment: str | None,
                              window_minutes: int) -> dict[str, dict]:
    """
    Sample recent traces for `service` and return fingerprint dict
    keyed by fp_hash, same format as baseline fingerprints.
    """
    if not _TF_AVAILABLE:
        return {}

    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    topo = discover_topology(lookback_hours=2, environment=environment)
    services = topo.get("services", [service])
    if service not in services:
        services = [service]

    known_root_ops: set[str] = set()
    known_root_ops.add(service)

    raw_traces = search_traces(
        [service], start_ms, now_ms, limit=TRACES_SAMPLE_LIMIT,
    )

    live_fps: dict[str, dict] = {}
    for t_summary in raw_traces:
        trace_id = t_summary.get("traceId") or t_summary.get("id")
        if not trace_id:
            continue
        full = get_trace_full(trace_id)
        if not full:
            continue
        fp = build_fingerprint(full, known_root_ops)
        if fp:
            live_fps[fp["hash"]] = fp

    return live_fps


# ── Edge-level diff ───────────────────────────────────────────────────────────

def _path_to_edges(path: str) -> list[tuple[str, str]]:
    """
    Parse a fingerprint path string like 'A -> B -> B -> C -> C -> D'
    into a list of unique (A,B), (B,C), (C,D) edge tuples.
    Paths encode edges as 'src -> dst -> dst -> next' (each hop is doubled).
    """
    tokens = [t.strip() for t in path.split(" -> ")]
    edges = []
    seen  = set()
    i = 0
    while i < len(tokens) - 1:
        src = tokens[i]
        dst = tokens[i + 1]
        edge = (src, dst)
        if edge not in seen and src != dst:
            edges.append(edge)
            seen.add(edge)
        i += 1
    return edges


def _edge_service(edge_node: str) -> str:
    """Extract service name from 'service:operation'."""
    return edge_node.split(":")[0] if ":" in edge_node else edge_node


def diff_fingerprints(baseline_fp: dict, live_fp: dict) -> dict:
    """
    Compute edge-level diff between a baseline and live fingerprint.
    Both must have the same root_op (matched by caller).
    """
    b_edges = set(_path_to_edges(baseline_fp.get("path", "")))
    l_edges = set(_path_to_edges(live_fp.get("path", "")))

    added   = sorted(l_edges - b_edges)
    removed = sorted(b_edges - l_edges)
    common  = b_edges & l_edges

    span_delta = live_fp.get("span_count", 0) - baseline_fp.get("span_count", 0)

    # Services added/removed
    b_svcs = set(baseline_fp.get("services", []))
    l_svcs = set(live_fp.get("services", []))

    return {
        "root_op":          baseline_fp.get("root_op"),
        "baseline_hash":    baseline_fp.get("hash"),
        "live_hash":        live_fp.get("hash"),
        "added_edges":      [{"from": a, "to": b} for a, b in added],
        "removed_edges":    [{"from": a, "to": b} for a, b in removed],
        "common_edge_count": len(common),
        "span_delta":       span_delta,
        "added_services":   sorted(l_svcs - b_svcs),
        "removed_services": sorted(b_svcs - l_svcs),
        "similarity":       len(common) / max(1, len(b_edges | l_edges)),
    }


def find_closest_baseline_fp(live_fp: dict, baseline_fps: dict) -> dict | None:
    """
    Find the baseline fingerprint most similar to `live_fp` by shared
    root_op first, then by edge Jaccard similarity.
    """
    root_op = live_fp.get("root_op", "")
    l_edges = set(_path_to_edges(live_fp.get("path", "")))

    best_score  = -1.0
    best_fp     = None

    for h, b_fp in baseline_fps.items():
        if b_fp.get("root_op") != root_op:
            continue
        b_edges = set(_path_to_edges(b_fp.get("path", "")))
        union   = b_edges | l_edges
        if not union:
            continue
        score = len(b_edges & l_edges) / len(union)
        if score > best_score:
            best_score = score
            best_fp = b_fp

    # If no matching root_op found, return None (truly new path family)
    return best_fp if best_fp is not None and best_score >= 0 else None


# ── Deployment event context ──────────────────────────────────────────────────

def _fetch_deploy_events(environment: str | None,
                         lookback_hours: int = DEPLOY_LOOKBACK_HOURS) -> list[dict]:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - lookback_hours * 3600 * 1000
    program  = 'events(eventType="deployment.started").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={now_ms}&immediate=true")
    req = urllib.request.Request(
        url, data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    events = []
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
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
                        props = msg.get("properties", {})
                        dims  = msg.get("metadata", {})
                        ev    = dims.get("environment") or props.get("environment", "")
                        if not environment or ev in (environment, "", "all"):
                            events.append({
                                "service": props.get("service", ""),
                                "version": props.get("version", ""),
                                "environment": ev,
                            })
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [warn] deploy events: {e}", file=sys.stderr)
    return events


# ── Claude explanation ────────────────────────────────────────────────────────

def _format_edge(e: dict) -> str:
    return f"  {e['from']} → {e['to']}"


def _build_prompt(service: str, diffs: list[dict],
                  new_fps: list[dict], vanished_fps: list[dict],
                  deploy_events: list[dict]) -> str:
    parts = [
        f"You are analyzing structural drift in distributed traces for service '{service}'.",
        "",
        "Your task: explain in plain, actionable English what changed and why.",
        "Be specific about edge changes. Reference the exact service:operation nodes.",
        "Keep each explanation to 2-4 sentences. Focus on likely causes (deploy, config change,",
        "retry logic, circuit breaker, service registration heartbeat, etc.).",
        "",
    ]

    if deploy_events:
        parts.append("Recent deployments (last 6h):")
        for d in deploy_events[:5]:
            parts.append(f"  - {d['service']} {d['version']} in {d['environment']}")
        parts.append("")

    for diff in diffs:
        parts.append(f"=== PATH DRIFT: {diff['root_op']} ===")
        parts.append(f"Baseline fingerprint: {diff['baseline_hash']}")
        parts.append(f"Live fingerprint:     {diff['live_hash']}")
        parts.append(f"Span count change: {diff['span_delta']:+d}")

        if diff["added_services"]:
            parts.append(f"NEW services in path: {', '.join(diff['added_services'])}")
        if diff["removed_services"]:
            parts.append(f"MISSING services: {', '.join(diff['removed_services'])}")

        if diff["added_edges"]:
            parts.append(f"\nNEW edges ({len(diff['added_edges'])}):")
            for e in diff["added_edges"][:8]:
                parts.append(_format_edge(e))
        if diff["removed_edges"]:
            parts.append(f"\nREMOVED edges ({len(diff['removed_edges'])}):")
            for e in diff["removed_edges"][:8]:
                parts.append(_format_edge(e))
        parts.append(f"\nSimilarity to baseline: {diff['similarity']:.0%}")
        parts.append("")

    if new_fps:
        parts.append(f"=== COMPLETELY NEW PATHS ({len(new_fps)}) ===")
        for fp in new_fps[:3]:
            parts.append(f"Root op: {fp['root_op']}")
            parts.append(f"Services: {', '.join(fp['services'])}")
            edges = _path_to_edges(fp['path'])
            parts.append(f"Edges ({len(edges)}):")
            for src, dst in edges[:6]:
                parts.append(f"  {src} → {dst}")
            parts.append("")

    if vanished_fps:
        parts.append(f"=== VANISHED PATHS ({len(vanished_fps)}) ===")
        for fp in vanished_fps[:3]:
            parts.append(f"Root op: {fp['root_op']} (hash {fp['hash']} not seen in last window)")
            edges = _path_to_edges(fp['path'])
            parts.append(f"Last known edges: {', '.join(f'{s}→{d}' for s, d in edges[:4])}")
            parts.append("")

    parts.append(
        "For each change group above, provide a numbered explanation. "
        "Be specific about what changed structurally and suggest the most likely root cause."
    )
    return "\n".join(parts)


def explain_with_claude(service: str, diffs: list[dict],
                        new_fps: list[dict], vanished_fps: list[dict],
                        deploy_events: list[dict]) -> str:
    prompt = _build_prompt(service, diffs, new_fps, vanished_fps, deploy_events)
    system = (
        "You are an expert in distributed systems and observability. "
        "You explain trace structure changes in plain English for on-call engineers. "
        "Be concise, specific, and actionable. Never say 'I cannot determine' — "
        "always provide the most likely explanation based on the evidence."
    )
    try:
        return _bedrock_request(
            messages=[{"role": "user", "content": prompt}],
            system=system,
        )
    except Exception as e:
        return f"[Claude unavailable: {e}]"


# ── Event emission ────────────────────────────────────────────────────────────

def _emit_drift_explanation(service: str, environment: str | None,
                             explanation: str, diff_count: int,
                             new_count: int, vanished_count: int) -> None:
    try:
        _request("POST", "/v2/event", [{
            "eventType":  "behavioral_baseline.drift.explained",
            "category":   "USER_DEFINED",
            "dimensions": {
                "service":     service,
                "environment": environment or "all",
            },
            "properties": {
                "explanation":   explanation[:1000],
                "diff_count":    diff_count,
                "new_count":     new_count,
                "vanished_count": vanished_count,
                "service":       service,
                "environment":   environment or "all",
            },
            "timestamp": int(time.time() * 1000),
        }], base_url=INGEST_URL)
    except Exception as e:
        print(f"  [warn] emit drift.explained: {e}", file=sys.stderr)


# ── Core analysis ─────────────────────────────────────────────────────────────

def explain_drift(service: str, environment: str | None,
                  window_minutes: int = DEFAULT_WINDOW_MINUTES,
                  dry_run: bool = False,
                  diff_only: bool = False) -> dict:
    print(f"[drift-explainer] Analyzing '{service}' (env={environment or 'all'}, "
          f"window={window_minutes}m)...")

    baseline     = _load_baseline(environment)
    baseline_fps = baseline.get("fingerprints", {})

    # Filter baseline fps to this service
    svc_baseline_fps = {
        h: v for h, v in baseline_fps.items()
        if service in v.get("services", [])
        or v.get("root_op", "").startswith(service + ":")
    }

    print(f"  Baseline: {len(svc_baseline_fps)} fingerprints for '{service}'")

    # Sample live traces
    live_fps = sample_live_fingerprints(service, environment, window_minutes)
    print(f"  Live:     {len(live_fps)} fingerprints sampled")

    if not live_fps and not svc_baseline_fps:
        print("  No data — nothing to diff.")
        return {"service": service, "diffs": [], "new": [], "vanished": [], "explanation": ""}

    # --- Classify live fingerprints ---
    drifted: list[dict]  = []  # live fp with matching baseline fp but different edges
    new_fps: list[dict]  = []  # live fp with no matching baseline fp
    live_hashes          = set(live_fps.keys())
    baseline_hashes      = set(svc_baseline_fps.keys())

    for h, live_fp in live_fps.items():
        if h in baseline_hashes:
            continue  # Exact match — no drift

        closest = find_closest_baseline_fp(live_fp, svc_baseline_fps)
        if closest is None:
            new_fps.append(live_fp)
        else:
            diff = diff_fingerprints(closest, live_fp)
            if diff["added_edges"] or diff["removed_edges"] or diff["added_services"] or diff["removed_services"]:
                drifted.append(diff)
            # (else: same edges different hash — rounding/timing artifact, ignore)

    # --- Vanished: baseline fps whose root_op hasn't been seen at all in live ---
    live_root_ops = {fp.get("root_op") for fp in live_fps.values()}
    vanished_fps: list[dict] = []
    for h, b_fp in svc_baseline_fps.items():
        if b_fp.get("root_op") not in live_root_ops:
            vanished_fps.append(b_fp)

    print(f"  Drifted: {len(drifted)}, New: {len(new_fps)}, Vanished: {len(vanished_fps)}")

    if not drifted and not new_fps and not vanished_fps:
        print(f"  ✅ No drift detected for '{service}' — baseline matches live traffic.")
        return {
            "service": service, "diffs": [], "new": [], "vanished": [],
            "explanation": "No drift detected — baseline matches live traffic."
        }

    # --- Print structural diff ---
    if drifted:
        print(f"\n  PATH DRIFT ({len(drifted)} fingerprint(s)):")
        for diff in drifted:
            print(f"\n    {diff['root_op']}  [{diff['baseline_hash']} → {diff['live_hash']}]")
            print(f"    Span delta: {diff['span_delta']:+d}  Similarity: {diff['similarity']:.0%}")
            if diff["added_edges"]:
                print(f"    NEW edges:")
                for e in diff["added_edges"][:5]:
                    print(f"      + {e['from']} → {e['to']}")
            if diff["removed_edges"]:
                print(f"    REMOVED edges:")
                for e in diff["removed_edges"][:5]:
                    print(f"      - {e['from']} → {e['to']}")
            if diff["added_services"]:
                print(f"    NEW services: {', '.join(diff['added_services'])}")
            if diff["removed_services"]:
                print(f"    MISSING services: {', '.join(diff['removed_services'])}")

    if new_fps:
        print(f"\n  NEW PATHS ({len(new_fps)}):")
        for fp in new_fps[:3]:
            print(f"    {fp['root_op']}  [{fp['hash']}]")
            edges = _path_to_edges(fp["path"])
            for src, dst in edges[:4]:
                print(f"      {src} → {dst}")

    if vanished_fps:
        print(f"\n  VANISHED PATHS ({len(vanished_fps)}):")
        for fp in vanished_fps[:3]:
            print(f"    {fp['root_op']}  [{fp['hash']}] (not seen in window)")

    explanation = ""
    if not diff_only:
        print(f"\n  Fetching deployment context...")
        deploy_events = _fetch_deploy_events(environment) if not dry_run else []

        print(f"  Calling Claude for explanation ({len(drifted)} drifts, "
              f"{len(new_fps)} new, {len(vanished_fps)} vanished)...")
        explanation = explain_with_claude(
            service, drifted, new_fps, vanished_fps, deploy_events
        )
        print(f"\n{'='*65}")
        print(f"DRIFT EXPLANATION: {service}")
        print(f"{'='*65}")
        print(explanation)
        print()

        if not dry_run:
            _emit_drift_explanation(
                service, environment, explanation,
                diff_count=len(drifted),
                new_count=len(new_fps),
                vanished_count=len(vanished_fps),
            )
            print(f"  → behavioral_baseline.drift.explained emitted to Splunk")

    return {
        "service":     service,
        "diffs":       drifted,
        "new":         new_fps,
        "vanished":    vanished_fps,
        "explanation": explanation,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Drift Explainer — edge-by-edge trace path diff with Claude explanation"
    )
    parser.add_argument("--service",        default=None,
                        help="Service to explain (omit to explain all drifted services)")
    parser.add_argument("--environment",    default=None)
    parser.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES)
    parser.add_argument("--dry-run",        action="store_true",
                        help="Don't emit Splunk events or call Claude")
    parser.add_argument("--diff-only",      action="store_true",
                        help="Print structural diff only, skip Claude explanation")
    parser.add_argument("--json",           action="store_true",
                        help="Output results as JSON")
    args = parser.parse_args()

    if args.service:
        services = [args.service]
    else:
        # Explain all services found in baseline
        baseline = _load_baseline(args.environment)
        fps      = baseline.get("fingerprints", {})
        services = sorted({
            v["services"][0]
            for v in fps.values()
            if v.get("services")
        })
        if not services:
            print("No services found in baseline.", file=sys.stderr)
            sys.exit(1)
        print(f"[drift-explainer] Explaining drift for {len(services)} services: "
              f"{', '.join(services)}")

    all_results = []
    for svc in services:
        result = explain_drift(
            svc, args.environment,
            window_minutes=args.window_minutes,
            dry_run=args.dry_run,
            diff_only=args.diff_only,
        )
        all_results.append(result)
        print()

    if args.json:
        # Serialize — remove non-JSON-serializable fingerprint dicts for diffs
        out = []
        for r in all_results:
            out.append({
                "service":     r["service"],
                "drifted":     len(r["diffs"]),
                "new":         len(r["new"]),
                "vanished":    len(r["vanished"]),
                "explanation": r["explanation"],
            })
        print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
