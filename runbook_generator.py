#!/usr/bin/env python3
"""
Behavioral Baseline — Runbook Generator (#13)
==============================================
One-time agent: when a new environment is onboarded, Claude reads the
topology and baseline and writes a tailored incident runbook.

Output: RUNBOOK.<environment>.md alongside the baseline files.

Contents:
  1. Service map summary (dependencies, shared deps, ingress points)
  2. Triage checklist — ordered by blast radius (check shared deps first)
  3. Per-service: normal traffic patterns, common error signatures, thresholds
  4. Copy-paste investigation commands for each service
  5. Escalation paths based on dependency chains

Usage:
  python runbook_generator.py --environment petclinicmbtest
  python runbook_generator.py --environment petclinicmbtest --force  # overwrite existing

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)

Optional:
  AWS_REGION    (default: us-west-2)
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")
AWS_REGION   = os.environ.get("AWS_REGION", "us-west-2")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
_BEDROCK_MODEL = "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7"

_TF_DIR = Path(__file__).parent
sys.path.insert(0, str(_TF_DIR))


# ── Bedrock ───────────────────────────────────────────────────────────────────

def _bedrock(messages: list[dict], system: str = "") -> str:
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 not installed — pip3 install boto3")
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    body = {"anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096, "messages": messages}
    if system:
        body["system"] = system
    resp   = client.invoke_model(modelId=_BEDROCK_MODEL, body=json.dumps(body),
                                  contentType="application/json", accept="application/json")
    result = json.loads(resp["body"].read())
    return result["content"][0]["text"]


# ── Data loading ──────────────────────────────────────────────────────────────

def _load_baseline(environment: str | None) -> dict:
    for pattern in [f"baseline.{environment}.json", "baseline.json"]:
        fp = Path(__file__).parent / pattern
        if fp.exists():
            try:
                return json.loads(fp.read_text())
            except Exception:
                pass
    return {"fingerprints": {}}


def _load_error_baseline(environment: str | None) -> dict:
    for pattern in [f"error_baseline.{environment}.json", "error_baseline.json"]:
        fp = Path(__file__).parent / pattern
        if fp.exists():
            try:
                return json.loads(fp.read_text())
            except Exception:
                pass
    return {"signatures": {}}


def _load_thresholds(service: str) -> dict:
    p = Path(__file__).parent / "thresholds.json"
    if p.exists():
        try:
            return json.loads(p.read_text()).get("services", {}).get(service, {})
        except Exception:
            pass
    return {}


def _fetch_topology(environment: str | None) -> dict:
    import urllib.request, urllib.error
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 48 * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [{"name": "sf_environment", "operator": "equals",
                                "value": environment, "scope": "global"}]
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data    = json.dumps(body).encode()
    req     = urllib.request.Request(f"{BASE_URL}/v2/apm/topology",
                                      data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            result    = json.loads(resp.read().decode())
            edges_raw = (result.get("data") or {}).get("edges", [])
            edges     = [(e["fromNode"], e["toNode"]) for e in edges_raw
                         if e["fromNode"] != e["toNode"]]
            callers_of: dict[str, set] = defaultdict(set)
            callees_of: dict[str, set] = defaultdict(set)
            services: set[str] = set()
            for src, dst in edges:
                callers_of[dst].add(src)
                callees_of[src].add(dst)
                services.add(src); services.add(dst)
            return {"callers_of": {k: sorted(v) for k, v in callers_of.items()},
                    "callees_of": {k: sorted(v) for k, v in callees_of.items()},
                    "services":   sorted(services)}
    except Exception as e:
        print(f"  [warn] topology: {e}", file=sys.stderr)
        return {"callers_of": {}, "callees_of": {}, "services": []}


# ── Context assembly ──────────────────────────────────────────────────────────

def _service_summary(svc: str, topo: dict, baseline: dict, err_baseline: dict) -> dict:
    """Summarize one service for the Claude prompt."""
    callers  = topo["callers_of"].get(svc, [])
    callees  = topo["callees_of"].get(svc, [])
    fps      = {h: v for h, v in baseline.get("fingerprints", {}).items()
                if svc in v.get("services", []) or v.get("root_op", "").startswith(svc + ":")}
    err_sigs = {h: v for h, v in err_baseline.get("signatures", {}).items()
                if v.get("service") == svc}
    thresholds = _load_thresholds(svc)

    # Fingerprint stats
    root_ops = sorted({v["root_op"] for v in fps.values()})
    span_counts = [v.get("span_count", 0) for v in fps.values()]
    avg_spans   = round(sum(span_counts) / max(1, len(span_counts)), 1)

    # Error signature types
    err_types = [v.get("error_type", "") for v in err_sigs.values()]

    return {
        "service":         svc,
        "callers":         callers,
        "callees":         callees,
        "blast_radius":    len(callers),
        "fingerprint_count": len(fps),
        "root_ops":        root_ops,
        "avg_span_count":  avg_spans,
        "error_types":     err_types,
        "thresholds":      thresholds,
    }


def _build_prompt(environment: str, topo: dict,
                  service_summaries: list[dict]) -> str:
    # Sort by blast radius (shared deps first)
    sorted_svcs = sorted(service_summaries, key=lambda s: -s["blast_radius"])

    lines = [
        f"You are writing an incident response runbook for the '{environment}' environment.",
        "Based on the service topology and behavioral baseline data below, write a comprehensive",
        "Markdown runbook that an on-call engineer can use during an incident.",
        "",
        "Include:",
        "1. **Environment Overview** — service map, ingress points, shared dependencies",
        "2. **Triage Checklist** — ordered steps: which services to check first and why",
        "3. **Per-Service Reference** — for each service: normal patterns, known error types,",
        "   specific investigation commands, and what downstream services it can break",
        "4. **Common Failure Scenarios** — based on the dependency graph",
        "5. **Copy-Paste Commands** — actual shell commands using the behavioral baseline tools",
        "",
        "Use the service names and operations exactly as provided. Be specific and actionable.",
        "",
        f"## Environment: {environment}",
        f"Services: {', '.join(topo['services'])}",
        "",
    ]

    for s in sorted_svcs:
        lines.append(f"### {s['service']}")
        if s["callers"]:
            lines.append(f"Called by: {', '.join(s['callers'])}")
        if s["callees"]:
            lines.append(f"Calls: {', '.join(s['callees'])}")
        if not s["callers"] and not s["callees"]:
            lines.append("Isolated (no dependency edges in APM)")
        lines.append(f"Blast radius: {s['blast_radius']} upstream callers")
        lines.append(f"Baseline fingerprints: {s['fingerprint_count']}")
        lines.append(f"Avg span count: {s['avg_span_count']}")
        if s["root_ops"]:
            lines.append(f"Root operations: {', '.join(s['root_ops'][:5])}" +
                         ("..." if len(s["root_ops"]) > 5 else ""))
        if s["error_types"]:
            lines.append(f"Known error types: {', '.join(s['error_types'])}")
        if s["thresholds"]:
            lines.append(f"Tuned thresholds: {json.dumps(s['thresholds'])}")
        lines.append("")

    lines.append(
        "Write the runbook now in Markdown. Use clear headers and bullet points. "
        "Include the actual python commands to run (e.g. "
        "`python3 triage_agent.py --environment {env} --window-minutes 60`). "
        "At the end, include a one-page quick reference card."
    )
    return "\n".join(lines)


# ── Generator ────────────────────────────────────────────────────────────────

def generate_runbook(environment: str, force: bool = False) -> Path:
    output_path = Path(__file__).parent / f"RUNBOOK.{environment}.md"
    if output_path.exists() and not force:
        print(f"  {output_path} already exists. Use --force to regenerate.")
        return output_path

    print(f"[runbook-generator] Generating runbook for '{environment}'...")

    topo         = _fetch_topology(environment)
    baseline     = _load_baseline(environment)
    err_baseline = _load_error_baseline(environment)

    services = topo.get("services", [])
    if not services:
        # Fall back to services in baseline
        fps = baseline.get("fingerprints", {})
        services = sorted({v["services"][0] for v in fps.values() if v.get("services")})

    print(f"  {len(services)} services: {', '.join(services)}")

    summaries = [_service_summary(s, topo, baseline, err_baseline)
                 for s in services]

    prompt = _build_prompt(environment, topo, summaries)

    print("  Calling Claude (Bedrock) to write runbook...")
    system = (
        "You are an expert SRE writing a production incident runbook. "
        "Be specific, actionable, and concise. Use Markdown with clear structure. "
        "Focus on what the on-call engineer needs to do in the first 10 minutes."
    )
    runbook_md = _bedrock(
        messages=[{"role": "user", "content": prompt}],
        system=system,
    )

    # Add generation header
    header = (
        f"# Incident Runbook — {environment}\n\n"
        f"_Generated by runbook_generator.py on "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}_\n\n"
        f"_Re-generate after major topology changes: "
        f"`python3 runbook_generator.py --environment {environment} --force`_\n\n"
        f"---\n\n"
    )
    full_runbook = header + runbook_md

    output_path.write_text(full_runbook)
    print(f"  ✅ Runbook written to {output_path} "
          f"({len(full_runbook)} chars, {len(full_runbook.splitlines())} lines)")
    return output_path


# ── onboard.py integration ────────────────────────────────────────────────────

def generate(environment: str, force: bool = False) -> str:
    """Callable from onboard.py: generate(env, force=False) → path str."""
    return str(generate_runbook(environment, force=force))


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Runbook Generator — writes a tailored incident runbook for an environment"
    )
    parser.add_argument("--environment", required=True)
    parser.add_argument("--force", action="store_true",
                        help="Overwrite existing runbook")
    args = parser.parse_args()

    path = generate_runbook(args.environment, force=args.force)
    print(f"\n  Open: {path}")


if __name__ == "__main__":
    main()
