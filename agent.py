#!/usr/bin/env python3
"""
agent.py — Behavioral baseline triage agent.
=============================================
Reads watch output (piped from trace_fingerprint.py watch --json) and calls
Claude (AWS Bedrock) to reason about the anomalies, then writes a triage
summary to alerts.log.

Usage:
  python3 core/trace_fingerprint.py --environment petclinicmbtest watch --window-minutes 5 --json \\
    | python3 agent.py --environment petclinicmbtest

  # dry-run: reason but don't act
  ... | python3 agent.py --environment petclinicmbtest --dry-run

Exit codes:
  0 — OK or DEGRADED (no immediate action required)
  1 — INCIDENT (use in CI/CD pipelines to gate on incident severity)

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us1)

Optional env vars:
  AWS_REGION                (default: us-west-2)
"""

import argparse
import json
import os
import re
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import collect

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
AWS_REGION   = os.environ.get("AWS_REGION", "us-west-2")
BEDROCK_ARN  = os.environ.get(
    "CLAUDE_MODEL",
    "arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7",
)

_DATA_DIR = Path(__file__).parent / "data"
# Stores resolved-incident context for the feedback loop
_FEEDBACK_FILE = _DATA_DIR / "incident_feedback.json"

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

try:
    import boto3 as _boto3
    _BEDROCK = True  # defer actual client creation to call time
except ImportError:
    _boto3  = None
    _BEDROCK = None


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an observability triage agent for a microservices application.

You receive a list of anomalies detected RIGHT NOW by a trace path drift detector.
The input may include several enrichment fields — use all of them:
  - "topology_context": live service dependency graph. Use it to assess blast radius.
    A shared dependency (many callers) failing is more severe than a leaf service failing.
  - "hypothesis_context": ranked root cause hypotheses from graph analysis.
    Use the highest-confidence hypothesis as your starting point for root_cause.
  - "recent_deployments": services deployed recently. If the affected service was deployed
    within the last hour, downgrade severity unless symptoms are severe.

Your job:
1. Determine what is actually wrong
2. Identify the most likely root cause (use hypothesis_context when available)
3. Recommend the minimum necessary action

Respond ONLY with valid JSON matching this schema:
{
  "assessment": "<one sentence: what is happening right now>",
  "severity": "OK | DEGRADED | INCIDENT",
  "root_cause": "<one sentence: most likely cause, or null if nothing is wrong>",
  "affected_services": ["<service-name>"],
  "confidence": "LOW | MEDIUM | HIGH",
  "action": "NO_ACTION | PAGE_ONCALL | RELEARN_BASELINE",
  "narrative": "<2-3 sentence plain-English summary for the on-call engineer>"
}

Anomaly type meanings:
  MISSING_SERVICE        — a service that normally appears in traces is completely absent.
                           Most likely cause: the service is down or unreachable.
  NEW_FINGERPRINT        — an execution path was seen that wasn't in the baseline.
                           Could be a new code path, a deployment, or a transient issue.
  NEW_SERVICE            — a new service appeared in traces that wasn't there at baseline time.
  SPAN_COUNT_SPIKE       — a trace has far more spans than usual (extra hops, retry storms).
  NEW_ERROR_SIGNATURE    — an error type/operation combination never seen before just appeared.
                           Most likely cause: a new failure mode — downstream outage, bad deploy, or new code path throwing.
  SIGNATURE_VANISHED     — a previously dominant error signature disappeared entirely.
                           Could mean the underlying issue resolved, or something worse replaced it.
  SIGNATURE_SPIKE        — a known error signature is occurring at much higher rate than baseline.

Severity guidelines:
  INCIDENT  — a service is completely missing (MISSING_SERVICE) with HIGH confidence,
              or multiple NEW_ERROR_SIGNATUREs across several services simultaneously
              (indicates a shared dependency like a database is down)
  DEGRADED  — one or two NEW_ERROR_SIGNATUREs on a single service, or SIGNATURE_SPIKE
  OK        — no anomalies or low-confidence noise

Only recommend PAGE_ONCALL for INCIDENT severity with HIGH confidence.
Only recommend RELEARN_BASELINE if the anomaly pattern suggests a deployment or planned change.
"""


# ── 1. READ WATCH OUTPUT ──────────────────────────────────────────────────────

def read_watch_output() -> dict:
    """Read JSON produced by one or more watch --json commands piped to stdin.

    Each watch command emits one JSON line. Multiple watch outputs (e.g. trace
    + error piped together) are merged into a single result with a combined
    anomaly list, giving Claude the full picture across both detection tiers.
    """
    raw = sys.stdin.read().strip()
    if not raw:
        print("Error: no input on stdin. Pipe watch --json output to agent.py.", file=sys.stderr)
        sys.exit(1)

    # Collect all JSON lines (one per watch invocation)
    results = []
    for line in raw.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    if not results:
        raise ValueError("No JSON found in stdin")

    if len(results) == 1:
        return results[0]

    # Merge multiple watch outputs — combine anomaly lists, keep first metadata
    merged = {
        "environment":    results[0].get("environment", "all"),
        "timestamp":      results[0].get("timestamp", ""),
        "window_minutes": results[0].get("window_minutes", 0),
        "checked":        sum(r.get("checked", 0) for r in results),
        "anomalies":      [],
    }
    for r in results:
        merged["anomalies"].extend(r.get("anomalies", []))
    return merged


# ── Feedback loop helpers ──────────────────────────────────────────────────────

def load_similar_past_incidents(anomalies: list[dict], top_n: int = 5) -> list[dict]:
    """
    Load the top_n most similar past resolved incidents from data/incident_feedback.json.
    Similarity is based on overlapping anomaly_type + service combinations.
    Returns a list of dicts with {anomaly_types, services, confirmed_cause, resolved_at}.
    """
    if not _FEEDBACK_FILE.exists():
        return []
    try:
        records = json.loads(_FEEDBACK_FILE.read_text())
    except Exception:
        return []

    current_types = {a.get("anomaly_type", "") for a in anomalies}
    current_svcs  = {a.get("service", a.get("root_op", "")).split(":")[0] for a in anomalies}

    scored = []
    for rec in records:
        past_types = set(rec.get("anomaly_types", []))
        past_svcs  = set(rec.get("services", []))
        overlap = len(current_types & past_types) + len(current_svcs & past_svcs)
        if overlap > 0:
            scored.append((overlap, rec))
    scored.sort(key=lambda x: -x[0])
    return [r for _, r in scored[:top_n]]


def record_incident_feedback(plan: dict, watch_result: dict, env: str) -> None:
    """
    Append a resolved-incident record to data/incident_feedback.json AND emit
    it as a behavioral_baseline.triage_result Splunk event so the feedback is
    cluster-wide (not just local to whoever ran agent.py).
    Only records INCIDENT or DEGRADED severity (OK has no learning value).
    """
    if plan.get("severity") == "OK":
        return
    anomalies = watch_result.get("anomalies", [])
    record = {
        "anomaly_types": sorted({a.get("anomaly_type", "") for a in anomalies}),
        "services":      sorted({a.get("service", a.get("root_op", "")).split(":")[0]
                                 for a in anomalies}),
        "environment":   env,
        "severity":      plan.get("severity"),
        "confirmed_cause": plan.get("root_cause") or "",
        "resolved_at":   "",  # filled in manually or by a resolve hook
        "triage_action": plan.get("action", ""),
    }
    # Write local file (fast lookup for future sessions on same machine)
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        existing = json.loads(_FEEDBACK_FILE.read_text()) if _FEEDBACK_FILE.exists() else []
        existing.append(record)
        _FEEDBACK_FILE.write_text(json.dumps(existing, indent=2))
    except Exception:
        pass  # best-effort — never fail the main flow

    # Also emit to Splunk so all agents (cluster-wide) benefit from this feedback
    try:
        import collect
        collect.emit_event("behavioral_baseline.triage_result", {
            "environment":     env,
            "severity":        plan.get("severity", ""),
            "anomaly_types":   ",".join(record["anomaly_types"]),
            "services":        ",".join(record["services"]),
            "confirmed_cause": record["confirmed_cause"],
            "triage_action":   record["triage_action"],
            "assessment":      plan.get("assessment", ""),
        })
    except Exception:
        pass  # best-effort


# ── 2. REASON ─────────────────────────────────────────────────────────────────

def _build_topology_context(env: str) -> str:
    """Fetch live service topology and return a compact summary for the prompt."""
    try:
        import collect
        topo = collect.fetch_topology(env, lookback_hours=2)
        services = topo.get("services", [])
        edges    = topo.get("edges", [])
        if not services:
            return ""
        lines = [f"Service topology for {env}:"]
        lines.append(f"  Services: {', '.join(sorted(services))}")
        if edges:
            # Group as callee: [callers] for compact representation
            callers_of: dict[str, list] = {}
            for src, dst in edges:
                callers_of.setdefault(dst, []).append(src)
            for svc, callers in sorted(callers_of.items()):
                lines.append(f"  {svc} ← called by: {', '.join(sorted(callers))}")
        return "\n".join(lines)
    except Exception:
        return ""


def _build_hypothesis_context(anomalies: list[dict], env: str) -> str:
    """
    Run hypothesis_engine.analyze() for the primary affected service and return
    a formatted context block for the Claude prompt.
    Returns empty string if hypothesis engine is unavailable or anomalies are empty.
    """
    if not anomalies:
        return ""
    # Determine primary service — prefer most directly evidenced:
    # 1. Service with "5xx on GET <x>" message (entry point with named downstream failure)
    # 2. MISSING_SERVICE anomaly
    # 3. api-gateway (best entry point for graph walk)
    # 4. First anomaly's service
    primary_service = None
    for a in anomalies:
        msg = a.get("message", "")
        if re.search(r"\b5\d\d on GET [a-z0-9_\-]+", msg, re.IGNORECASE):
            svc = a.get("service") or a.get("root_op", "").split(":")[0]
            primary_service = svc.split(":")[0] if ":" in svc else svc
            break
    if not primary_service:
        for a in anomalies:
            if a.get("anomaly_type") == "MISSING_SERVICE":
                primary_service = a.get("root_op", "").split(":")[0]
                break
    if not primary_service:
        for a in anomalies:
            svc = a.get("service") or a.get("root_op", "").split(":")[0]
            svc = svc.split(":")[0] if ":" in svc else svc
            if svc == "api-gateway":
                primary_service = svc
                break
    if not primary_service:
        svc = anomalies[0].get("service") or anomalies[0].get("root_op", "")
        primary_service = svc.split(":")[0] if ":" in svc else svc
    if not primary_service:
        return ""

    try:
        import sys as _sys
        import importlib
        _agents_dir = str(Path(__file__).parent / "agents")
        if _agents_dir not in _sys.path:
            _sys.path.insert(0, _agents_dir)
        hyp = importlib.import_module("hypothesis_engine")

        # Build a minimal corr dict from anomalies
        corr = {
            "service":       primary_service,
            "anomaly_types": [a.get("anomaly_type", "") for a in anomalies],
            "messages":      [a.get("message", "") for a in anomalies],
            "deployment":    None,
        }
        result = hyp.analyze(primary_service, corr, env, window_minutes=5)
        return hyp.format_for_prompt(result)
    except Exception:
        return ""


def reason(watch_result: dict, env: str = "") -> dict:
    """Single Claude call. Returns structured triage plan."""
    if _boto3 is None:
        raise RuntimeError("boto3 not available — install with: pip install boto3")

    # Create client at call time so it always picks up current AWS env vars
    bedrock = _boto3.client("bedrock-runtime", region_name=AWS_REGION)

    # topology_context is pre-injected by main() via a concurrent fetch —
    # watch_result already contains it when passed here.
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": json.dumps(watch_result, indent=2)}],
    })

    response = bedrock.invoke_model(modelId=BEDROCK_ARN, body=body)
    text = json.loads(response["body"].read())["content"][0]["text"].strip()

    if "```" in text:
        # Strip ```json ... ``` or ``` ... ``` fences
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]

    return json.loads(text.strip())




# ── 3. ACT ────────────────────────────────────────────────────────────────────

def act(plan: dict, watch_result: dict, env: str, dry_run: bool = False) -> None:
    """Print triage result and write to alerts.log."""
    severity_icon = {"OK": "✓", "DEGRADED": "!", "INCIDENT": "!!"}
    icon = severity_icon.get(plan.get("severity", "OK"), "?")

    print(f"\n[{icon}] {plan.get('severity')} — {plan.get('assessment', '')}")
    if plan.get("root_cause"):
        print(f"    Root cause: {plan['root_cause']}")
    print(f"    {plan.get('narrative', '')}")
    print(f"    Confidence: {plan.get('confidence')} | "
          f"Affected: {', '.join(plan.get('affected_services', [])) or 'none'}")
    print(f"    Recommended action: {plan.get('action', 'NO_ACTION')}")

    if dry_run:
        print("\n    (dry-run — skipping alerts.log write)")
        return

    # Write one DETECTION entry per anomaly
    for a in watch_result.get("anomalies", []):
        atype = a.get("anomaly_type", "")
        fields: dict = {
            "anomaly type": atype,
            "environment":  env,
            "service":      a.get("service", a.get("root_op", "")),
            "message":      a.get("message", ""),
            "detail":       a.get("detail", ""),
        }
        if a.get("trace_id"):
            fields["trace id"] = a["trace_id"]
        if atype == "MISSING_SERVICE":
            fields["root op"] = a.get("root_op", "")
            missing = a.get("missing_services") or []
            present = a.get("services_in_trace", [])
            fields["missing services"] = ", ".join(missing) if isinstance(missing, list) else missing
            fields["services in trace"] = ", ".join(present) if isinstance(present, list) else present
        elif atype in ("NEW_ERROR_SIGNATURE", "SIGNATURE_VANISHED", "SIGNATURE_SPIKE"):
            fields["error type"] = a.get("error_type", "")
            fields["operation"]  = a.get("operation", "")
            fields["call path"]  = a.get("call_path", "")
        collect.log_alert("DETECTION", fields)

    # Build missing_services summary for triage entry
    missing_lines = []
    for a in watch_result.get("anomalies", []):
        if a.get("anomaly_type") == "MISSING_SERVICE":
            svcs = a.get("missing_services") or a.get("services_in_trace", [])
            if isinstance(svcs, list):
                svcs = ", ".join(svcs)
            missing_lines.append(f"{a['root_op']} → missing: {svcs}")

    triage_fields = {
        "severity":          plan.get("severity", "OK"),
        "confidence":        plan.get("confidence", ""),
        "environment":       env,
        "affected_services": ", ".join(plan.get("affected_services", [])) or "none",
        "assessment":        plan.get("assessment", ""),
        "root_cause":        plan.get("root_cause") or "",
        "missing_services":  "; ".join(missing_lines),
        "action":            plan.get("action", "NO_ACTION"),
        "narrative":         plan.get("narrative", ""),
    }
    collect.log_alert("TRIAGE", triage_fields)
    print("\n    [TRIAGE SUMMARY] written to alerts.log")

    if plan.get("action") == "PAGE_ONCALL" and not dry_run:
        try:
            collect.emit_event("behavioral_baseline.oncall.page", {
                "environment": env,
                "severity":    plan.get("severity", "INCIDENT"),
                "assessment":  plan.get("assessment", ""),
                "root_cause":  plan.get("root_cause", ""),
                "narrative":   plan.get("narrative", ""),
            })
            print("    [PAGE_ONCALL] event emitted to Splunk")
        except Exception as e:
            print(f"    [warn] PAGE_ONCALL emit failed: {e}", file=sys.stderr)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Triage agent — pipe watch --json output to this script"
    )
    parser.add_argument("--environment", required=True)
    parser.add_argument("--dry-run", action="store_true",
                        help="Reason but don't write to alerts.log")
    args = parser.parse_args()

    env = args.environment

    # Read stdin first (required to know which services are affected before
    # we can run hypothesis engine). Topology can still start concurrently.
    _topo_ctx: list[str] = []
    def _fetch_topo():
        _topo_ctx.append(_build_topology_context(env))
    topo_thread = threading.Thread(target=_fetch_topo, daemon=True)
    topo_thread.start()

    watch_result = read_watch_output()
    anomalies = watch_result.get("anomalies", [])

    topo_thread.join(timeout=10)

    print(f"[agent] env={env} | {len(anomalies)} anomaly(s) from watch")

    if not anomalies:
        print("  No anomalies — system healthy.")
        sys.exit(0)

    # Inject topology context (already fetched)
    if _topo_ctx and _topo_ctx[0]:
        watch_result["topology_context"] = _topo_ctx[0]

    # Fetch hypothesis context (past incidents dropped — hypothesis engine covers root cause)
    print("  Building enriched context (hypothesis engine)...")
    hyp_ctx = _build_hypothesis_context(anomalies, env)

    if hyp_ctx:
        watch_result["hypothesis_context"] = hyp_ctx

    print("  Reasoning with Claude...")
    try:
        plan = reason(watch_result, env=env)
    except Exception as e:
        print(f"  [error] Claude call failed: {e}", file=sys.stderr)
        # Retry once with a fresh client in case credentials rotated mid-flight
        try:
            print("  Retrying...", file=sys.stderr)
            plan = reason(watch_result, env=env)
        except Exception as e2:
            print(f"  [error] Retry failed: {e2}", file=sys.stderr)
            sys.exit(1)

    act(plan, watch_result, env, dry_run=args.dry_run)

    # Record this incident in the feedback loop for future correlation
    if not args.dry_run:
        record_incident_feedback(plan, watch_result, env)

    sys.exit(0 if plan.get("severity") != "INCIDENT" else 1)


if __name__ == "__main__":
    main()
