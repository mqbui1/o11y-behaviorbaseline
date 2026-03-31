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

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us1)

Optional env vars:
  AWS_REGION                (default: us-west-2)
"""

import argparse
import json
import os
import sys
from pathlib import Path

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
Each anomaly has a type, the affected service, and a message describing what changed.

Your job:
1. Determine what is actually wrong
2. Identify the most likely root cause
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


# ── 2. REASON ─────────────────────────────────────────────────────────────────

def reason(watch_result: dict) -> dict:
    """Single Claude call. Returns structured triage plan."""
    if _boto3 is None:
        raise RuntimeError("boto3 not available — install with: pip install boto3")

    # Create client at call time so it always picks up current AWS env vars
    bedrock = _boto3.client("bedrock-runtime", region_name=AWS_REGION)

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": json.dumps(watch_result, indent=2)}],
    })

    response = bedrock.invoke_model(modelId=BEDROCK_ARN, body=body)
    text = json.loads(response["body"].read())["content"][0]["text"].strip()

    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]

    return json.loads(text.strip())




# ── 3. ACT ────────────────────────────────────────────────────────────────────

def act(plan: dict, watch_result: dict, env: str, dry_run: bool = False) -> None:
    """Print triage result and write to alerts.log."""
    import collect

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

    watch_result = read_watch_output()
    anomalies = watch_result.get("anomalies", [])
    env = args.environment

    print(f"[agent] env={env} | {len(anomalies)} anomaly(s) from watch")

    if not anomalies:
        print("  No anomalies — system healthy.")
        sys.exit(0)

    print("  Reasoning with Claude...")
    try:
        plan = reason(watch_result)
    except Exception as e:
        print(f"  [error] Claude call failed: {e}", file=sys.stderr)
        sys.exit(1)

    act(plan, watch_result, env, dry_run=args.dry_run)
    sys.exit(0 if plan.get("severity") != "INCIDENT" else 1)


if __name__ == "__main__":
    main()
