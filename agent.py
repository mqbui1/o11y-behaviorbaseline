#!/usr/bin/env python3
"""
agent.py — Unified behavioral baseline agent.
==============================================
One perception-action loop replacing 14 single-purpose scripts.

Every cycle:
  1. PERCEIVE  — collect anomaly events, traces, topology, deployments
  2. REASON    — one Claude call synthesizes everything
  3. ACT        — execute Claude's structured response

Usage:
  python agent.py --environment petclinicmbtest              # single cycle
  python agent.py --environment petclinicmbtest --poll 5     # every 5 minutes
  python agent.py --environment petclinicmbtest --dry-run    # perceive + reason, no act

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)

Optional env vars:
  SPLUNK_INGEST_TOKEN       (default: ACCESS_TOKEN)
  AWS_REGION                (default: us-west-2)
  AGENT_WINDOW_MINUTES      anomaly lookback window (default: 30)
"""

import argparse
import json
import os
import sys
import time
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
    import boto3
    _BEDROCK = boto3.client("bedrock-runtime", region_name=AWS_REGION)
except ImportError:
    _BEDROCK = None


# ── System prompt ─────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an observability agent for a microservices application monitored by Splunk.

You receive a JSON snapshot of the current system state and must:
1. Determine what is actually wrong (vs noise/expected behavior)
2. Identify the most likely root cause
3. Decide what concrete actions to take

Respond ONLY with valid JSON matching exactly this schema:
{
  "assessment": "<one sentence: what is happening right now>",
  "severity": "OK | DEGRADED | INCIDENT",
  "root_cause": "<one sentence: most likely cause, or null if nothing is wrong>",
  "affected_services": ["<service-name>"],
  "confidence": "LOW | MEDIUM | HIGH",
  "actions": [
    {
      "type": "SUPPRESS_ANOMALY | RELEARN_BASELINE | EMIT_EVENT | PAGE_ONCALL | UPDATE_THRESHOLD | NO_ACTION",
      "service": "<service-name or null>",
      "reason": "<why>",
      "params": {}
    }
  ],
  "narrative": "<2-3 sentence plain-English summary for the on-call engineer>"
}

Action type semantics:
  NO_ACTION         — system is healthy, no intervention needed
  SUPPRESS_ANOMALY  — this anomaly is noise or expected (e.g. post-deploy churn), don't re-alert
  RELEARN_BASELINE  — service baseline is stale or diverged; re-learn from clean traffic window
                      params: {"window_minutes": 240, "reset": false}
  EMIT_EVENT        — emit a structured event to Splunk for dashboard visibility
                      params: {"event_type": "behavioral_baseline.agent.action", "detail": "..."}
  PAGE_ONCALL       — warrants human attention (only for severity=INCIDENT)
  UPDATE_THRESHOLD  — adjust detection sensitivity for a service
                      params: {"missing_service_dominance_threshold": 0.7, "span_count_spike_multiplier": 2.5}

Guidelines:
- If there are recent deployments AND anomalies on the same service, the deployment is likely the cause.
  In that case: SUPPRESS_ANOMALY (expected churn) unless error rate is also elevated.
- If error baseline is contaminated, RELEARN_BASELINE for that service (reset=true).
- If baseline is stale (>7 days), RELEARN_BASELINE.
- If the same anomaly has been open for >30 minutes with no new signal, it may be noise — SUPPRESS.
- Only PAGE_ONCALL when severity=INCIDENT and confidence=HIGH.
- Keep actions to the minimum needed. Don't relearn everything if only one service is affected.
- Use the history.frequent_suppressions field: if a service has been suppressed many times before,
  that pattern is likely chronic noise — consider UPDATE_THRESHOLD instead of another suppression.
- Use history.recent_cycles to avoid repeating the same action that didn't resolve the situation.
"""


# ── 1. PERCEIVE ───────────────────────────────────────────────────────────────

def perceive(env: str, window_minutes: int) -> dict:
    """
    Gather everything Claude needs to reason about the current state.
    Returns a single world-state dict.
    """
    import collect
    from baseline import BaselineStore

    bs = BaselineStore(env)

    # Fetch in parallel using threads for speed
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=4) as pool:
        f_anomalies  = pool.submit(collect.fetch_anomaly_events, env, window_minutes)
        f_deploys    = pool.submit(collect.fetch_deployment_events, env, 120)
        f_topology   = pool.submit(collect.fetch_topology, env, 2)
        f_incidents  = pool.submit(collect.fetch_open_incidents, env)

        anomalies   = f_anomalies.result()
        deployments = f_deploys.result()
        topology    = f_topology.result()
        open_incs   = f_incidents.result()

    # SLO status for affected services only (avoid unnecessary API calls)
    affected_svcs = list({a["service"] for a in anomalies if a["service"] != "unknown"})
    slo = {}
    if affected_svcs:
        try:
            slo = collect.fetch_slo_status(affected_svcs[:5], env, window_minutes)
        except Exception:
            pass

    baseline_summary = bs.summarize()
    baseline_health  = bs.health()
    coverage         = collect.fetch_coverage_summary(env, bs.trace_fingerprints)
    history          = collect.summarize_history(collect.load_history(env))

    return {
        "environment":        env,
        "window_minutes":     window_minutes,
        "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "active_anomalies":   anomalies,
        "open_incidents":     open_incs,
        "recent_deployments": deployments,
        "topology":           {
            "services":   topology["services"],
            "callers_of": topology["callers_of"],
        },
        "slo_status":         slo,
        "baseline":           baseline_summary,
        "baseline_health":    baseline_health,
        "coverage":           coverage,
        "history":            history,
    }


# ── 2. REASON ─────────────────────────────────────────────────────────────────

def reason(world_state: dict) -> dict:
    """Single Claude call. Returns structured action plan."""
    if _BEDROCK is None:
        raise RuntimeError("boto3 not available — install with: pip install boto3")

    context = _trim_for_context(world_state)
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2048,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": json.dumps(context, indent=2)}],
    })

    response = _BEDROCK.invoke_model(modelId=BEDROCK_ARN, body=body)
    text = json.loads(response["body"].read())["content"][0]["text"].strip()

    # Strip markdown fences if present
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]

    return json.loads(text.strip())


def _trim_for_context(world_state: dict) -> dict:
    """Keep context under ~6k tokens. Prioritize anomalies and deployments."""
    out = dict(world_state)

    # Cap anomaly list
    if len(out.get("active_anomalies", [])) > 20:
        out["active_anomalies"] = out["active_anomalies"][-20:]
        out["anomalies_truncated"] = True

    # Trim coverage map (can be large)
    cov = out.get("coverage", {})
    if len(cov) > 15:
        # Keep lowest coverage entries — most relevant to Claude
        sorted_cov = sorted(cov.items(), key=lambda x: (x[1] or 0))
        out["coverage"] = dict(sorted_cov[:15])
        out["coverage_truncated"] = True

    # Trim topology callers_of if huge
    callers = out.get("topology", {}).get("callers_of", {})
    if len(callers) > 10:
        out["topology"] = dict(out["topology"])
        out["topology"]["callers_of"] = dict(list(callers.items())[:10])

    return out


# ── 3. ACT ────────────────────────────────────────────────────────────────────

def act(plan: dict, env: str, dry_run: bool = False,
        world_state: dict | None = None) -> None:
    """Execute each action in Claude's plan."""
    import collect
    from baseline import BaselineStore
    # Attach raw anomalies to plan so triage summary can reference them
    if world_state:
        plan["_anomalies"] = world_state.get("active_anomalies", [])

    severity_icon = {"OK": "✓", "DEGRADED": "!", "INCIDENT": "!!"}
    icon = severity_icon.get(plan.get("severity", "OK"), "?")

    print(f"\n[{icon}] {plan.get('severity', '?')} — {plan.get('assessment', '')}")
    if plan.get("root_cause"):
        print(f"    Root cause: {plan['root_cause']}")
    print(f"    {plan.get('narrative', '')}")
    print(f"    Confidence: {plan.get('confidence', '?')} | "
          f"Affected: {', '.join(plan.get('affected_services', [])) or 'none'}")

    actions = plan.get("actions", [])
    if not actions or (len(actions) == 1 and actions[0]["type"] == "NO_ACTION"):
        print("\n    No actions needed.")
        return

    bs = BaselineStore(env)

    for action in actions:
        atype   = action.get("type", "NO_ACTION")
        service = action.get("service") or "all"
        reason  = action.get("reason", "")
        params  = action.get("params", {})

        print(f"\n    [{atype}] {service}: {reason}")

        if dry_run:
            print(f"      (dry-run — skipping execution)")
            continue

        if atype == "NO_ACTION":
            pass

        elif atype == "SUPPRESS_ANOMALY":
            # Update open incident state — mark suppressed
            incidents = {
                inc["key"]: inc
                for inc in collect.fetch_open_incidents(env)
            }
            for key, inc in incidents.items():
                if service == "all" or inc.get("service") == service:
                    inc["state"] = "SUPPRESSED"
                    inc["suppressed_reason"] = reason
            collect.save_incident_state(env, incidents)
            print(f"      Suppressed incidents for {service}")

        elif atype == "RELEARN_BASELINE":
            window  = int(params.get("window_minutes", 240))
            reset   = bool(params.get("reset", False))
            svc_arg = service if service != "all" else None
            print(f"      Re-learning baseline (window={window}m, reset={reset})...")
            success = bs.learn(service=svc_arg, window_minutes=window, reset=reset)
            print(f"      {'Success' if success else 'Failed'}")
            collect.emit_event("behavioral_baseline.agent.action", {
                "action":      "RELEARN_BASELINE",
                "service":     service,
                "environment": env,
                "reason":      reason,
                "success":     success,
            })

        elif atype == "EMIT_EVENT":
            event_type = params.get("event_type", "behavioral_baseline.agent.action")
            collect.emit_event(event_type, {
                "service":     service,
                "environment": env,
                "action":      atype,
                "reason":      reason,
                "assessment":  plan.get("assessment", ""),
                "severity":    plan.get("severity", ""),
                "detail":      params.get("detail", ""),
            })
            print(f"      Emitted {event_type}")

        elif atype == "PAGE_ONCALL":
            collect.emit_event("behavioral_baseline.oncall.page", {
                "service":     service,
                "environment": env,
                "severity":    plan.get("severity", "INCIDENT"),
                "assessment":  plan.get("assessment", ""),
                "root_cause":  plan.get("root_cause", ""),
                "narrative":   plan.get("narrative", ""),
                "confidence":  plan.get("confidence", ""),
            })
            print(f"      Paged on-call via behavioral_baseline.oncall.page event")

        elif atype == "UPDATE_THRESHOLD":
            if service != "all":
                collect.update_threshold(service, params)
                print(f"      Updated thresholds for {service}: {params}")

    # ── Always emit a triage summary so full Bedrock reasoning is visible
    #    in the Splunk dashboard regardless of severity or actions taken.
    if not dry_run:
        actions_taken = [
            a.get("type") for a in actions if a.get("type") != "NO_ACTION"
        ]
        # Pull out MISSING_SERVICE anomalies for explicit visibility
        missing_svc_details = "; ".join(
            a.get("message", "") for a in plan.get("_anomalies", [])
            if a.get("anomaly_type") == "MISSING_SERVICE"
        )
        try:
            collect.emit_event("behavioral_baseline.triage.summary", {
                "environment":        env,
                "severity":           plan.get("severity", "OK"),
                "confidence":         plan.get("confidence", ""),
                "assessment":         plan.get("assessment", ""),
                "root_cause":         plan.get("root_cause", "") or "",
                "narrative":          plan.get("narrative", ""),
                "affected_services":  ", ".join(plan.get("affected_services", [])) or "none",
                "actions_taken":      ", ".join(actions_taken) or "none",
                "missing_services":   missing_svc_details or "none",
            }, dimensions={
                "sf_environment": env,
                "severity":       plan.get("severity", "OK"),
            })
            print(f"\n    [TRIAGE SUMMARY] emitted behavioral_baseline.triage.summary")
        except Exception as e:
            print(f"    [warn] triage summary emit failed: {e}", file=sys.stderr)


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_once(env: str, window_minutes: int, dry_run: bool = False,
             json_output: bool = False) -> dict:
    print(f"[agent] env={env}, window={window_minutes}m"
          + (" (dry-run)" if dry_run else ""))

    print("  Perceiving...")
    world_state = perceive(env, window_minutes)

    n_anomalies  = len(world_state["active_anomalies"])
    n_incidents  = len(world_state["open_incidents"])
    n_deploys    = len(world_state["recent_deployments"])
    n_health     = len(world_state["baseline_health"])
    print(f"  {n_anomalies} anomalies, {n_incidents} open incidents, "
          f"{n_deploys} recent deploys, {n_health} baseline issue(s)")

    print("  Reasoning...")
    try:
        plan = reason(world_state)
    except Exception as e:
        print(f"  [error] Claude call failed: {e}", file=sys.stderr)
        return {}

    if json_output:
        print(json.dumps(plan, indent=2))
    else:
        act(plan, env, dry_run=dry_run, world_state=world_state)

    # Record this cycle to history for future feedback
    if not dry_run:
        import collect as _collect
        _collect.append_history(env, {
            "timestamp":        world_state["timestamp"],
            "severity":         plan.get("severity", "OK"),
            "assessment":       plan.get("assessment", ""),
            "root_cause":       plan.get("root_cause"),
            "confidence":       plan.get("confidence", ""),
            "affected_services": plan.get("affected_services", []),
            "actions":          [
                {"type": a.get("type"), "service": a.get("service")}
                for a in plan.get("actions", [])
            ],
        })

    return plan


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified behavioral baseline agent"
    )
    parser.add_argument("--environment",    required=True)
    parser.add_argument("--poll",           type=int, default=0,
                        help="Run every N minutes (0 = single cycle)")
    parser.add_argument("--window-minutes", type=int,
                        default=int(os.environ.get("AGENT_WINDOW_MINUTES", "30")))
    parser.add_argument("--dry-run",        action="store_true",
                        help="Perceive and reason but don't execute actions")
    parser.add_argument("--json",           action="store_true",
                        help="Print Claude's plan as JSON instead of acting")
    args = parser.parse_args()

    if args.poll:
        print(f"[agent] polling every {args.poll}m")
        while True:
            try:
                run_once(args.environment, args.window_minutes,
                         args.dry_run, args.json)
            except Exception as e:
                print(f"[agent] cycle error: {e}", file=sys.stderr)
            time.sleep(args.poll * 60)
    else:
        plan = run_once(args.environment, args.window_minutes,
                        args.dry_run, args.json)
        sys.exit(0 if plan.get("severity") != "INCIDENT" else 1)


if __name__ == "__main__":
    main()
