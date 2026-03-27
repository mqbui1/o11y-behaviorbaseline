#!/usr/bin/env python3
"""
Behavioral Baseline — Anomaly Triage Agent
===========================================
An agentic AI layer that sits on top of the correlation engine. When a
correlated anomaly fires, this agent:

  1. Fetches the raw anomaly + deployment events from Splunk
  2. Retrieves full trace details for the most recent affected traces
  3. Calls Claude API with all available context
  4. Produces a plain-English incident summary with root cause hypothesis,
     affected services, and recommended next steps
  5. Optionally routes the summary to a webhook (Slack, PagerDuty, etc.)

The agent can run in two modes:
  - poll  (default) — periodically checks for new correlated anomaly events
                      and triages anything unseen in the last N minutes
  - once  — run once and exit (useful for cron or post-correlate hook)

Usage:
  python triage_agent.py --environment petclinicmbtest
  python triage_agent.py --environment petclinicmbtest --mode once
  python triage_agent.py --environment petclinicmbtest --webhook-url https://hooks.slack.com/...
  python triage_agent.py --environment petclinicmbtest --window-minutes 15 --dry-run

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)

Optional env vars:
  SPLUNK_INGEST_TOKEN       (default: ACCESS_TOKEN)
  TRIAGE_WEBHOOK_URL        webhook for Slack/PagerDuty notifications
  TRIAGE_POLL_INTERVAL      seconds between poll cycles (default: 60)
  TRIAGE_WINDOW_MINUTES     how far back to look for correlated events (default: 15)
  CLAUDE_MODEL              Bedrock model ID or inference profile ARN
                            (default: arn:aws:bedrock:us-west-2:387769110234:application-inference-profile/fky19kpnw2m7)
  AWS_REGION                AWS region for Bedrock (default: us-west-2)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import boto3
    _BOTO3_AVAILABLE = True
except ImportError:
    _BOTO3_AVAILABLE = False

# ── Config ─────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN  = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM         = os.environ.get("SPLUNK_REALM", "us0")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY")  # optional: direct API fallback
AWS_REGION    = os.environ.get("AWS_REGION", "us-west-2")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

_DEFAULT_BEDROCK_MODEL = (
    "arn:aws:bedrock:us-west-2:387769110234:"
    "application-inference-profile/fky19kpnw2m7"
)
CLAUDE_MODEL        = os.environ.get("CLAUDE_MODEL", _DEFAULT_BEDROCK_MODEL)
POLL_INTERVAL       = int(os.environ.get("TRIAGE_POLL_INTERVAL", "60"))
DEFAULT_WINDOW_MIN  = int(os.environ.get("TRIAGE_WINDOW_MINUTES", "15"))
WEBHOOK_URL         = os.environ.get("TRIAGE_WEBHOOK_URL")

# Max traces to fetch per anomaly service for context
MAX_TRACES_PER_SERVICE = 3
# Max spans to include in the Claude prompt (keep tokens manageable)
MAX_SPANS_IN_PROMPT = 30

# Track which correlated anomaly events we've already triaged (in-memory, per run)
_triaged_event_keys: set[str] = set()


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL, timeout: float = 30.0) -> Any:
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
        try:
            detail = json.loads(raw)
        except Exception:
            detail = raw
        raise RuntimeError(f"Splunk API {e.code}: {json.dumps(detail)}")


def _claude_request(messages: list[dict], system: str) -> str:
    """
    Call Claude. Tries AWS Bedrock first (uses ambient AWS credentials,
    no extra cost if already on Bedrock). Falls back to direct Anthropic
    API if ANTHROPIC_API_KEY is set.
    """
    if _BOTO3_AVAILABLE:
        try:
            return _bedrock_request(messages, system)
        except Exception as e:
            if ANTHROPIC_KEY:
                print(f"  [warn] Bedrock failed ({e}), falling back to Anthropic API",
                      file=sys.stderr)
            else:
                raise
    if ANTHROPIC_KEY:
        return _anthropic_direct_request(messages, system)
    raise RuntimeError(
        "No LLM backend available. Install boto3 (pip install boto3) for "
        "Bedrock, or set ANTHROPIC_API_KEY for direct API access."
    )


def _bedrock_request(messages: list[dict], system: str) -> str:
    """Invoke Claude via AWS Bedrock using ambient IAM credentials."""
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 1024,
        "system":     system,
        "messages":   messages,
    })
    resp   = client.invoke_model(modelId=CLAUDE_MODEL, body=body)
    result = json.loads(resp["body"].read())
    return result["content"][0]["text"]


def _anthropic_direct_request(messages: list[dict], system: str) -> str:
    """Call Claude via the direct Anthropic API (requires ANTHROPIC_API_KEY)."""
    # Use claude-opus-4-6 for direct API if model is a Bedrock ARN
    model = CLAUDE_MODEL if not CLAUDE_MODEL.startswith("arn:") else "claude-opus-4-6"
    body = {
        "model":      model,
        "max_tokens": 1024,
        "system":     system,
        "messages":   messages,
    }
    headers = {
        "x-api-key":         ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
        "content-type":      "application/json",
    }
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=data, headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            result = json.loads(resp.read().decode())
            return result["content"][0]["text"]
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"Anthropic API {e.code}: {raw[:300]}")


# ── Splunk event fetching ──────────────────────────────────────────────────────

def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 12.0) -> list[dict]:
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url,
        data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data_lines: list[str] = []
            for raw_line in resp:
                line    = raw_line.decode()
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


def fetch_correlated_anomaly_events(start_ms: int, end_ms: int,
                                     environment: str | None) -> list[dict]:
    """Fetch behavioral_baseline.correlated_anomaly events from Splunk."""
    raw = _signalflow_events("behavioral_baseline.correlated_anomaly",
                             start_ms, end_ms)
    events = []
    for msg in raw:
        dims  = msg.get("metadata", {})
        props = msg.get("properties", {})
        event_env = dims.get("environment") or props.get("environment", "all")
        if environment and event_env not in (environment, "all"):
            continue
        events.append({
            "service":       dims.get("service", "unknown"),
            "corr_type":     dims.get("corr_type", ""),
            "severity":      dims.get("severity", ""),
            "tiers":         dims.get("tiers", "").split(","),
            "anomaly_types": props.get("anomaly_types", "").split(","),
            "messages":      props.get("details", "").split(" | "),
            "environment":   event_env,
            "timestamp_ms":  msg.get("timestampMs", 0),
            "deployment":    {
                "version":  props.get("deployment_version", ""),
                "commit":   props.get("deployment_commit", ""),
                "deployer": props.get("deployment_deployer", ""),
                "desc":     props.get("deployment_desc", ""),
            } if props.get("deployment_correlated") == "true" else None,
        })
    return events


# ── Trace fetching ─────────────────────────────────────────────────────────────

def search_recent_traces(service: str, start_ms: int, end_ms: int,
                          environment: str | None,
                          limit: int = MAX_TRACES_PER_SERVICE) -> list[str]:
    """Return a list of recent traceIDs for the given service."""
    tag_filters = [{"tag": "sf_service", "operation": "IN", "values": [service]}]
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN",
                             "values": [environment]})
    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": end_ms},
            "filters": [{"traceFilter": {"tags": tag_filters},
                         "filterType": "traceFilter"}],
            "samplingFactor": 100,
        },
        "sectionsParameters": [{"sectionType": "traceExamples", "limit": limit}],
    }
    start_body = {
        "operationName": "StartAnalyticsSearch",
        "variables": {"parameters": parameters},
        "query": ("query StartAnalyticsSearch($parameters: JSON!) "
                  "{ startAnalyticsSearch(parameters: $parameters) }"),
    }
    try:
        start_result = _request("POST", "/v2/apm/graphql?op=StartAnalyticsSearch",
                                 start_body, base_url=APP_URL)
        job_id = (
            ((start_result.get("data") or {}).get("startAnalyticsSearch") or {})
            .get("jobId")
        )
        if not job_id:
            return []
        get_body = {
            "operationName": "GetAnalyticsSearch",
            "variables": {"jobId": job_id},
            "query": ("query GetAnalyticsSearch($jobId: ID!) "
                      "{ getAnalyticsSearch(jobId: $jobId) }"),
        }
        delay, elapsed = 0.1, 0.0
        while elapsed < 15.0:
            result = _request("POST", "/v2/apm/graphql?op=GetAnalyticsSearch",
                              get_body, base_url=APP_URL)
            sections = (
                ((result.get("data") or {}).get("getAnalyticsSearch") or {})
                .get("sections", [])
            )
            for section in sections:
                if section.get("sectionType") == "traceExamples":
                    examples = section.get("legacyTraceExamples") or []
                    if section.get("isComplete"):
                        return [e.get("traceId") or e.get("id", "")
                                for e in examples[:limit] if e.get("traceId") or e.get("id")]
            time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, 2.0)
    except Exception as e:
        print(f"  [warn] search_traces({service}): {e}", file=sys.stderr)
    return []


def get_trace_full(trace_id: str) -> dict | None:
    """Fetch full span details for a single trace via GraphQL."""
    query = (
        "query TraceFullDetailsLessValidation($id: ID!) {"
        " trace(id: $id) {"
        " traceID startTime duration"
        " spans { spanID operationName serviceName"
        "         startTime duration tags { key value } } } }"
    )
    gql_body = {
        "operationName": "TraceFullDetailsLessValidation",
        "variables": {"id": trace_id},
        "query": query,
    }
    try:
        result = _request("POST", "/v2/apm/graphql?op=TraceFullDetailsLessValidation",
                          gql_body, base_url=APP_URL)
        return (result.get("data") or {}).get("trace")
    except Exception as e:
        print(f"  [warn] get_trace_full({trace_id}): {e}", file=sys.stderr)
        return None


def _summarize_trace(trace: dict) -> dict:
    """
    Produce a compact, human-readable summary of a trace for the LLM prompt.
    Truncates to MAX_SPANS_IN_PROMPT spans to keep token count manageable.
    """
    spans = trace.get("spans", [])
    total_spans = len(spans)

    # Sort by startTime
    spans_sorted = sorted(spans, key=lambda s: s.get("startTime", 0))

    # Collect interesting tags (errors, HTTP status, exceptions)
    error_spans = []
    for span in spans_sorted[:MAX_SPANS_IN_PROMPT]:
        tags = {t["key"]: t["value"] for t in span.get("tags", [])}
        has_error = (
            tags.get("error") in ("true", "True", True)
            or tags.get("otel.status_code") == "ERROR"
            or tags.get("http.status_code", "200").startswith(("4", "5"))
        )
        span_summary = {
            "service":   span.get("serviceName"),
            "operation": span.get("operationName"),
            "duration_ms": round(span.get("duration", 0) / 1000, 1),
        }
        if has_error:
            if tags.get("http.status_code"):
                span_summary["http_status"] = tags["http.status_code"]
            if tags.get("exception.message"):
                span_summary["exception"] = tags["exception.message"][:200]
            if tags.get("db.statement"):
                span_summary["db_statement"] = tags["db.statement"][:100]
            error_spans.append(span_summary)

    # All services involved
    services = sorted({s.get("serviceName") for s in spans if s.get("serviceName")})

    root = spans_sorted[0] if spans_sorted else {}
    return {
        "trace_id":      trace.get("traceID"),
        "total_duration_ms": round(trace.get("duration", 0) / 1000, 1),
        "total_spans":   total_spans,
        "services":      services,
        "root_service":  root.get("serviceName"),
        "root_operation": root.get("operationName"),
        "error_spans":   error_spans,
    }


# ── Claude triage ──────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert Site Reliability Engineer analyzing a correlated anomaly
alert from a behavioral baseline monitoring system. Your job is to produce a concise,
actionable incident triage summary.

The monitoring system works by:
- Learning normal trace paths and error signatures during baseline periods
- Detecting deviations: new trace paths (TIER2), new error signatures (TIER3),
  new services appearing in topology (TIER1)
- Correlating signals across tiers to reduce false positives

When multiple tiers fire on the same service simultaneously, it indicates a
high-confidence incident, not a false positive.

Anomaly types:
- NEW_FINGERPRINT: trace took a path never seen before (new code path, retry logic, fallback)
- MISSING_SERVICE: expected downstream service not appearing in traces (service down, network issue)
- SPAN_COUNT_SPIKE: far more spans than normal (cascading retries, fan-out explosion)
- NEW_SIGNATURE: new error pattern never seen in baseline (new bug, unhandled edge case)
- SIGNATURE_VANISHED: error that was common is now gone (possible fix, or service completely down)

Be concise. Structure your response as:
1. **Incident Summary** (1-2 sentences: what happened)
2. **Root Cause Hypothesis** (most likely cause based on the evidence)
3. **Affected Services** (list with what's wrong for each)
4. **Evidence** (key observations from traces and anomaly signals)
5. **Recommended Actions** (specific, ordered steps to investigate or remediate)

If a deployment is correlated, consider it the most likely cause and say so explicitly."""


def triage_anomaly(corr: dict, traces: list[dict], dry_run: bool = False) -> str:
    """
    Call Claude with the full correlated anomaly context + trace data.
    Returns the triage summary text.
    """
    # Build trace summaries
    trace_summaries = [_summarize_trace(t) for t in traces if t]

    # Build the user message
    ts = datetime.fromtimestamp(corr["timestamp_ms"] / 1000, tz=timezone.utc)
    ts_str = ts.strftime("%Y-%m-%d %H:%M:%S UTC")

    context_parts = [
        f"## Correlated Anomaly Alert",
        f"",
        f"**Time:** {ts_str}",
        f"**Environment:** {corr['environment']}",
        f"**Primary Service:** {corr['service']}",
        f"**Severity:** {corr['severity']}",
        f"**Correlation Type:** {corr['corr_type']}",
        f"**Tiers Fired:** {', '.join(t for t in corr['tiers'] if t)}",
        f"**Anomaly Types:** {', '.join(a for a in corr['anomaly_types'] if a)}",
        f"",
        f"## Anomaly Messages",
    ]
    for msg in corr["messages"]:
        if msg.strip():
            context_parts.append(f"- {msg}")

    deploy = corr.get("deployment")
    if deploy and (deploy.get("version") or deploy.get("commit")):
        context_parts += [
            f"",
            f"## Deployment Context",
            f"**This anomaly is correlated with a recent deployment:**",
            f"- Service: {corr['service']}",
            f"- Version: {deploy.get('version') or 'n/a'}",
            f"- Commit: {deploy.get('commit') or 'n/a'}",
            f"- Deployer: {deploy.get('deployer') or 'n/a'}",
        ]
        if deploy.get("desc"):
            context_parts.append(f"- Description: {deploy['desc']}")

    if trace_summaries:
        context_parts += [
            f"",
            f"## Recent Traces ({len(trace_summaries)} retrieved)",
        ]
        for i, ts_data in enumerate(trace_summaries, 1):
            context_parts += [
                f"",
                f"### Trace {i}: {ts_data['trace_id']}",
                f"- Root: {ts_data['root_service']}:{ts_data['root_operation']}",
                f"- Duration: {ts_data['total_duration_ms']}ms",
                f"- Spans: {ts_data['total_spans']}",
                f"- Services involved: {', '.join(ts_data['services'])}",
            ]
            if ts_data["error_spans"]:
                context_parts.append(f"- Error spans ({len(ts_data['error_spans'])}):")
                for es in ts_data["error_spans"][:5]:
                    line = f"  - {es['service']}:{es['operation']} ({es['duration_ms']}ms)"
                    if es.get("http_status"):
                        line += f" HTTP {es['http_status']}"
                    if es.get("exception"):
                        line += f" — {es['exception'][:100]}"
                    context_parts.append(line)
            else:
                context_parts.append(f"- No error spans detected in this trace")
    else:
        context_parts += [
            f"",
            f"## Traces",
            f"No recent traces could be retrieved for this service.",
            f"(Service may be completely down or traces not yet indexed)",
        ]

    user_message = "\n".join(context_parts)

    if dry_run:
        print("\n--- [dry-run] Would send to Claude ---")
        print(user_message[:1000] + ("..." if len(user_message) > 1000 else ""))
        print("--- [dry-run] end ---\n")
        return "[dry-run] Triage skipped"

    return _claude_request(
        messages=[{"role": "user", "content": user_message}],
        system=SYSTEM_PROMPT,
    )


# ── Webhook routing ────────────────────────────────────────────────────────────

def send_to_webhook(webhook_url: str, corr: dict, summary: str) -> None:
    """Send the triage summary to a Slack-compatible webhook."""
    severity_emoji = {"Critical": ":red_circle:", "Major": ":large_orange_circle:",
                      "Minor": ":large_yellow_circle:", "Info": ":white_circle:"}
    emoji = severity_emoji.get(corr["severity"], ":large_orange_circle:")

    text = (
        f"{emoji} *Behavioral Baseline — {corr['severity']} Anomaly*\n"
        f"*Service:* {corr['service']}  |  *Env:* {corr['environment']}  "
        f"|  *Type:* {corr['corr_type']}\n\n"
        f"{summary}"
    )
    # Truncate for Slack (4000 char limit)
    if len(text) > 3900:
        text = text[:3900] + "\n_(truncated)_"

    body = {"text": text}
    data = json.dumps(body).encode()
    req  = urllib.request.Request(
        webhook_url, data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception as e:
        print(f"  [warn] Webhook delivery failed: {e}", file=sys.stderr)


# ── Core triage loop ───────────────────────────────────────────────────────────

def run_triage(window_minutes: int, environment: str | None,
               webhook_url: str | None, dry_run: bool) -> int:
    """
    Fetch recent correlated anomaly events, triage each one with Claude,
    and optionally route to webhook. Returns number of events triaged.
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000
    env_desc = environment or "all environments"

    print(f"[triage] Scanning {window_minutes}m window for correlated anomalies "
          f"({env_desc})...")

    correlated = fetch_correlated_anomaly_events(start_ms, now_ms, environment)

    if not correlated:
        print("  No correlated anomaly events found.")
        return 0

    # Deduplicate: skip events we already triaged this session
    new_events = []
    for c in correlated:
        key = f"{c['service']}:{c['corr_type']}:{c['timestamp_ms']}"
        if key not in _triaged_event_keys:
            new_events.append((key, c))

    if not new_events:
        print(f"  Found {len(correlated)} event(s) — all already triaged.")
        return 0

    print(f"  Found {len(correlated)} event(s), {len(new_events)} new to triage.\n")

    triaged = 0
    for key, corr in new_events:
        _triaged_event_keys.add(key)
        ts = datetime.fromtimestamp(corr["timestamp_ms"] / 1000, tz=timezone.utc)
        print(f"[{corr['severity']}] {corr['corr_type']} — {corr['service']} "
              f"@ {ts.strftime('%H:%M:%S UTC')}")
        print(f"  Tiers: {', '.join(t for t in corr['tiers'] if t)}")
        print(f"  Anomaly types: {', '.join(a for a in corr['anomaly_types'] if a)}")

        # Fetch traces for this service in the anomaly window
        trace_ids = []
        if not dry_run:
            # Look back a bit further for traces around the anomaly time
            trace_start = corr["timestamp_ms"] - 10 * 60 * 1000  # 10m before
            trace_end   = corr["timestamp_ms"] + 2 * 60 * 1000   # 2m after
            print(f"  Fetching traces for {corr['service']}...")
            trace_ids = search_recent_traces(
                corr["service"], trace_start, trace_end, environment
            )
            print(f"  Retrieved {len(trace_ids)} trace ID(s)")

        # Fetch full trace details in parallel
        traces = []
        if trace_ids:
            with ThreadPoolExecutor(max_workers=len(trace_ids)) as pool:
                futures = {pool.submit(get_trace_full, tid): tid
                           for tid in trace_ids}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        traces.append(result)

        # Call Claude
        print(f"  Calling Claude ({CLAUDE_MODEL}) for triage analysis...")
        try:
            summary = triage_anomaly(corr, traces, dry_run=dry_run)
        except Exception as e:
            print(f"  [error] Claude triage failed: {e}", file=sys.stderr)
            continue

        # Print the summary
        print()
        print("=" * 70)
        print(f"TRIAGE SUMMARY — {corr['service']} ({corr['severity']})")
        print("=" * 70)
        print(summary)
        print("=" * 70)
        print()

        # Route to webhook if configured
        if webhook_url and not dry_run:
            send_to_webhook(webhook_url, corr, summary)
            print(f"  Routed to webhook.")

        triaged += 1

    return triaged


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Anomaly Triage Agent — AI-powered incident analysis for behavioral baseline alerts"
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help="APM environment to scope triage to (e.g. petclinicmbtest)",
    )
    parser.add_argument(
        "--mode", choices=["poll", "once"], default="once",
        help="Run once or continuously poll (default: once)",
    )
    parser.add_argument(
        "--window-minutes", type=int, default=DEFAULT_WINDOW_MIN,
        help=f"How far back to look for correlated events (default: {DEFAULT_WINDOW_MIN})",
    )
    parser.add_argument(
        "--webhook-url", type=str, default=WEBHOOK_URL,
        help="Slack/webhook URL to route summaries to (overrides TRIAGE_WEBHOOK_URL)",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=POLL_INTERVAL,
        help=f"Seconds between poll cycles in poll mode (default: {POLL_INTERVAL})",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch events but do not call Claude or send webhooks",
    )
    args = parser.parse_args()

    if args.mode == "once":
        run_triage(
            window_minutes=args.window_minutes,
            environment=args.environment,
            webhook_url=args.webhook_url,
            dry_run=args.dry_run,
        )
    else:
        print(f"[triage] Poll mode: checking every {args.poll_interval}s "
              f"(window={args.window_minutes}m, env={args.environment or 'all'})")
        print("  Press Ctrl+C to stop.\n")
        while True:
            try:
                run_triage(
                    window_minutes=args.window_minutes,
                    environment=args.environment,
                    webhook_url=args.webhook_url,
                    dry_run=args.dry_run,
                )
                time.sleep(args.poll_interval)
            except KeyboardInterrupt:
                print("\n[triage] Stopped.")
                break


if __name__ == "__main__":
    main()
