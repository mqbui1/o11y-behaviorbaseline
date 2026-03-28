#!/usr/bin/env python3
"""
collect.py — All data fetching for the unified agent.

Responsible for:
  - Splunk API calls (topology, traces, events, SLO metrics)
  - Emitting custom events to Splunk ingest
  - Reading/writing open incident state (dedup)
  - Loading thresholds and baseline summaries

No reasoning happens here. This is pure I/O.
"""

import json
import os
import time
import urllib.error
import urllib.parse
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

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM        = os.environ.get("SPLUNK_REALM", "us0")

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

_DATA_DIR           = Path(__file__).parent / "data"
INCIDENT_STATE_PATH = Path(os.environ.get("INCIDENT_STATE_PATH", str(_DATA_DIR / "incident_state.{env}.json")))
THRESHOLDS_PATH     = Path(os.environ.get("THRESHOLDS_PATH", str(_DATA_DIR / "thresholds.json")))
HISTORY_PATH        = Path(os.environ.get("AGENT_HISTORY_PATH", str(_DATA_DIR / "agent_history.{env}.json")))

# Max cycles to retain in history
HISTORY_MAX_ENTRIES = int(os.environ.get("AGENT_HISTORY_MAX", "50"))


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
        raise RuntimeError(f"API {e.code}: {raw[:300]}")


def _signalflow(program: str, start_ms: int, end_ms: int,
                timeout: float = 15.0) -> list[dict]:
    """Execute a SignalFlow program and return all data messages."""
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
                line = raw_line.decode().strip()
                if line.startswith("data:"):
                    data_lines.append(line[5:].strip())
                elif line == "" and data_lines:
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
    except Exception:
        pass
    return results


# ── Topology ──────────────────────────────────────────────────────────────────

def fetch_topology(environment: str | None, lookback_hours: int = 2) -> dict:
    """
    Returns:
      {
        "services": [...],
        "callers_of": {"svc": ["caller1", ...]},
        "callees_of": {"svc": ["callee1", ...]},
        "edges": [("src", "dst"), ...]
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
        result    = _request("POST", "/v2/apm/topology", body)
        nodes     = (result.get("data") or {}).get("nodes", [])
        edges_raw = (result.get("data") or {}).get("edges", [])
        services  = [n["serviceName"] for n in nodes if not n.get("inferred")]
        edges     = [(e["fromNode"], e["toNode"]) for e in edges_raw
                     if e["fromNode"] != e["toNode"]]

        callers_of: dict[str, list] = defaultdict(list)
        callees_of: dict[str, list] = defaultdict(list)
        for src, dst in edges:
            callers_of[dst].append(src)
            callees_of[src].append(dst)

        return {
            "services":   services,
            "callers_of": dict(callers_of),
            "callees_of": dict(callees_of),
            "edges":      edges,
        }
    except Exception as e:
        return {"services": [], "callers_of": {}, "callees_of": {}, "edges": [],
                "error": str(e)}


# ── Anomaly events ────────────────────────────────────────────────────────────

def fetch_anomaly_events(environment: str | None,
                         window_minutes: int = 30) -> list[dict]:
    """
    Fetch trace.path.drift and error.signature.drift events from SignalFlow.
    Returns a simplified list of anomaly dicts.
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    events = []
    for event_type in ("trace.path.drift", "error.signature.drift"):
        if environment:
            program = (f"events(eventType='{event_type}', "
                       f"filter=filter('sf_environment', '{environment}')).publish()")
        else:
            program = f"events(eventType='{event_type}').publish()"

        for msg in _signalflow(program, start_ms, now_ms):
            dims  = msg.get("metadata", {})
            props = msg.get("properties", {})
            root_op = dims.get("root_operation", "")
            service = (dims.get("service") or props.get("service")
                       or (root_op.split(":")[0] if ":" in root_op else None)
                       or "unknown")
            events.append({
                "event_type":   event_type,
                "anomaly_type": dims.get("anomaly_type", ""),
                "service":      service,
                "environment":  dims.get("sf_environment") or props.get("environment", ""),
                "message":      props.get("message", ""),
                "detail":       props.get("detail", ""),
                "fp_hash":      dims.get("fp_hash") or props.get("fp_hash", ""),
                "timestamp_ms": props.get("timestamp") or now_ms,
            })

    # Sort oldest first
    events.sort(key=lambda e: e["timestamp_ms"])
    return events


def fetch_deployment_events(environment: str | None,
                            window_minutes: int = 120) -> list[dict]:
    """Fetch deployment.started events in the window."""
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    if environment:
        program = (f"events(eventType='deployment.started', "
                   f"filter=filter('sf_environment', '{environment}')).publish()")
    else:
        program = "events(eventType='deployment.started').publish()"

    deploys = []
    for msg in _signalflow(program, start_ms, now_ms):
        props = msg.get("properties", {})
        dims  = msg.get("metadata", {})
        deploys.append({
            "service":     props.get("service") or dims.get("service", ""),
            "version":     props.get("version", ""),
            "environment": props.get("environment") or dims.get("sf_environment", ""),
            "timestamp_ms": props.get("timestamp") or now_ms,
        })

    deploys.sort(key=lambda d: d["timestamp_ms"])
    return deploys


# ── SLO / metrics ─────────────────────────────────────────────────────────────

def fetch_slo_status(services: list[str], environment: str | None,
                     window_minutes: int = 30) -> dict[str, dict]:
    """
    Returns per-service error rate and p99 latency from SignalFlow.
    Uses spans.count metric.  Falls back to empty dict on failure.

    Returns:
      {
        "api-gateway": {"error_rate": 0.02, "p99_ms": 380, "burn_rate": 2.1},
        ...
      }
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    TARGET_ERROR_RATE = 0.005   # 0.5% SLO — reasonable default
    results: dict[str, dict] = {}

    for svc in services:
        try:
            env_filter = (f"filter('sf_environment', '{environment}') and "
                          if environment else "")
            program = (
                f"A = spans.count(filter={env_filter}"
                f"filter('sf_service', '{svc}') and filter('sf_error', 'true'))"
                f".sum(over='5m').publish('errors')\n"
                f"B = spans.count(filter={env_filter}"
                f"filter('sf_service', '{svc}')).sum(over='5m').publish('total')"
            )
            msgs = _signalflow(program, start_ms, now_ms, timeout=10.0)
            errors = total = 0
            for m in msgs:
                label = (m.get("metadata") or {}).get("sf_streamLabel", "")
                val   = (m.get("data") or {}).get("value")
                if val is None:
                    continue
                if label == "errors":
                    errors = max(errors, val)
                elif label == "total":
                    total  = max(total,  val)

            error_rate = (errors / total) if total > 0 else 0.0
            burn_rate  = error_rate / TARGET_ERROR_RATE if TARGET_ERROR_RATE > 0 else 0.0
            results[svc] = {
                "error_rate": round(error_rate, 4),
                "burn_rate":  round(burn_rate, 2),
                "p99_ms":     None,  # requires histogram metric; omit for now
            }
        except Exception:
            results[svc] = {"error_rate": None, "burn_rate": None, "p99_ms": None}

    return results


# ── Coverage summary ──────────────────────────────────────────────────────────

def fetch_coverage_summary(environment: str | None,
                            baseline_fps: dict) -> dict[str, float | None]:
    """
    Quick coverage estimate: for each root_op in the baseline, return the
    number of known fingerprints.  Full live-trace matching is too slow for
    the agent loop — that's coverage_auditor.py's job on a longer schedule.

    Returns: {"api-gateway:GET /owners": 4, "vets-service:GET": 1, ...}
    """
    coverage: dict[str, int] = defaultdict(int)
    for fp in baseline_fps.values():
        root_op = fp.get("root_op", "")
        if root_op:
            coverage[root_op] += 1
    return dict(coverage)


# ── Open incidents (dedup state) ───────────────────────────────────────────────

def _incident_state_path(environment: str | None) -> Path:
    env = environment or "all"
    return Path(str(INCIDENT_STATE_PATH).replace("{env}", env))


def fetch_open_incidents(environment: str | None) -> list[dict]:
    """Load open incident groups from the dedup state file."""
    p = _incident_state_path(environment)
    if not p.exists():
        return []
    try:
        state = json.loads(p.read_text())
        return [v for v in state.get("incidents", {}).values()
                if v.get("state") == "OPEN"]
    except Exception:
        return []


def save_incident_state(environment: str | None, incidents: dict) -> None:
    p = _incident_state_path(environment)
    state = {"incidents": incidents,
             "updated_at": datetime.now(timezone.utc).isoformat()}
    p.write_text(json.dumps(state, indent=2))


# ── Thresholds ────────────────────────────────────────────────────────────────

def load_thresholds() -> dict:
    if THRESHOLDS_PATH.exists():
        try:
            return json.loads(THRESHOLDS_PATH.read_text())
        except Exception:
            pass
    return {"services": {}}


def save_thresholds(thresholds: dict) -> None:
    THRESHOLDS_PATH.write_text(json.dumps(thresholds, indent=2))


def update_threshold(service: str, updates: dict) -> None:
    t = load_thresholds()
    t.setdefault("services", {}).setdefault(service, {}).update(updates)
    save_thresholds(t)


# ── Event emission ────────────────────────────────────────────────────────────

# ── Agent history (feedback loop) ────────────────────────────────────────────

def _history_path(environment: str | None) -> Path:
    env = environment or "all"
    return Path(str(HISTORY_PATH).replace("{env}", env))


def load_history(environment: str | None, max_entries: int = 20) -> list[dict]:
    """
    Load the most recent N agent cycles from history.
    Each entry: {timestamp, severity, assessment, root_cause, actions, outcomes}
    """
    p = _history_path(environment)
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text())
        entries = data.get("cycles", [])
        return entries[-max_entries:]
    except Exception:
        return []


def append_history(environment: str | None, cycle: dict) -> None:
    """
    Append one completed agent cycle to history.
    Trims to HISTORY_MAX_ENTRIES automatically.
    """
    p = _history_path(environment)
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = json.loads(p.read_text()) if p.exists() else {"cycles": []}
    except Exception:
        data = {"cycles": []}

    data["cycles"].append(cycle)
    # Keep only the most recent N entries
    if len(data["cycles"]) > HISTORY_MAX_ENTRIES:
        data["cycles"] = data["cycles"][-HISTORY_MAX_ENTRIES:]
    data["updated_at"] = datetime.now(timezone.utc).isoformat()

    p.write_text(json.dumps(data, indent=2))


def summarize_history(history: list[dict]) -> dict:
    """
    Compress history into a Claude-friendly summary.
    Returns counts + recent patterns — not the full raw list.
    """
    if not history:
        return {"cycles": 0}

    severity_counts: dict[str, int] = defaultdict(int)
    suppressed_patterns: dict[str, int] = defaultdict(int)  # service → suppress count
    paged_patterns: dict[str, int]      = defaultdict(int)  # service → page count
    relearn_count = 0

    for cycle in history:
        severity_counts[cycle.get("severity", "OK")] += 1
        for action in cycle.get("actions", []):
            atype   = action.get("type", "")
            service = action.get("service") or "all"
            if atype == "SUPPRESS_ANOMALY":
                suppressed_patterns[service] += 1
            elif atype == "PAGE_ONCALL":
                paged_patterns[service] += 1
            elif atype == "RELEARN_BASELINE":
                relearn_count += 1

    # Most recent 3 assessments for context
    recent = [
        {"timestamp": c.get("timestamp"), "severity": c.get("severity"),
         "assessment": c.get("assessment"), "root_cause": c.get("root_cause")}
        for c in history[-3:]
    ]

    return {
        "cycles":              len(history),
        "severity_counts":     dict(severity_counts),
        "frequent_suppressions": {k: v for k, v in suppressed_patterns.items() if v >= 2},
        "paged_services":      dict(paged_patterns),
        "baseline_relearns":   relearn_count,
        "recent_cycles":       recent,
    }


# ── Alert log ─────────────────────────────────────────────────────────────────

ALERT_LOG_PATH = Path(os.environ.get("ALERT_LOG_PATH",
                                      str(_DATA_DIR / "alerts.log")))

_SEP = "─" * 72


def log_alert(kind: str, fields: dict) -> None:
    """
    Append a structured entry to data/alerts.log.

    kind: "DETECTION" | "TRIAGE"
    fields: arbitrary key-value pairs to display.

    Format:
    ══════════════════════════════════════════════════════════════════════════
    [2026-03-28 04:12:33 UTC]  DETECTION
      anomaly_type : MISSING_SERVICE
      service      : vets-service
      ...
    ──────────────────────────────────────────────────────────────────────────
    """
    ALERT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "",
        "═" * 72,
        f"[{ts}]  {kind}",
    ]
    for k, v in fields.items():
        if v is None or v == "" or v == "none":
            continue
        label = k.replace("_", " ").ljust(20)
        # Wrap long values at 72 chars after the label
        val_str = str(v)
        if len(val_str) > 52:
            lines.append(f"  {label} : {val_str[:52]}")
            for chunk in [val_str[i:i+70] for i in range(52, len(val_str), 70)]:
                lines.append(f"  {'':20}   {chunk}")
        else:
            lines.append(f"  {label} : {val_str}")
    lines.append(_SEP)

    entry = "\n".join(lines) + "\n"
    with open(ALERT_LOG_PATH, "a") as f:
        f.write(entry)


# ── Event + metric emission ───────────────────────────────────────────────────

def emit_metric(metric_name: str, value: int, dimensions: dict) -> None:
    """Emit a gauge metric — immediately queryable via SignalFlow data()."""
    try:
        _request("POST", "/v2/datapoint", {
            "gauge": [{
                "metric":     metric_name,
                "value":      value,
                "dimensions": dimensions,
                "timestamp":  int(time.time() * 1000),
            }],
        }, base_url=INGEST_URL)
    except Exception as e:
        import sys
        print(f"  [warn] emit_metric {metric_name}: {e}", file=sys.stderr)


def emit_event(event_type: str, properties: dict,
               dimensions: dict | None = None) -> None:
    """Emit a custom event to Splunk ingest, plus a metric for dashboard visibility."""
    dims = {"sf_environment": properties.get("environment", "all")}
    if dimensions:
        dims.update(dimensions)
    if "service" in properties:
        dims["service"] = properties["service"]

    payload = [{
        "eventType":  event_type,
        "category":   "ALERT",
        "dimensions": dims,
        "properties": properties,
        "timestamp":  int(time.time() * 1000),
    }]
    try:
        _request("POST", "/v2/event", payload, base_url=INGEST_URL)
    except Exception as e:
        import sys
        print(f"  [warn] emit_event {event_type}: {e}", file=sys.stderr)

    # Also emit a queryable metric for each agent action/page event
    action = properties.get("action") or properties.get("severity")
    if event_type == "behavioral_baseline.agent.action" and action:
        metric_dims = {
            "sf_environment": dims.get("sf_environment", "all"),
            "service":        dims.get("service", "all"),
            "action":         properties.get("action", ""),
            "severity":       properties.get("severity", ""),
        }
        emit_metric("behavioral_baseline.agent.action.count", 1, metric_dims)
    elif event_type == "behavioral_baseline.oncall.page":
        emit_metric("behavioral_baseline.agent.action.count", 1, {
            "sf_environment": dims.get("sf_environment", "all"),
            "service":        dims.get("service", "all"),
            "action":         "PAGE_ONCALL",
            "severity":       properties.get("severity", "INCIDENT"),
        })
