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

INCIDENT_STATE_PATH = Path(os.environ.get("INCIDENT_STATE_PATH", "./incident_state.{env}.json"))
THRESHOLDS_PATH     = Path(os.environ.get("THRESHOLDS_PATH", "./thresholds.json"))


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

def emit_event(event_type: str, properties: dict,
               dimensions: dict | None = None) -> None:
    """Emit a custom event to Splunk ingest."""
    dims = {"environment": properties.get("environment", "all")}
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
