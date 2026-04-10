#!/usr/bin/env python3
"""
watch_otel_events.py — Triage OTel edge detector events from Splunk.
=====================================================================
Queries Splunk SignalFlow for recent trace.path.drift and
error.signature.drift events emitted by the OTel collector edge processor,
formats them as agent.py-compatible JSON, and writes to stdout.

Usage:
  python3 watch_otel_events.py --environment bdf-7fdc-workshop | python3 agent.py --environment bdf-7fdc-workshop

  # Narrow window (default 5m — covers OTel events since the last check):
  python3 watch_otel_events.py --environment bdf-7fdc-workshop --window-minutes 5

  # Dedup: skip events whose hash was already seen within TTL seconds (default 120)
  python3 watch_otel_events.py --environment bdf-7fdc-workshop --dedup-ttl 120

The output is a single JSON line matching the schema agent.py expects:
  {"environment": "...", "anomalies": [...], "window_minutes": N, ...}

Required env vars (loaded from .env if present):
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM          (default: us1)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ── Config ─────────────────────────────────────────────────────────────────────

_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
REALM        = os.environ.get("SPLUNK_REALM", "us1")
STREAM_URL   = f"https://stream.{REALM}.signalfx.com"

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

# ── Dedup state file ───────────────────────────────────────────────────────────

_DEDUP_DIR = Path(__file__).parent / "data"

def _dedup_path(env: str) -> Path:
    return _DEDUP_DIR / f"otel_dedup_state.{env}.json"

def _load_dedup(env: str) -> dict:
    p = _dedup_path(env)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _save_dedup(env: str, state: dict) -> None:
    _dedup_path(env).write_text(json.dumps(state))

# ── SignalFlow query ───────────────────────────────────────────────────────────

def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 15.0) -> list[dict]:
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
                line = raw_line.decode()
                stripped = line.strip()
                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    payload = "".join(data_lines)
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
        print(f"  [warn] SignalFlow query for {event_type}: {e}", file=sys.stderr)
    return results


# ── Event → anomaly conversion ─────────────────────────────────────────────────

def _trace_drift_to_anomaly(msg: dict, environment: str | None) -> dict | None:
    """Convert a trace.path.drift SignalFlow event to an agent.py anomaly dict."""
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})

    event_env = dims.get("sf_environment") or props.get("environment")
    if environment and event_env and event_env not in (environment, "all"):
        return None

    root_op  = props.get("root_op") or dims.get("root_operation", "")
    services = [s for s in props.get("services", "").split(",") if s]
    fp_hash  = props.get("hash") or dims.get("fp_hash", "")
    trace_id = props.get("trace_id", "")
    path     = props.get("path", "")

    service = dims.get("service") or (root_op.split(":")[0] if ":" in root_op else root_op)

    return {
        "anomaly_type":  "NEW_FINGERPRINT",
        "service":       service,
        "root_op":       root_op,
        "message":       f"Trace path drift on '{root_op}' (OTel edge detector)",
        "detail":        f"Path: {path}" if path else "",
        "trace_id":      trace_id,
        "hash":          fp_hash,
        "services":      services,
        "source":        "otel-edge",
        "timestamp_ms":  msg.get("timestampMs", 0),
    }


def _error_drift_to_anomaly(msg: dict, environment: str | None) -> dict | None:
    """Convert an error.signature.drift SignalFlow event to an agent.py anomaly dict."""
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})

    event_env = dims.get("sf_environment") or props.get("environment")
    if environment and event_env and event_env not in (environment, "all"):
        return None

    service    = dims.get("service") or props.get("service", "")
    error_type = dims.get("error_type") or props.get("error_type", "")
    operation  = props.get("operation", "")
    call_path  = props.get("call_path", "")
    sig_hash   = props.get("hash") or dims.get("sig_hash", "")
    trace_id   = props.get("trace_id", "")

    return {
        "anomaly_type":  "NEW_ERROR_SIGNATURE",
        "service":       service,
        "message":       f"New error signature in {service}: {error_type} on {operation}",
        "error_type":    error_type,
        "operation":     operation,
        "call_path":     call_path,
        "trace_id":      trace_id,
        "hash":          sig_hash,
        "source":        "otel-edge",
        "timestamp_ms":  msg.get("timestampMs", 0),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch OTel edge drift events from Splunk and emit as agent.py JSON"
    )
    parser.add_argument("--environment", required=True,
                        help="Splunk APM environment filter")
    parser.add_argument("--window-minutes", type=int, default=5,
                        help="How far back to query (default: 5)")
    parser.add_argument("--dedup-ttl", type=int, default=120,
                        help="Suppress events whose hash was seen within this many seconds (default: 120)")
    parser.add_argument("--no-dedup", action="store_true",
                        help="Disable hash deduplication (show all events in window)")
    args = parser.parse_args()

    env          = args.environment
    window_ms    = args.window_minutes * 60 * 1000
    now_ms       = int(time.time() * 1000)
    start_ms     = now_ms - window_ms
    dedup_ttl_ms = args.dedup_ttl * 1000

    # Load dedup state
    dedup_state = {} if args.no_dedup else _load_dedup(env)
    # Expire old entries
    dedup_state = {h: ts for h, ts in dedup_state.items() if now_ms - ts < dedup_ttl_ms}

    # Fetch both event types in parallel
    import threading
    trace_events: list[dict] = []
    error_events: list[dict] = []

    def _fetch_trace():
        trace_events.extend(_signalflow_events("trace.path.drift", start_ms, now_ms))

    def _fetch_error():
        error_events.extend(_signalflow_events("error.signature.drift", start_ms, now_ms))

    t1 = threading.Thread(target=_fetch_trace)
    t2 = threading.Thread(target=_fetch_error)
    t1.start(); t2.start()
    t1.join();  t2.join()

    # Convert to anomaly dicts, apply dedup
    anomalies = []
    new_dedup  = dict(dedup_state)

    for msg in sorted(trace_events + error_events, key=lambda m: m.get("timestampMs", 0)):
        is_trace = msg in trace_events
        anomaly = (_trace_drift_to_anomaly if is_trace else _error_drift_to_anomaly)(msg, env)
        if anomaly is None:
            continue

        h = anomaly.get("hash", "")
        if h and not args.no_dedup:
            last_seen = dedup_state.get(h, 0)
            if now_ms - last_seen < dedup_ttl_ms:
                continue
            new_dedup[h] = now_ms

        anomalies.append(anomaly)

    # Save updated dedup state
    if not args.no_dedup:
        _save_dedup(env, new_dedup)

    result = {
        "environment":    env,
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "window_minutes": args.window_minutes,
        "source":         "otel-edge",
        "checked":        len(trace_events) + len(error_events),
        "anomalies":      anomalies,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
