#!/usr/bin/env python3
"""
Behavioral Baseline — Anomaly Deduplication Agent
===================================================
Prevents identical anomalies from flooding the correlation engine and
dashboard when a single incident spans multiple watch cycles.

Problem:
  vets-service goes down at 14:00. Watch runs at 14:00, 14:05, 14:10, ...
  Each cycle emits MISSING_SERVICE × N traces. After 30 minutes you have
  30+ identical events. correlate.py fires every cycle. triage_agent.py
  re-triages the same incident 6 times. Dashboard is unreadable.

Solution:
  This agent sits between the raw event stream and the correlation engine.
  It maintains an in-memory (+ optional disk) incident state table:
    - Groups anomaly events by (service, anomaly_type, fingerprint_key)
    - First occurrence of a group → OPEN: forward to correlate, emit incident.opened
    - Subsequent identical occurrences → SUPPRESSED: count but don't re-emit
    - When a group stops firing for RESOLVE_AFTER_MINUTES → RESOLVED: emit incident.resolved
    - If an OPEN incident changes character (new anomaly_type or different services)
      → ESCALATED: re-emit with escalation flag

  The dedup state is stored in dedup_state.<env>.json so it survives restarts.

Usage:
  # Replace direct correlate.py invocation:
  python dedup_agent.py --environment petclinicmbtest --window-minutes 5
  # The agent reads raw events, deduplicates, then runs correlate logic
  # on the filtered unique-incident set only.

  # Or run standalone to inspect current incident state:
  python dedup_agent.py --environment petclinicmbtest --show

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
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
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# An open incident group is resolved when it stops firing for this many minutes
RESOLVE_AFTER_MINUTES = int(os.environ.get("DEDUP_RESOLVE_MINUTES", "15"))

# Anomaly event types to watch
ANOMALY_EVENT_TYPES = ["trace.path.drift", "error.signature.drift"]

# Dedup state file path template
DEDUP_STATE_PATH = Path(os.environ.get("DEDUP_STATE_PATH", "./dedup_state.{env}.json"))


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL) -> Any:
    url     = f"{base_url}{path}"
    token   = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"API {e.code}: {raw[:200]}")


def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 12.0) -> list[dict]:
    program = f'events(eventType="{event_type}").publish()'
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
                line = raw_line.decode()
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


# ── State management ──────────────────────────────────────────────────────────

def _state_path(environment: str | None) -> Path:
    env = environment or "all"
    return Path(str(DEDUP_STATE_PATH).replace("{env}", env))


def load_state(environment: str | None) -> dict:
    p = _state_path(environment)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"incidents": {}, "updated_at": None}


def save_state(state: dict, environment: str | None) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    _state_path(environment).write_text(json.dumps(state, indent=2))


# ── Incident key ─────────────────────────────────────────────────────────────

def _incident_key(service: str, anomaly_type: str,
                   fingerprint_key: str | None) -> str:
    """
    Stable key that identifies a unique incident group.
    fingerprint_key is the fp_hash for NEW_FINGERPRINT / MISSING_SERVICE,
    or error_type+operation for error signatures.
    """
    fp = fingerprint_key or "any"
    return f"{service}|{anomaly_type}|{fp}"


def _extract_fingerprint_key(msg: dict) -> str | None:
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})
    return (
        dims.get("fp_hash")
        or dims.get("hash")
        or props.get("fp_hash")
        or f"{props.get('error_type','')}/{props.get('operation','')}"
        or None
    )


def _extract_service(msg: dict) -> str | None:
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})
    root_op = dims.get("root_operation", "")
    return (
        dims.get("service")
        or props.get("service")
        or (root_op.split(":")[0] if ":" in root_op else None)
        or (props.get("services", "").split(",")[0].strip() or None)
    )


# ── Core dedup logic ──────────────────────────────────────────────────────────

class IncidentGroup:
    """Represents a deduplicated incident group."""

    def __init__(self, key: str, service: str, anomaly_type: str,
                 first_event: dict, environment: str | None):
        now = datetime.now(timezone.utc)
        self.key           = key
        self.service       = service
        self.anomaly_type  = anomaly_type
        self.environment   = environment
        self.state         = "OPEN"        # OPEN | RESOLVED | ESCALATED
        self.opened_at     = now.isoformat()
        self.last_seen_at  = now.isoformat()
        self.resolved_at:  str | None = None
        self.fire_count    = 1
        self.suppressed    = 0
        self.first_message = (first_event.get("properties") or {}).get("message", "")
        self.first_detail  = (first_event.get("properties") or {}).get("detail", "")
        self.anomaly_types: set[str] = {anomaly_type}

    def to_dict(self) -> dict:
        return {
            "key":           self.key,
            "service":       self.service,
            "anomaly_type":  self.anomaly_type,
            "environment":   self.environment,
            "state":         self.state,
            "opened_at":     self.opened_at,
            "last_seen_at":  self.last_seen_at,
            "resolved_at":   self.resolved_at,
            "fire_count":    self.fire_count,
            "suppressed":    self.suppressed,
            "first_message": self.first_message,
            "first_detail":  self.first_detail,
            "anomaly_types": sorted(self.anomaly_types),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "IncidentGroup":
        obj = cls.__new__(cls)
        obj.__dict__.update(d)
        obj.anomaly_types = set(d.get("anomaly_types", [d.get("anomaly_type", "")]))
        return obj

    def minutes_since_last_seen(self) -> float:
        try:
            dt = datetime.fromisoformat(self.last_seen_at)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).total_seconds() / 60
        except Exception:
            return 0.0


def process_events(raw_events: list[dict], state: dict,
                   environment: str | None) -> dict:
    """
    Process a batch of raw anomaly events through the dedup engine.

    Returns:
      {
        new_incidents:      [IncidentGroup],   # first-time fires → forward
        escalated:          [IncidentGroup],   # changed character → re-forward
        suppressed_count:   int,               # duplicates eaten
        resolved:           [IncidentGroup],   # incidents that timed out
      }
    """
    incidents: dict[str, IncidentGroup] = {
        k: IncidentGroup.from_dict(v)
        for k, v in state.get("incidents", {}).items()
    }

    new_incidents: list[IncidentGroup] = []
    escalated:     list[IncidentGroup] = []
    suppressed_count = 0
    now_ms = int(time.time() * 1000)

    # Check for resolutions (incidents silent for RESOLVE_AFTER_MINUTES)
    resolved: list[IncidentGroup] = []
    for key, inc in list(incidents.items()):
        if inc.state == "OPEN" and inc.minutes_since_last_seen() >= RESOLVE_AFTER_MINUTES:
            inc.state       = "RESOLVED"
            inc.resolved_at = datetime.now(timezone.utc).isoformat()
            resolved.append(inc)

    # Process incoming events
    for msg in raw_events:
        dims      = msg.get("metadata", {})
        props     = msg.get("properties", {})
        event_env = dims.get("environment") or props.get("environment", "all")
        if environment and event_env not in (environment, "all"):
            continue

        service      = _extract_service(msg)
        anomaly_type = dims.get("anomaly_type", "")
        fp_key       = _extract_fingerprint_key(msg)

        if not service or not anomaly_type:
            continue

        key = _incident_key(service, anomaly_type, fp_key)

        if key not in incidents:
            # Brand new incident — open it and forward
            inc = IncidentGroup(key, service, anomaly_type, msg, environment)
            incidents[key] = inc
            new_incidents.append(inc)
        else:
            inc = incidents[key]
            inc.last_seen_at = datetime.now(timezone.utc).isoformat()
            inc.fire_count  += 1

            if inc.state == "RESOLVED":
                # Resolved incident re-fired → reopen as new
                inc.state      = "OPEN"
                inc.resolved_at = None
                new_incidents.append(inc)
            elif inc.state == "OPEN":
                # Check for escalation: new anomaly type for same service
                if anomaly_type not in inc.anomaly_types:
                    inc.anomaly_types.add(anomaly_type)
                    inc.state = "ESCALATED"
                    escalated.append(inc)
                else:
                    inc.suppressed += 1
                    suppressed_count += 1

    # Persist updated state
    state["incidents"] = {k: v.to_dict() for k, v in incidents.items()}

    return {
        "new_incidents":    new_incidents,
        "escalated":        escalated,
        "suppressed_count": suppressed_count,
        "resolved":         resolved,
    }


# ── Event emission ────────────────────────────────────────────────────────────

def _emit_incident_event(event_type: str, inc: IncidentGroup,
                          extra_props: dict | None = None) -> None:
    props = {
        "message":      inc.first_message,
        "detail":       inc.first_detail,
        "service":      inc.service,
        "anomaly_type": inc.anomaly_type,
        "anomaly_types": ",".join(sorted(inc.anomaly_types)),
        "fire_count":   inc.fire_count,
        "suppressed":   inc.suppressed,
        "opened_at":    inc.opened_at,
        "environment":  inc.environment or "all",
    }
    if extra_props:
        props.update(extra_props)
    try:
        _request("POST", "/v2/event", [{
            "eventType":  event_type,
            "category":   "ALERT",
            "dimensions": {
                "service":      inc.service,
                "anomaly_type": inc.anomaly_type,
                "environment":  inc.environment or "all",
                "incident_state": inc.state,
            },
            "properties": props,
            "timestamp":  int(time.time() * 1000),
        }], base_url=INGEST_URL)
    except Exception as e:
        print(f"  [warn] emit {event_type}: {e}", file=sys.stderr)


# ── Main run ──────────────────────────────────────────────────────────────────

def run(window_minutes: int, environment: str | None,
        dry_run: bool = False) -> None:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000
    env_desc = environment or "all"

    print(f"[dedup] Fetching anomaly events ({window_minutes}m, env={env_desc})...")
    raw_events: list[dict] = []
    for et in ANOMALY_EVENT_TYPES:
        raw_events.extend(_signalflow_events(et, start_ms, now_ms))
    print(f"  {len(raw_events)} raw event(s) received")

    state  = load_state(environment)
    result = process_events(raw_events, state, environment)

    new    = result["new_incidents"]
    esc    = result["escalated"]
    sup    = result["suppressed_count"]
    res    = result["resolved"]

    print(f"  {len(new)} new incident(s), {len(esc)} escalation(s), "
          f"{sup} suppressed, {len(res)} resolved")

    for inc in new:
        print(f"\n  [NEW] {inc.anomaly_type} on {inc.service}")
        print(f"    {inc.first_message}")
        if not dry_run:
            _emit_incident_event("behavioral_baseline.incident.opened", inc)
            print(f"    → incident.opened emitted")

    for inc in esc:
        print(f"\n  [ESCALATED] {inc.service}: "
              f"now {', '.join(sorted(inc.anomaly_types))}")
        if not dry_run:
            _emit_incident_event("behavioral_baseline.incident.escalated", inc,
                                  {"new_anomaly_types": ",".join(sorted(inc.anomaly_types))})
            print(f"    → incident.escalated emitted")

    for inc in res:
        dur_min = 0
        try:
            opened = datetime.fromisoformat(inc.opened_at)
            if opened.tzinfo is None:
                opened = opened.replace(tzinfo=timezone.utc)
            dur_min = int((datetime.now(timezone.utc) - opened).total_seconds() / 60)
        except Exception:
            pass
        print(f"\n  [RESOLVED] {inc.anomaly_type} on {inc.service} "
              f"(open {dur_min}m, {inc.fire_count} fires, {inc.suppressed} suppressed)")
        if not dry_run:
            _emit_incident_event("behavioral_baseline.incident.resolved", inc,
                                  {"duration_minutes": dur_min,
                                   "resolved_at": inc.resolved_at or ""})
            print(f"    → incident.resolved emitted")

    if not dry_run:
        save_state(state, environment)

    if sup > 0:
        print(f"\n  Suppressed {sup} duplicate event(s) — "
              f"correlation engine protected from flood.")


def show(environment: str | None) -> None:
    state = load_state(environment)
    incidents = state.get("incidents", {})
    if not incidents:
        print(f"No open incidents for '{environment or 'all'}'.")
        return

    open_   = [v for v in incidents.values() if v["state"] == "OPEN"]
    res_    = [v for v in incidents.values() if v["state"] == "RESOLVED"]
    print(f"\nIncident state for '{environment or 'all'}' "
          f"({len(open_)} open, {len(res_)} resolved):\n")

    for inc in sorted(open_, key=lambda x: x["opened_at"], reverse=True):
        print(f"  OPEN   {inc['service']}:{inc['anomaly_type']}  "
              f"fires={inc['fire_count']}  suppressed={inc['suppressed']}  "
              f"opened={inc['opened_at'][:19]}")
    for inc in sorted(res_, key=lambda x: x.get("resolved_at",""), reverse=True)[:5]:
        print(f"  CLOSED {inc['service']}:{inc['anomaly_type']}  "
              f"fires={inc['fire_count']}  resolved={inc.get('resolved_at','?')[:19]}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Anomaly Deduplication Agent — prevents incident floods"
    )
    parser.add_argument("--environment", default=None)
    parser.add_argument("--window-minutes", type=int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--show", action="store_true",
                        help="Show current incident state and exit")
    args = parser.parse_args()

    if args.show:
        show(args.environment)
        return

    run(args.window_minutes, args.environment, args.dry_run)


if __name__ == "__main__":
    main()
