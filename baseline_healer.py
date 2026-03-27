#!/usr/bin/env python3
"""
Behavioral Baseline — Self-Healing Baseline Agent
==================================================
Monitors the anomaly event rate and autonomously re-baselines after incidents
resolve. Eliminates the need for manual --reset --window-offset-minutes judgment.

How it works:
  1. MONITOR  — watches trace.path.drift and error.signature.drift event rates
                over rolling windows. Detects a spike (incident start) followed
                by a drop back to near-zero (incident resolved).

  2. SCORE    — when resolution is detected, evaluates N candidate pre-incident
                windows by two metrics:
                  - error_rate: fraction of traces with error spans (lower = cleaner)
                  - trace_diversity: unique fingerprint count (higher = richer baseline)
                Picks the window with best combined score.

  3. HEAL     — runs trace_fingerprint learn + error_fingerprint learn with
                --reset on the winning window. No human judgment required.

  4. REPORT   — emits a baseline.healed custom event to Splunk with the chosen
                window, scores, and reason.

Usage:
  python baseline_healer.py --environment petclinicmbtest
  python baseline_healer.py --environment petclinicmbtest --mode once
  python baseline_healer.py --environment petclinicmbtest --dry-run

Modes:
  poll (default) — continuously monitors; heals whenever an incident resolves
  once           — evaluate right now and heal if conditions are met, then exit

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
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
APP_URL    = f"https://app.{REALM}.signalfx.com"

# Anomaly event types to monitor for rate changes
ANOMALY_EVENT_TYPES = ["trace.path.drift", "error.signature.drift"]

# How many events/minute qualifies as a "spike" (incident active)
SPIKE_THRESHOLD = float(os.environ.get("HEALER_SPIKE_THRESHOLD", "1.0"))

# Rate must drop below this to be considered "resolved"
RESOLVED_THRESHOLD = float(os.environ.get("HEALER_RESOLVED_THRESHOLD", "0.2"))

# Minimum spike duration before we consider it a real incident (not noise)
MIN_SPIKE_MINUTES = int(os.environ.get("HEALER_MIN_SPIKE_MINUTES", "5"))

# How long after resolution to wait before re-baselining (let system stabilize)
STABILIZATION_MINUTES = int(os.environ.get("HEALER_STABILIZATION_MINUTES", "5"))

# Candidate pre-incident windows to score (offset, duration) in minutes
# Each tuple: (how far before incident start, window duration)
CANDIDATE_WINDOWS = [
    (30,  60),   # 30-90 min before incident
    (60,  60),   # 60-120 min before incident
    (120, 120),  # 2-4h before incident
    (240, 120),  # 4-6h before incident
]

# Polling interval in seconds
POLL_INTERVAL = int(os.environ.get("HEALER_POLL_INTERVAL", "60"))

# Window used to measure current anomaly rate (minutes)
RATE_WINDOW_MINUTES = int(os.environ.get("HEALER_RATE_WINDOW_MINUTES", "10"))

# Minimum traces needed in a window to be scoreable
MIN_TRACES_FOR_SCORING = int(os.environ.get("HEALER_MIN_TRACES", "10"))

# Script paths
_SCRIPT_DIR = Path(__file__).parent
TRACE_FP    = str(_SCRIPT_DIR / "trace_fingerprint.py")
ERROR_FP    = str(_SCRIPT_DIR / "error_fingerprint.py")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

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
                        results.append(msg)
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [warn] SignalFlow {event_type}: {e}", file=sys.stderr)
    return results


# ── Anomaly rate measurement ───────────────────────────────────────────────────

def measure_anomaly_rate(start_ms: int, end_ms: int,
                          environment: str | None) -> float:
    """
    Count anomaly events in the window and return events/minute.
    Queries all ANOMALY_EVENT_TYPES in parallel (sequentially here for simplicity).
    """
    total = 0
    for et in ANOMALY_EVENT_TYPES:
        events = _signalflow_events(et, start_ms, end_ms)
        for msg in events:
            dims      = msg.get("metadata", {})
            event_env = dims.get("environment") or msg.get("properties", {}).get("environment")
            if environment and event_env and event_env not in (environment, "all"):
                continue
            total += 1
    duration_minutes = (end_ms - start_ms) / 60000
    return total / duration_minutes if duration_minutes > 0 else 0.0


# ── Window scoring ─────────────────────────────────────────────────────────────

def _fetch_traces_for_window(start_ms: int, end_ms: int,
                              environment: str | None,
                              limit: int = 100) -> list[dict]:
    """Fetch a sample of traces in the given window for scoring."""
    tag_filters: list[dict] = []
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN",
                             "values": [environment]})
    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": end_ms},
            "filters": ([{"traceFilter": {"tags": tag_filters},
                          "filterType": "traceFilter"}] if tag_filters else []),
            "samplingFactor": 100,
        },
        "sectionsParameters": [{"sectionType": "traceExamples", "limit": limit}],
    }
    start_body = {
        "operationName": "StartAnalyticsSearch",
        "variables":     {"parameters": parameters},
        "query": ("query StartAnalyticsSearch($parameters: JSON!) "
                  "{ startAnalyticsSearch(parameters: $parameters) }"),
    }
    try:
        r = _request("POST", "/v2/apm/graphql?op=StartAnalyticsSearch",
                     start_body, base_url=APP_URL)
        job_id = (((r.get("data") or {}).get("startAnalyticsSearch") or {})
                  .get("jobId"))
        if not job_id:
            return []
        get_body = {
            "operationName": "GetAnalyticsSearch",
            "variables":     {"jobId": job_id},
            "query": ("query GetAnalyticsSearch($jobId: ID!) "
                      "{ getAnalyticsSearch(jobId: $jobId) }"),
        }
        delay, elapsed = 0.1, 0.0
        while elapsed < 15.0:
            r2 = _request("POST", "/v2/apm/graphql?op=GetAnalyticsSearch",
                          get_body, base_url=APP_URL)
            sections = (((r2.get("data") or {}).get("getAnalyticsSearch") or {})
                        .get("sections", []))
            for section in sections:
                if section.get("sectionType") == "traceExamples":
                    if section.get("isComplete"):
                        return section.get("legacyTraceExamples") or []
            time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, 2.0)
    except Exception as e:
        print(f"  [warn] trace fetch for scoring: {e}", file=sys.stderr)
    return []


def _get_trace_full(trace_id: str) -> dict | None:
    query = (
        "query TraceFullDetailsLessValidation($id: ID!) {"
        " trace(id: $id) { traceID spans {"
        " spanID serviceName operationName startTime duration"
        " tags { key value } } } }"
    )
    try:
        r = _request("POST", "/v2/apm/graphql?op=TraceFullDetailsLessValidation",
                     {"operationName": "TraceFullDetailsLessValidation",
                      "variables": {"id": trace_id}, "query": query},
                     base_url=APP_URL)
        return (r.get("data") or {}).get("trace")
    except Exception:
        return None


def score_window(start_ms: int, end_ms: int, environment: str | None,
                 label: str) -> dict:
    """
    Score a candidate baseline window.
    Returns: {label, start_ms, end_ms, trace_count, error_rate,
              diversity, score, scoreable}
    score = (1 - error_rate) * 0.6 + normalized_diversity * 0.4
    Higher is better.
    """
    print(f"    Scoring window {label}...")
    examples = _fetch_traces_for_window(start_ms, end_ms, environment, limit=80)
    trace_count = len(examples)

    if trace_count < MIN_TRACES_FOR_SCORING:
        print(f"      Too few traces ({trace_count}) — skipping")
        return {"label": label, "start_ms": start_ms, "end_ms": end_ms,
                "trace_count": trace_count, "error_rate": 1.0,
                "diversity": 0, "score": 0.0, "scoreable": False}

    # Fetch full spans for a subset to measure error rate
    sample_ids = [
        e.get("traceId") or e.get("id", "")
        for e in examples[:30]
        if e.get("traceId") or e.get("id")
    ]
    error_count = 0
    unique_paths: set[str] = set()

    for tid in sample_ids:
        trace = _get_trace_full(tid)
        if not trace:
            continue
        spans = trace.get("spans", [])
        has_error = False
        path_sigs = []
        for span in spans:
            tags = {t["key"]: t["value"] for t in span.get("tags", [])}
            if (tags.get("error") in ("true", True)
                    or tags.get("otel.status_code") == "ERROR"
                    or str(tags.get("http.status_code", "200")).startswith(("4", "5"))):
                has_error = True
            path_sigs.append(f"{span.get('serviceName')}:{span.get('operationName')}")
        if has_error:
            error_count += 1
        if path_sigs:
            unique_paths.add("|".join(sorted(path_sigs)))

    sample_size = len(sample_ids)
    error_rate  = error_count / sample_size if sample_size else 1.0
    diversity   = len(unique_paths)

    # Score: low error rate is most important; high diversity is secondary
    # diversity is normalized assuming 50 unique paths = maximum diversity
    norm_diversity = min(diversity / 50.0, 1.0)
    score = (1.0 - error_rate) * 0.6 + norm_diversity * 0.4

    ts_start = datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc).strftime("%H:%M")
    ts_end   = datetime.fromtimestamp(end_ms / 1000, tz=timezone.utc).strftime("%H:%M")
    print(f"      {ts_start}-{ts_end} UTC: {trace_count} traces, "
          f"error_rate={error_rate:.1%}, diversity={diversity}, score={score:.3f}")

    return {
        "label":       label,
        "start_ms":    start_ms,
        "end_ms":      end_ms,
        "trace_count": trace_count,
        "error_rate":  error_rate,
        "diversity":   diversity,
        "score":       score,
        "scoreable":   True,
    }


def pick_best_window(incident_start_ms: int,
                     environment: str | None) -> dict | None:
    """
    Score all CANDIDATE_WINDOWS relative to the incident start time.
    Returns the highest-scoring scoreable window, or None if none qualify.
    """
    print(f"  [healer] Scoring {len(CANDIDATE_WINDOWS)} candidate windows...")
    scored = []
    for offset_min, duration_min in CANDIDATE_WINDOWS:
        end_ms   = incident_start_ms - offset_min * 60 * 1000
        start_ms = end_ms - duration_min * 60 * 1000
        label    = f"-{offset_min}m to -{offset_min + duration_min}m"
        result   = score_window(start_ms, end_ms, environment, label)
        if result["scoreable"]:
            scored.append(result)

    if not scored:
        print("  [healer] No scoreable windows found — cannot auto-heal.")
        return None

    best = max(scored, key=lambda w: w["score"])
    print(f"\n  [healer] Best window: {best['label']} "
          f"(score={best['score']:.3f}, error_rate={best['error_rate']:.1%}, "
          f"diversity={best['diversity']})")
    return best


# ── Healing ────────────────────────────────────────────────────────────────────

def _run_learn(script: str, environment: str, start_ms: int, end_ms: int,
               dry_run: bool) -> bool:
    """
    Run trace_fingerprint or error_fingerprint learn with --reset and
    a window offset computed from the chosen window's end time.
    """
    now_ms         = int(time.time() * 1000)
    # offset = how far back from now the window's end is
    window_offset  = (now_ms - end_ms) // 60000
    window_duration = (end_ms - start_ms) // 60000

    cmd = [
        sys.executable, script,
        "--environment", environment,
        "learn",
        "--window-minutes", str(window_duration),
        "--window-offset-minutes", str(window_offset),
        "--reset",
    ]

    print(f"    $ {' '.join(cmd)}")
    if dry_run:
        print(f"    [dry-run] skipped")
        return True

    result = subprocess.run(cmd, capture_output=True, text=True,
                            cwd=str(_SCRIPT_DIR))
    if result.returncode != 0:
        print(f"    [error] exit {result.returncode}")
        if result.stderr:
            print(result.stderr[-500:], file=sys.stderr)
        return False

    # Print last few lines of output for visibility
    lines = (result.stdout or "").strip().splitlines()
    for line in lines[-8:]:
        print(f"    {line}")
    return True


def heal(incident_start_ms: int, environment: str, best_window: dict,
         dry_run: bool) -> None:
    """Run both learn scripts against the chosen window with --reset."""
    print(f"\n  [healer] Healing baseline for '{environment}' using window "
          f"{best_window['label']}...")

    ok_trace = _run_learn(TRACE_FP, environment,
                          best_window["start_ms"], best_window["end_ms"], dry_run)
    ok_error = _run_learn(ERROR_FP, environment,
                          best_window["start_ms"], best_window["end_ms"], dry_run)

    if ok_trace and ok_error and not dry_run:
        _emit_healed_event(environment, best_window, incident_start_ms)
        print(f"  [healer] Baseline healed successfully.")
    elif dry_run:
        print(f"  [healer] Dry run complete — no changes written.")


def _emit_healed_event(environment: str, window: dict,
                       incident_start_ms: int) -> None:
    """Emit a baseline.healed event to Splunk for observability."""
    props = {
        "message":       (f"Baseline auto-healed for '{environment}' "
                          f"using window {window['label']} "
                          f"(score={window['score']:.3f})"),
        "window_label":  window["label"],
        "window_score":  str(round(window["score"], 4)),
        "error_rate":    str(round(window["error_rate"], 4)),
        "diversity":     str(window["diversity"]),
        "trace_count":   str(window["trace_count"]),
        "environment":   environment,
    }
    try:
        _request("POST", "/v2/event", [{
            "eventType":  "baseline.healed",
            "category":   "USER_DEFINED",
            "dimensions": {"environment": environment, "trigger": "auto"},
            "properties": props,
            "timestamp":  int(time.time() * 1000),
        }], base_url=INGEST_URL)
    except Exception as e:
        print(f"  [warn] Could not emit baseline.healed event: {e}", file=sys.stderr)


# ── Incident lifecycle detection ───────────────────────────────────────────────

class IncidentTracker:
    """
    Tracks the state machine: NORMAL → SPIKING → RESOLVING → HEALED
    """

    def __init__(self, spike_threshold: float, resolved_threshold: float,
                 min_spike_minutes: int, stabilization_minutes: int):
        self.spike_threshold       = spike_threshold
        self.resolved_threshold    = resolved_threshold
        self.min_spike_minutes     = min_spike_minutes
        self.stabilization_minutes = stabilization_minutes

        self.state              = "NORMAL"
        self.spike_start_ms: int | None   = None
        self.resolved_at_ms: int | None   = None
        self.incident_start_ms: int | None = None

    def update(self, rate: float, now_ms: int) -> str | None:
        """
        Feed the current anomaly rate. Returns an action string when
        the tracker decides it's time to heal, else None.

        Actions: None | "HEAL"
        """
        if self.state == "NORMAL":
            if rate >= self.spike_threshold:
                self.state          = "SPIKING"
                self.spike_start_ms = now_ms
                spike_age = 0
                print(f"  [healer] Spike detected: {rate:.2f} events/min — watching...")

        elif self.state == "SPIKING":
            spike_age_min = (now_ms - self.spike_start_ms) / 60000
            if rate < self.spike_threshold and spike_age_min < self.min_spike_minutes:
                # Too brief — noise, not a real incident
                print(f"  [healer] Spike was brief ({spike_age_min:.1f}m < "
                      f"{self.min_spike_minutes}m min) — treating as noise, resetting.")
                self.state          = "NORMAL"
                self.spike_start_ms = None
            elif rate < self.resolved_threshold:
                self.state             = "RESOLVING"
                self.resolved_at_ms    = now_ms
                self.incident_start_ms = self.spike_start_ms
                spike_dur = (now_ms - self.spike_start_ms) / 60000
                print(f"  [healer] Incident resolved after {spike_dur:.0f}m. "
                      f"Waiting {self.stabilization_minutes}m to stabilize...")

        elif self.state == "RESOLVING":
            stable_min = (now_ms - self.resolved_at_ms) / 60000
            if rate >= self.spike_threshold:
                # Incident re-spiked — reset to SPIKING
                print(f"  [healer] Re-spike detected ({rate:.2f}/min) — "
                      f"continuing to monitor.")
                self.state          = "SPIKING"
                self.resolved_at_ms = None
            elif stable_min >= self.stabilization_minutes:
                print(f"  [healer] System stable for {stable_min:.0f}m — "
                      f"ready to heal.")
                self.state = "HEALING"
                return "HEAL"

        return None

    def reset_after_heal(self) -> None:
        self.state             = "NORMAL"
        self.spike_start_ms    = None
        self.resolved_at_ms    = None
        self.incident_start_ms = None


# ── Main loop ─────────────────────────────────────────────────────────────────

def run_once(environment: str | None, dry_run: bool) -> None:
    """
    Evaluate the current anomaly rate once. If it's elevated then recently
    dropped, pick a clean window and heal. Useful for a post-incident hook.
    """
    now_ms      = int(time.time() * 1000)
    window_ms   = RATE_WINDOW_MINUTES * 60 * 1000

    # Look at current rate (last N minutes) vs. the window before that
    current_rate = measure_anomaly_rate(now_ms - window_ms, now_ms, environment)
    prior_rate   = measure_anomaly_rate(now_ms - 2 * window_ms,
                                         now_ms - window_ms, environment)

    print(f"[healer] Current anomaly rate: {current_rate:.2f}/min "
          f"(prior: {prior_rate:.2f}/min)")

    if prior_rate >= SPIKE_THRESHOLD and current_rate < RESOLVED_THRESHOLD:
        print(f"  Incident pattern detected (spike then drop). Evaluating windows...")
        incident_start_ms = now_ms - 2 * window_ms  # approximate
        best = pick_best_window(incident_start_ms, environment)
        if best:
            heal(incident_start_ms, environment or "all", best, dry_run)
    elif current_rate >= SPIKE_THRESHOLD:
        print(f"  Incident still active ({current_rate:.2f}/min >= "
              f"{SPIKE_THRESHOLD}/min threshold). Not healing yet.")
    else:
        print(f"  No incident pattern detected. Baseline appears healthy.")


def run_poll(environment: str | None, dry_run: bool,
             poll_interval: int) -> None:
    """Continuously monitor anomaly rate and heal when incidents resolve."""
    tracker = IncidentTracker(
        spike_threshold       = SPIKE_THRESHOLD,
        resolved_threshold    = RESOLVED_THRESHOLD,
        min_spike_minutes     = MIN_SPIKE_MINUTES,
        stabilization_minutes = STABILIZATION_MINUTES,
    )
    env_desc = environment or "all environments"
    print(f"[healer] Poll mode: checking every {poll_interval}s ({env_desc})")
    print(f"  Spike threshold:    {SPIKE_THRESHOLD}/min")
    print(f"  Resolved threshold: {RESOLVED_THRESHOLD}/min")
    print(f"  Min spike duration: {MIN_SPIKE_MINUTES}m")
    print(f"  Stabilization wait: {STABILIZATION_MINUTES}m")
    print("  Press Ctrl+C to stop.\n")

    while True:
        try:
            now_ms       = int(time.time() * 1000)
            window_ms    = RATE_WINDOW_MINUTES * 60 * 1000
            current_rate = measure_anomaly_rate(now_ms - window_ms, now_ms,
                                                environment)
            ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
            print(f"[{ts}] anomaly rate: {current_rate:.2f}/min  state: {tracker.state}")

            action = tracker.update(current_rate, now_ms)
            if action == "HEAL":
                best = pick_best_window(tracker.incident_start_ms, environment)
                if best:
                    heal(tracker.incident_start_ms, environment or "all",
                         best, dry_run)
                tracker.reset_after_heal()

            time.sleep(poll_interval)

        except KeyboardInterrupt:
            print("\n[healer] Stopped.")
            break


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Self-Healing Baseline Agent — autonomously re-baselines after incidents"
    )
    parser.add_argument("--environment", type=str, default=None,
                        help="APM environment to scope to (e.g. petclinicmbtest)")
    parser.add_argument("--mode", choices=["poll", "once"], default="poll",
                        help="poll: continuous monitor | once: evaluate now and exit")
    parser.add_argument("--poll-interval", type=int, default=POLL_INTERVAL,
                        help=f"Seconds between checks in poll mode (default: {POLL_INTERVAL})")
    parser.add_argument("--dry-run", action="store_true",
                        help="Score windows and print plan without running learn")
    args = parser.parse_args()

    if args.mode == "once":
        run_once(args.environment, args.dry_run)
    else:
        run_poll(args.environment, args.dry_run, args.poll_interval)


if __name__ == "__main__":
    main()
