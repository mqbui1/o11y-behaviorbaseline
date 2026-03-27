#!/usr/bin/env python3
"""
Behavioral Baseline — Adaptive Threshold Tuner
===============================================
Observes false positive / true positive rates per service over time and
tunes anomaly detection thresholds per-service automatically.

Today's problem:
  MISSING_SERVICE_DOMINANCE_THRESHOLD = 0.6  (global constant)
  SPAN_COUNT_SPIKE_MULTIPLIER = 2            (global constant)
  SPIKE_MULTIPLIER = 3                       (global constant)

  api-gateway has high churn (canary deploys, A/B routing) — a 0.6 dominance
  threshold fires too readily. mysql:petclinic never changes — 0.6 is too loose,
  every change is real.

How it works:
  1. OBSERVE — queries recent anomaly events (trace.path.drift,
               error.signature.drift) and correlates them against
               behavioral_baseline.correlated_anomaly events.
               - If an anomaly fired AND a correlated alert fired on the same
                 service within 10 minutes → TRUE POSITIVE
               - If an anomaly fired but NO correlation followed → FALSE POSITIVE
                   (isolated signal, not confirmed by cross-tier evidence)
               - Correlated alerts that fired → confirmed incident count

  2. SCORE   — for each service, computes:
               - fp_rate = false_positives / (false_positives + true_positives)
               - High fp_rate → loosen threshold (raise dominance, lower spike mult)
               - Low fp_rate  → tighten threshold (lower dominance, raise spike mult)

  3. TUNE    — writes per-service overrides to thresholds.json.
               The fingerprint scripts load this file at startup and apply
               per-service thresholds when available, falling back to global defaults.

  4. REPORT  — prints a per-service threshold change summary.

Usage:
  python adaptive_thresholds.py --environment petclinicmbtest
  python adaptive_thresholds.py --environment petclinicmbtest --dry-run
  python adaptive_thresholds.py --environment petclinicmbtest --show

  # Recommended: run daily after the learn cycle
  0 3 * * * python adaptive_thresholds.py --environment petclinicmbtest

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

_ENV_FILE = Path(__file__).parent.parent / ".env"
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

STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Where per-service threshold overrides are stored
THRESHOLDS_PATH = Path(os.environ.get("THRESHOLDS_PATH", str(Path(__file__).parent.parent / "data" / "thresholds.json")))

# Observation window — how far back to look for anomaly signals
OBSERVATION_DAYS = int(os.environ.get("THRESHOLD_OBSERVATION_DAYS", "7"))

# How many anomaly events per service minimum before we trust the stats
MIN_EVENTS_FOR_TUNING = int(os.environ.get("THRESHOLD_MIN_EVENTS", "5"))

# Window within which a correlated_anomaly confirms a trace/error anomaly as TP
CORRELATION_CONFIRM_WINDOW_MS = 10 * 60 * 1000  # 10 minutes

# ── Threshold bounds ───────────────────────────────────────────────────────────
# Dominance threshold: fraction of baseline patterns that must include a service
# for MISSING_SERVICE to fire. Higher = less sensitive (fewer FPs, more FNs).
DOMINANCE_MIN  = 0.40   # never go below — too noisy
DOMINANCE_MAX  = 0.90   # never go above — would miss real outages
DOMINANCE_DEFAULT = 0.60

# Span count spike multiplier: how many × the baseline max to fire SPAN_COUNT_SPIKE.
# Higher = less sensitive.
SPAN_SPIKE_MIN  = 1.5
SPAN_SPIKE_MAX  = 5.0
SPAN_SPIKE_DEFAULT = 2.0

# Error signature spike multiplier.
# Higher = less sensitive.
ERROR_SPIKE_MIN  = 2.0
ERROR_SPIKE_MAX  = 8.0
ERROR_SPIKE_DEFAULT = 3.0

# Tuning step sizes per adjustment cycle
DOMINANCE_STEP  = 0.05
SPAN_SPIKE_STEP = 0.25
ERROR_SPIKE_STEP = 0.5

# fp_rate above this → loosen (service is noisy)
HIGH_FP_RATE = 0.70
# fp_rate below this → tighten (service is stable)
LOW_FP_RATE  = 0.20


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       timeout: float = 15.0) -> list[dict]:
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


# ── Event collection ───────────────────────────────────────────────────────────

def _normalize_event(msg: dict, environment: str | None) -> dict | None:
    """Extract service, type, timestamp from a raw SignalFlow event message."""
    dims  = msg.get("metadata", {})
    props = msg.get("properties", {})

    event_env = dims.get("environment") or props.get("environment", "all")
    if environment and event_env not in (environment, "all"):
        return None

    # Infer service from dimensions
    service = (
        dims.get("service")
        or props.get("service")
        or _service_from_root_op(dims.get("root_operation", ""))
        or _service_from_services_list(props.get("services", ""))
    )
    if not service:
        return None

    return {
        "service":      service,
        "anomaly_type": dims.get("anomaly_type", ""),
        "timestamp_ms": msg.get("timestampMs", 0),
        "environment":  event_env,
    }


def _service_from_root_op(root_op: str) -> str | None:
    return root_op.split(":")[0] if ":" in root_op else None


def _service_from_services_list(services_str: str) -> str | None:
    parts = [s.strip() for s in services_str.split(",") if s.strip()]
    return parts[0] if parts else None


def collect_signals(start_ms: int, end_ms: int,
                    environment: str | None) -> dict:
    """
    Fetch anomaly events and correlated anomaly events.
    Returns {
      "anomalies": [{service, anomaly_type, timestamp_ms, environment}],
      "correlations": [{service, timestamp_ms, severity}]
    }
    """
    print(f"  Fetching trace.path.drift events...")
    trace_raw  = _signalflow_events("trace.path.drift", start_ms, end_ms)
    print(f"  Fetching error.signature.drift events...")
    error_raw  = _signalflow_events("error.signature.drift", start_ms, end_ms)
    print(f"  Fetching behavioral_baseline.correlated_anomaly events...")
    corr_raw   = _signalflow_events("behavioral_baseline.correlated_anomaly",
                                    start_ms, end_ms)

    anomalies = []
    for msg in trace_raw + error_raw:
        ev = _normalize_event(msg, environment)
        if ev:
            anomalies.append(ev)

    correlations = []
    for msg in corr_raw:
        dims  = msg.get("metadata", {})
        props = msg.get("properties", {})
        event_env = dims.get("environment") or props.get("environment", "all")
        if environment and event_env not in (environment, "all"):
            continue
        svc = dims.get("service") or props.get("service")
        if svc:
            correlations.append({
                "service":      svc,
                "timestamp_ms": msg.get("timestampMs", 0),
                "severity":     dims.get("severity", ""),
            })

    print(f"  Found {len(anomalies)} anomaly events, "
          f"{len(correlations)} correlation events")
    return {"anomalies": anomalies, "correlations": correlations}


# ── TP/FP classification ───────────────────────────────────────────────────────

def classify_signals(signals: dict) -> dict[str, dict]:
    """
    For each service, classify each anomaly event as TP or FP.

    TRUE POSITIVE: anomaly on service X at time T, AND a correlated_anomaly
    event on service X exists within CORRELATION_CONFIRM_WINDOW_MS of T.

    FALSE POSITIVE: anomaly fired, but no correlated_anomaly confirmed it.

    Returns: {service: {tp, fp, total, fp_rate, anomaly_types}}
    """
    # Index correlations by service → sorted list of timestamps
    corr_index: dict[str, list[int]] = defaultdict(list)
    for c in signals["correlations"]:
        corr_index[c["service"]].append(c["timestamp_ms"])

    stats: dict[str, dict] = defaultdict(lambda: {
        "tp": 0, "fp": 0, "total": 0, "anomaly_types": defaultdict(int)
    })

    for ev in signals["anomalies"]:
        svc = ev["service"]
        ts  = ev["timestamp_ms"]
        stats[svc]["total"] += 1
        if ev["anomaly_type"]:
            stats[svc]["anomaly_types"][ev["anomaly_type"]] += 1

        # Check if any correlation confirms this anomaly
        confirmed = any(
            abs(corr_ts - ts) <= CORRELATION_CONFIRM_WINDOW_MS
            for corr_ts in corr_index.get(svc, [])
        )
        if confirmed:
            stats[svc]["tp"] += 1
        else:
            stats[svc]["fp"] += 1

    # Compute fp_rate and freeze anomaly_types to regular dict
    result = {}
    for svc, s in stats.items():
        total = s["total"]
        fp_rate = s["fp"] / total if total > 0 else 0.0
        result[svc] = {
            "tp":           s["tp"],
            "fp":           s["fp"],
            "total":        total,
            "fp_rate":      fp_rate,
            "anomaly_types": dict(s["anomaly_types"]),
        }
    return result


# ── Threshold computation ──────────────────────────────────────────────────────

def _clamp(value: float, lo: float, hi: float) -> float:
    return max(lo, min(hi, value))


def compute_new_thresholds(service: str, stats: dict,
                            current: dict) -> tuple[dict, list[str]]:
    """
    Given TP/FP stats and current thresholds for a service, return
    (new_thresholds, list_of_change_descriptions).
    """
    fp_rate = stats["fp_rate"]
    changes = []
    new = dict(current)  # copy

    # ── MISSING_SERVICE dominance threshold ───────────────────────────────────
    cur_dom = current.get("missing_service_dominance_threshold", DOMINANCE_DEFAULT)
    if fp_rate >= HIGH_FP_RATE:
        # Too many FPs — raise threshold (require more of the baseline to agree)
        new_dom = _clamp(cur_dom + DOMINANCE_STEP, DOMINANCE_MIN, DOMINANCE_MAX)
        if new_dom != cur_dom:
            changes.append(
                f"missing_service_dominance_threshold: {cur_dom:.2f} → {new_dom:.2f} "
                f"(fp_rate={fp_rate:.0%} ≥ {HIGH_FP_RATE:.0%}: loosen)"
            )
            new["missing_service_dominance_threshold"] = round(new_dom, 3)
    elif fp_rate <= LOW_FP_RATE and stats["total"] >= MIN_EVENTS_FOR_TUNING:
        # Very few FPs — tighten (catch changes earlier)
        new_dom = _clamp(cur_dom - DOMINANCE_STEP, DOMINANCE_MIN, DOMINANCE_MAX)
        if new_dom != cur_dom:
            changes.append(
                f"missing_service_dominance_threshold: {cur_dom:.2f} → {new_dom:.2f} "
                f"(fp_rate={fp_rate:.0%} ≤ {LOW_FP_RATE:.0%}: tighten)"
            )
            new["missing_service_dominance_threshold"] = round(new_dom, 3)

    # ── SPAN_COUNT_SPIKE multiplier ────────────────────────────────────────────
    has_span_spikes = stats["anomaly_types"].get("SPAN_COUNT_SPIKE", 0) > 0
    if has_span_spikes:
        cur_span = current.get("span_count_spike_multiplier", SPAN_SPIKE_DEFAULT)
        if fp_rate >= HIGH_FP_RATE:
            new_span = _clamp(cur_span + SPAN_SPIKE_STEP, SPAN_SPIKE_MIN, SPAN_SPIKE_MAX)
            if new_span != cur_span:
                changes.append(
                    f"span_count_spike_multiplier: {cur_span:.2f} → {new_span:.2f} "
                    f"(loosen — high FP rate on SPAN_COUNT_SPIKE)"
                )
                new["span_count_spike_multiplier"] = round(new_span, 2)
        elif fp_rate <= LOW_FP_RATE:
            new_span = _clamp(cur_span - SPAN_SPIKE_STEP, SPAN_SPIKE_MIN, SPAN_SPIKE_MAX)
            if new_span != cur_span:
                changes.append(
                    f"span_count_spike_multiplier: {cur_span:.2f} → {new_span:.2f} "
                    f"(tighten — low FP rate on SPAN_COUNT_SPIKE)"
                )
                new["span_count_spike_multiplier"] = round(new_span, 2)

    # ── ERROR_SPIKE multiplier ─────────────────────────────────────────────────
    has_error_spikes = stats["anomaly_types"].get("SIGNATURE_SPIKE", 0) > 0
    if has_error_spikes:
        cur_err = current.get("error_spike_multiplier", ERROR_SPIKE_DEFAULT)
        if fp_rate >= HIGH_FP_RATE:
            new_err = _clamp(cur_err + ERROR_SPIKE_STEP, ERROR_SPIKE_MIN, ERROR_SPIKE_MAX)
            if new_err != cur_err:
                changes.append(
                    f"error_spike_multiplier: {cur_err:.2f} → {new_err:.2f} "
                    f"(loosen — high FP rate on SIGNATURE_SPIKE)"
                )
                new["error_spike_multiplier"] = round(new_err, 2)
        elif fp_rate <= LOW_FP_RATE:
            new_err = _clamp(cur_err - ERROR_SPIKE_STEP, ERROR_SPIKE_MIN, ERROR_SPIKE_MAX)
            if new_err != cur_err:
                changes.append(
                    f"error_spike_multiplier: {cur_err:.2f} → {new_err:.2f} "
                    f"(tighten — low FP rate on SIGNATURE_SPIKE)"
                )
                new["error_spike_multiplier"] = round(new_err, 2)

    return new, changes


# ── Threshold persistence ──────────────────────────────────────────────────────

def load_thresholds() -> dict:
    """Load thresholds.json. Returns empty dict if not found."""
    if THRESHOLDS_PATH.exists():
        try:
            return json.loads(THRESHOLDS_PATH.read_text())
        except Exception:
            pass
    return {}


def save_thresholds(thresholds: dict) -> None:
    thresholds["_updated_at"] = datetime.now(timezone.utc).isoformat()
    THRESHOLDS_PATH.write_text(json.dumps(thresholds, indent=2))


def get_service_thresholds(thresholds: dict, service: str) -> dict:
    """Return current per-service thresholds, falling back to global defaults."""
    return thresholds.get("services", {}).get(service, {})


# ── Main tuning run ────────────────────────────────────────────────────────────

def run(environment: str | None, dry_run: bool,
        observation_days: int = OBSERVATION_DAYS) -> None:
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - observation_days * 24 * 60 * 60 * 1000
    env_desc = environment or "all environments"

    print(f"[adaptive-thresholds] Observing {observation_days}d window "
          f"({env_desc})...")

    signals = collect_signals(start_ms, now_ms, environment)

    if not signals["anomalies"]:
        print("  No anomaly events found — nothing to tune.")
        return

    service_stats = classify_signals(signals)

    # Filter to services with enough data
    tunable = {
        svc: s for svc, s in service_stats.items()
        if s["total"] >= MIN_EVENTS_FOR_TUNING
    }
    skipped = len(service_stats) - len(tunable)

    print(f"\n  Per-service signal summary:")
    print(f"  {'Service':<30} {'Total':>6} {'TP':>5} {'FP':>5} {'FP%':>6}  Anomaly types")
    print(f"  {'-'*30} {'-'*6} {'-'*5} {'-'*5} {'-'*6}  {'-'*30}")
    for svc, s in sorted(service_stats.items(), key=lambda x: -x[1]["total"]):
        types_str = ", ".join(f"{k}:{v}" for k, v in s["anomaly_types"].items())
        flag = "" if s["total"] >= MIN_EVENTS_FOR_TUNING else "  (skip: too few)"
        print(f"  {svc:<30} {s['total']:>6} {s['tp']:>5} {s['fp']:>5} "
              f"{s['fp_rate']:>5.0%}  {types_str}{flag}")

    if not tunable:
        print(f"\n  No services have ≥{MIN_EVENTS_FOR_TUNING} events — "
              f"not enough data to tune yet.")
        return

    # Load existing thresholds
    thresholds = load_thresholds()
    services_block = thresholds.setdefault("services", {})

    print(f"\n  Threshold adjustments:")
    any_changes = False

    for svc, stats in sorted(tunable.items()):
        current  = get_service_thresholds(thresholds, svc)
        new, changes = compute_new_thresholds(svc, stats, current)
        if changes:
            any_changes = True
            print(f"\n  {svc}  (fp_rate={stats['fp_rate']:.0%}, "
                  f"tp={stats['tp']}, fp={stats['fp']}):")
            for c in changes:
                print(f"    {c}")
            if not dry_run:
                services_block[svc] = new
        else:
            print(f"  {svc}: no changes (fp_rate={stats['fp_rate']:.0%} "
                  f"within normal range)")

    if not any_changes:
        print("  All services within normal FP range — no threshold changes needed.")
        return

    if dry_run:
        print(f"\n  [dry-run] Would write {THRESHOLDS_PATH}")
        return

    thresholds["services"] = services_block
    thresholds.setdefault("_meta", {
        "description": (
            "Per-service threshold overrides for behavioral baseline detection. "
            "Generated by adaptive_thresholds.py. "
            "Loaded by trace_fingerprint.py and error_fingerprint.py at startup."
        ),
        "global_defaults": {
            "missing_service_dominance_threshold": DOMINANCE_DEFAULT,
            "span_count_spike_multiplier":         SPAN_SPIKE_DEFAULT,
            "error_spike_multiplier":              ERROR_SPIKE_DEFAULT,
        },
    })

    save_thresholds(thresholds)
    print(f"\n  Written to {THRESHOLDS_PATH}")
    print(f"  Add THRESHOLDS_PATH={THRESHOLDS_PATH} to your .env or environment "
          f"to have fingerprint scripts pick up per-service overrides.")


def cmd_show() -> None:
    """Print current per-service thresholds from thresholds.json."""
    thresholds = load_thresholds()
    if not thresholds:
        print(f"No thresholds file found at {THRESHOLDS_PATH}.")
        return

    updated = thresholds.get("_updated_at", "unknown")
    print(f"Per-service thresholds (last updated: {updated})\n")
    services = thresholds.get("services", {})
    if not services:
        print("  No per-service overrides — all services using global defaults.")
        return

    defaults = thresholds.get("_meta", {}).get("global_defaults", {})
    print(f"  {'Service':<30} {'missing_dom':>12} {'span_spike':>11} "
          f"{'err_spike':>10}")
    print(f"  {'-'*30} {'-'*12} {'-'*11} {'-'*10}")
    for svc, t in sorted(services.items()):
        dom  = t.get("missing_service_dominance_threshold",
                     defaults.get("missing_service_dominance_threshold", DOMINANCE_DEFAULT))
        span = t.get("span_count_spike_multiplier",
                     defaults.get("span_count_spike_multiplier", SPAN_SPIKE_DEFAULT))
        err  = t.get("error_spike_multiplier",
                     defaults.get("error_spike_multiplier", ERROR_SPIKE_DEFAULT))
        print(f"  {svc:<30} {dom:>12.3f} {span:>11.2f} {err:>10.2f}")
    print(f"\n  Global defaults: missing_dom={DOMINANCE_DEFAULT}, "
          f"span_spike={SPAN_SPIKE_DEFAULT}, err_spike={ERROR_SPIKE_DEFAULT}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Adaptive Threshold Tuner — per-service anomaly sensitivity tuning"
    )
    parser.add_argument("--environment", type=str, default=None,
                        help="APM environment to scope to")
    parser.add_argument("--dry-run", action="store_true",
                        help="Compute changes without writing thresholds.json")
    parser.add_argument("--show", action="store_true",
                        help="Print current per-service thresholds and exit")
    parser.add_argument("--observation-days", type=int, default=OBSERVATION_DAYS,
                        help=f"Days of history to analyze (default: {OBSERVATION_DAYS})")
    args = parser.parse_args()

    if args.show:
        cmd_show()
        return

    obs_days = args.observation_days
    run(args.environment, args.dry_run, obs_days)


if __name__ == "__main__":
    main()
