#!/usr/bin/env python3
"""
Behavioral Baseline — SLO Impact Estimator (#12)
================================================
When a TIER2_TIER3 correlated anomaly fires, the triage agent tells you
what broke — but not how long you have before the SLO burns out.

This agent:
  1. Queries current error rate and latency percentiles from Splunk metrics
     using SignalFlow
  2. Loads or infers SLO targets for the service (from thresholds.json or
     standard defaults: 99.9% availability, p99 < 2s)
  3. Computes the current error budget consumed and burn rate
  4. Estimates time-to-breach at the current burn rate

Output injected into triage_agent.py summary:
  "At current error rate (2.3%), p99 SLO will breach in ~23 minutes.
   Monthly error budget: 43.2min. Already consumed: 12.1min (28%)."

Usage:
  python slo_impact_estimator.py --service vets-service --environment petclinicmbtest
  python slo_impact_estimator.py --service api-gateway --environment petclinicmbtest --window-minutes 10

  # From triage_agent.py (called automatically):
  from slo_impact_estimator import estimate_impact
  summary = estimate_impact("vets-service", "petclinicmbtest")

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM              (default: us0)
"""

import argparse
import json
import os
import sys
import time
import urllib.request
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
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

STREAM_URL = f"https://stream.{REALM}.signalfx.com"

# Default SLO targets (can be overridden in thresholds.json per service)
DEFAULT_AVAILABILITY_SLO = 0.999   # 99.9%
DEFAULT_P99_LATENCY_MS   = 2000    # 2 seconds
MONTHLY_MINUTES          = 30 * 24 * 60  # 43,200 minutes

# Lookback for current error/latency rate
DEFAULT_WINDOW_MINUTES = 10

# ── Thresholds loading ────────────────────────────────────────────────────────

def _load_slo_targets(service: str) -> dict:
    """Load SLO targets from thresholds.json, fall back to defaults."""
    p = Path(__file__).parent / "thresholds.json"
    if p.exists():
        try:
            svc = json.loads(p.read_text()).get("services", {}).get(service, {})
            return {
                "availability_slo": float(svc.get("availability_slo", DEFAULT_AVAILABILITY_SLO)),
                "p99_latency_ms":   float(svc.get("p99_latency_ms", DEFAULT_P99_LATENCY_MS)),
            }
        except Exception:
            pass
    return {
        "availability_slo": DEFAULT_AVAILABILITY_SLO,
        "p99_latency_ms":   DEFAULT_P99_LATENCY_MS,
    }


# ── SignalFlow metric queries ─────────────────────────────────────────────────

def _run_signalflow(program: str, start_ms: int, end_ms: int,
                    timeout: float = 12.0) -> list[dict]:
    """Execute a SignalFlow program and return all data messages."""
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true&resolution=60000")
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
                    results.append(msg)
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception as e:
        print(f"  [warn] SignalFlow: {e}", file=sys.stderr)
    return results


def _extract_last_value(messages: list[dict]) -> float | None:
    """Extract the most recent data value from SignalFlow messages."""
    last_val = None
    for msg in messages:
        if msg.get("type") == "data":
            for ts_data in msg.get("data", {}).values():
                if isinstance(ts_data, (int, float)):
                    last_val = float(ts_data)
    return last_val


def _extract_mean_value(messages: list[dict]) -> float | None:
    """Extract mean of all data values."""
    values = []
    for msg in messages:
        if msg.get("type") == "data":
            for ts_data in msg.get("data", {}).values():
                if isinstance(ts_data, (int, float)):
                    values.append(float(ts_data))
    return sum(values) / len(values) if values else None


# ── Metric queries ────────────────────────────────────────────────────────────

def query_error_rate(service: str, environment: str | None,
                     start_ms: int, end_ms: int) -> float | None:
    """
    Query error rate for service using APM spans.count metric.
    Returns error rate as fraction (0.0 - 1.0) or None if no data.
    """
    env_filter = f"filter('sf_environment', '{environment}') and " if environment else ""
    svc_filter = f"filter('sf_service', '{service}')"

    # Try APM error rate metric
    for metric in [
        "spans.count",
        "service.request.count",
        "traces.count",
    ]:
        program = (
            f"A = data('{metric}', filter={env_filter}{svc_filter} "
            f"and filter('sf_error', 'true')).sum().publish(label='errors')\n"
            f"B = data('{metric}', filter={env_filter}{svc_filter}).sum().publish(label='total')\n"
            f"(A / B).publish(label='error_rate')"
        )
        msgs = _run_signalflow(program, start_ms, end_ms)
        # Look for the 'error_rate' stream
        rate = None
        for msg in msgs:
            if msg.get("type") == "data":
                for v in msg.get("data", {}).values():
                    if isinstance(v, (int, float)) and 0 <= v <= 1:
                        rate = float(v)
        if rate is not None:
            return rate

    return None


def query_p99_latency(service: str, environment: str | None,
                      start_ms: int, end_ms: int) -> float | None:
    """Query p99 latency in milliseconds."""
    env_filter = f"filter('sf_environment', '{environment}') and " if environment else ""
    svc_filter = f"filter('sf_service', '{service}')"

    for metric in [
        "spans.duration.ns.p99",
        "service.request.duration.ns.p99",
        "traces.duration.ns.percentile",
    ]:
        program = (
            f"data('{metric}', filter={env_filter}{svc_filter}).mean().publish()"
        )
        msgs = _run_signalflow(program, start_ms, end_ms)
        val  = _extract_mean_value(msgs)
        if val is not None and val > 0:
            # Convert ns to ms
            return val / 1e6 if val > 10000 else val  # already ms if < 10s

    return None


def query_request_rate(service: str, environment: str | None,
                       start_ms: int, end_ms: int) -> float | None:
    """Query requests/minute."""
    env_filter = f"filter('sf_environment', '{environment}') and " if environment else ""
    svc_filter = f"filter('sf_service', '{service}')"

    program = (
        f"data('spans.count', filter={env_filter}{svc_filter}).sum()"
        f".publish()"
    )
    msgs = _run_signalflow(program, start_ms, end_ms)
    val  = _extract_mean_value(msgs)
    return val  # already per-minute from resolution=60000


# ── Budget computation ────────────────────────────────────────────────────────

def compute_budget(error_rate: float, slo: float) -> dict:
    """
    Compute error budget consumption and burn rate.
    Returns dict with human-readable fields.
    """
    allowed_error_rate = 1.0 - slo
    # Monthly error budget in minutes
    monthly_budget_min = MONTHLY_MINUTES * allowed_error_rate

    if error_rate <= 0:
        return {
            "error_rate_pct":     0.0,
            "allowed_rate_pct":   round(allowed_error_rate * 100, 3),
            "burn_rate":          0.0,
            "monthly_budget_min": round(monthly_budget_min, 1),
            "time_to_breach_min": None,
            "status":             "OK",
            "summary":            f"Error rate 0% — SLO healthy.",
        }

    burn_rate = error_rate / allowed_error_rate

    # Time until monthly budget exhausted at current burn rate
    # Each minute at current error rate consumes (burn_rate / MONTHLY_MINUTES) of budget
    # Time to exhaust entire remaining budget = monthly_budget_min / burn_rate
    time_to_exhaust_min = monthly_budget_min / burn_rate

    if burn_rate >= 14.4:
        status = "CRITICAL"   # Burning 1hr budget in 5min
    elif burn_rate >= 6:
        status = "HIGH"
    elif burn_rate >= 2:
        status = "MEDIUM"
    else:
        status = "LOW"

    # Friendly time string
    if time_to_exhaust_min < 60:
        ttb_str = f"~{round(time_to_exhaust_min)} minutes"
    elif time_to_exhaust_min < 1440:
        ttb_str = f"~{round(time_to_exhaust_min / 60, 1)} hours"
    else:
        ttb_str = f"~{round(time_to_exhaust_min / 1440, 1)} days"

    return {
        "error_rate_pct":     round(error_rate * 100, 2),
        "allowed_rate_pct":   round(allowed_error_rate * 100, 3),
        "burn_rate":          round(burn_rate, 1),
        "monthly_budget_min": round(monthly_budget_min, 1),
        "time_to_breach_min": round(time_to_exhaust_min, 1),
        "time_to_breach_str": ttb_str,
        "status":             status,
        "summary": (
            f"At current error rate ({error_rate*100:.2f}%), "
            f"monthly error budget ({monthly_budget_min:.0f}min) "
            f"will exhaust in {ttb_str}. Burn rate: {burn_rate:.1f}x."
        ),
    }


# ── Main estimate ─────────────────────────────────────────────────────────────

def estimate_impact(service: str, environment: str | None,
                    window_minutes: int = DEFAULT_WINDOW_MINUTES) -> dict:
    """
    Callable from triage_agent.py. Returns impact dict with human-readable summary.
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000

    targets = _load_slo_targets(service)
    avail_slo = targets["availability_slo"]
    p99_target = targets["p99_latency_ms"]

    print(f"  [slo] Querying metrics for '{service}' "
          f"(SLO: {avail_slo*100:.1f}%, p99<{p99_target}ms)...", file=sys.stderr)

    error_rate = query_error_rate(service, environment, start_ms, now_ms)
    p99_ms     = query_p99_latency(service, environment, start_ms, now_ms)
    req_rate   = query_request_rate(service, environment, start_ms, now_ms)

    budget = compute_budget(error_rate or 0.0, avail_slo) if error_rate is not None else None

    # Latency SLO check
    latency_status: str | None = None
    latency_summary: str | None = None
    if p99_ms is not None:
        if p99_ms > p99_target * 2:
            latency_status = "CRITICAL"
            latency_summary = (f"p99 latency {p99_ms:.0f}ms is "
                               f"{p99_ms/p99_target:.1f}x above SLO target ({p99_target}ms).")
        elif p99_ms > p99_target:
            latency_status = "HIGH"
            latency_summary = (f"p99 latency {p99_ms:.0f}ms exceeds SLO target ({p99_target}ms).")
        else:
            latency_status = "OK"
            latency_summary = f"p99 latency {p99_ms:.0f}ms is within SLO target ({p99_target}ms)."

    result = {
        "service":          service,
        "environment":      environment,
        "window_minutes":   window_minutes,
        "error_rate_pct":   round((error_rate or 0) * 100, 2),
        "p99_latency_ms":   round(p99_ms, 1) if p99_ms is not None else None,
        "req_rate_per_min": round(req_rate, 1) if req_rate is not None else None,
        "availability_slo": avail_slo,
        "p99_target_ms":    p99_target,
        "budget":           budget,
        "latency_status":   latency_status,
        "latency_summary":  latency_summary,
        "no_data":          error_rate is None and p99_ms is None,
    }

    # Compose a single-line summary for injection into triage
    if result["no_data"]:
        result["one_liner"] = (
            f"SLO metrics unavailable for '{service}' — "
            "no spans.count/duration data in Splunk APM."
        )
    else:
        parts = []
        if budget:
            parts.append(budget["summary"])
        if latency_summary and latency_status != "OK":
            parts.append(latency_summary)
        result["one_liner"] = " ".join(parts) if parts else "SLO: all metrics nominal."

    return result


# ── CLI ────────────────────────────────────────────────────────────────────────

def print_impact(result: dict) -> None:
    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
                "LOW": "🟢", "OK": "✅"}.get
    b = result.get("budget") or {}

    print(f"\n{'='*65}")
    print(f"SLO IMPACT ESTIMATE: {result['service']}")
    print(f"  Environment: {result['environment'] or 'all'}")
    print(f"  Window:      {result['window_minutes']}m")
    print(f"{'='*65}")

    if result.get("no_data"):
        print("\n  ⬜ No metric data — APM spans metrics not available for this service.")
        print(f"     One-liner: {result['one_liner']}")
        return

    if result.get("error_rate_pct") is not None:
        status = b.get("status", "OK")
        icon   = sev_icon(status, "•")
        print(f"\n  Availability ({result['availability_slo']*100:.1f}% SLO):")
        print(f"    {icon} Current error rate:  {result['error_rate_pct']:.2f}%  "
              f"(allowed: {b.get('allowed_rate_pct', 0):.3f}%)")
        if b.get("burn_rate"):
            print(f"    Burn rate:           {b['burn_rate']:.1f}x")
        if b.get("time_to_breach_str"):
            print(f"    Time to budget exhaustion: {b['time_to_breach_str']}")
        print(f"    Monthly budget:      {b.get('monthly_budget_min', 0):.0f}min")

    if result.get("p99_latency_ms") is not None:
        lat_icon = sev_icon(result.get("latency_status", "OK"), "•")
        print(f"\n  Latency (p99 < {result['p99_target_ms']}ms SLO):")
        print(f"    {lat_icon} Current p99: {result['p99_latency_ms']:.0f}ms")

    if result.get("req_rate_per_min") is not None:
        print(f"\n  Request rate: {result['req_rate_per_min']:.0f} req/min")

    print(f"\n  Triage summary:")
    print(f"  \"{result['one_liner']}\"")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SLO Impact Estimator — estimates time-to-breach from current error rate"
    )
    parser.add_argument("--service",        required=True)
    parser.add_argument("--environment",    default=None)
    parser.add_argument("--window-minutes", type=int, default=DEFAULT_WINDOW_MINUTES)
    parser.add_argument("--json",           action="store_true")
    args = parser.parse_args()

    result = estimate_impact(args.service, args.environment, args.window_minutes)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print_impact(result)


if __name__ == "__main__":
    main()
