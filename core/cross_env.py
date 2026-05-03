#!/usr/bin/env python3
"""
cross_env.py — Cross-environment anomaly correlation.

Connects anomalies observed in a staging/canary environment to predictions
about production risk, and surfaces production anomalies that preceded
the staging signal (leading indicator pattern).

Usage (standalone):
  python3 core/cross_env.py --staging petclinictest-2d77-workshop \
                             --production petclinic-prod \
                             --window-minutes 60

  Returns JSON with:
    staging_anomalies   — anomalies in staging during the window
    prod_anomalies      — anomalies in production during the same window
    leading_signals     — prod anomalies that preceded matching staging anomalies
                          (prod→staging propagation pattern)
    risk_predictions    — staging anomalies NOT yet in prod (early warning)
    correlation_score   — 0.0-1.0: how similar the two environments look right now

Integrated use (called from agent.py when CROSS_ENV_ENVS is set):
  from core.cross_env import cross_env_context
  ctx = cross_env_context(staging_env, prod_env, window_minutes=30)
  # Returns a summary string for inclusion in the Claude prompt
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

_REPO     = Path(__file__).parent.parent
_DATA_DIR = _REPO / "data"

# ── Load .env ──────────────────────────────────────────────────────────────────
_env_file = _REPO / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
REALM        = os.environ.get("SPLUNK_REALM", "us1")
_API_BASE    = f"https://api.{REALM}.signalfx.com"

# How long to match anomalies across environments (staging fires, prod follows within N min)
PROPAGATION_WINDOW_MINUTES = 30
# Minimum service name similarity to consider two anomalies "matching"
# (handles svc-v2 vs svc naming differences between envs)
_SERVICE_CORE_STRIP = str.maketrans("", "", "-_0123456789")


def _service_core(name: str) -> str:
    """Normalise service name for fuzzy cross-env matching: strip version suffixes."""
    return name.lower().translate(_SERVICE_CORE_STRIP)


def _fetch_events(environment: str, window_minutes: int) -> list[dict]:
    """
    Fetch recent behavioral baseline events for a given environment from
    Splunk Observability Cloud.  Returns a flat list of event dicts with at
    minimum: anomaly_type, service, timestamp_ms.

    Falls back to the local baseline watch-output file if the API is unavailable
    (useful in offline / demo mode).
    """
    if not ACCESS_TOKEN:
        return _load_local_events(environment)

    try:
        import urllib.request
        import urllib.error

        now_ms   = int(time.time() * 1000)
        start_ms = now_ms - window_minutes * 60 * 1000

        # Query the /v2/event endpoint for behavioral events in this environment
        event_types = [
            "trace.path.drift",
            "error.signature.drift",
            "service.latency.anomaly",
            "service.error.rate.anomaly",
            "service.throughput.drop",
        ]
        events: list[dict] = []
        for etype in event_types:
            url = (
                f"{_API_BASE}/v2/event?"
                f"type={etype}"
                f"&dimensions%5Benvironment%5D={environment}"
                f"&startTime={start_ms}&endTime={now_ms}"
                f"&limit=100"
            )
            req = urllib.request.Request(
                url, headers={"X-SF-TOKEN": ACCESS_TOKEN, "Content-Type": "application/json"}
            )
            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read())
                    for ev in data.get("results", []):
                        dims = ev.get("dimensions", {})
                        events.append({
                            "anomaly_type":  dims.get("anomaly_type", etype),
                            "service":       dims.get("service", ""),
                            "root_op":       dims.get("root_op", ""),
                            "environment":   environment,
                            "timestamp_ms":  ev.get("timestamp", now_ms),
                            "source":        "splunk-events",
                        })
            except Exception:
                pass  # individual type failure is non-fatal

        return events
    except ImportError:
        return _load_local_events(environment)


def _load_local_events(environment: str) -> list[dict]:
    """
    Load events from the local dedup state file as a fallback.
    These are the hashes we've seen recently — useful for offline demo mode.
    """
    dedup_path = _DATA_DIR / f"otel_dedup_state.{environment}.json"
    if not dedup_path.exists():
        return []
    try:
        raw = json.loads(dedup_path.read_text())
        now_ms = int(time.time() * 1000)
        events = []
        for key, ts_ms in raw.items():
            parts = key.split(":")
            atype = parts[0] if parts else "UNKNOWN"
            svc   = parts[1] if len(parts) > 1 else ""
            events.append({
                "anomaly_type": atype,
                "service":      svc,
                "root_op":      ":".join(parts[2:]) if len(parts) > 2 else "",
                "environment":  environment,
                "timestamp_ms": ts_ms,
                "source":       "local-dedup",
            })
        return events
    except Exception:
        return []


def _match_score(a: dict, b: dict) -> float:
    """
    Return 0.0-1.0 similarity score between two anomaly dicts from different envs.
    Considers: anomaly_type match (required), service core match, root_op similarity.
    """
    if a.get("anomaly_type") != b.get("anomaly_type"):
        return 0.0
    svc_a = _service_core(a.get("service", ""))
    svc_b = _service_core(b.get("service", ""))
    if not svc_a or not svc_b:
        return 0.0

    # Exact service core match
    if svc_a == svc_b:
        svc_score = 1.0
    # One contains the other (e.g. "customerssvc" vs "customerservice")
    elif svc_a in svc_b or svc_b in svc_a:
        svc_score = 0.7
    else:
        return 0.0

    # Root op similarity bonus (strip HTTP method prefix for comparison)
    op_a = a.get("root_op", "").split(":", 1)[-1].strip()
    op_b = b.get("root_op", "").split(":", 1)[-1].strip()
    if op_a and op_b and op_a == op_b:
        op_score = 1.0
    elif op_a and op_b and (op_a in op_b or op_b in op_a):
        op_score = 0.5
    else:
        op_score = 0.0

    return svc_score * 0.7 + op_score * 0.3


def correlate(staging_events: list[dict], prod_events: list[dict],
              propagation_window_minutes: int = PROPAGATION_WINDOW_MINUTES
              ) -> dict:
    """
    Core correlation engine.  Returns:
      leading_signals   — prod anomalies that fired BEFORE a matching staging anomaly
                          (prod→staging propagation: staging is echoing a prod problem)
      risk_predictions  — staging anomalies with NO matching prod anomaly yet
                          (staging canary: early warning before prod impact)
      matched_pairs     — all (staging, prod) pairs above threshold with scores
      correlation_score — overall env similarity [0.0–1.0]
    """
    prop_ms = propagation_window_minutes * 60 * 1000
    leading_signals:  list[dict] = []
    risk_predictions: list[dict] = []
    matched_pairs:    list[dict] = []

    for s_ev in staging_events:
        best_score = 0.0
        best_prod  = None
        for p_ev in prod_events:
            score = _match_score(s_ev, p_ev)
            if score > best_score:
                best_score = score
                best_prod  = p_ev

        if best_score >= 0.7 and best_prod is not None:
            time_delta_ms = s_ev["timestamp_ms"] - best_prod["timestamp_ms"]
            matched_pairs.append({
                "staging":        s_ev,
                "prod":           best_prod,
                "match_score":    round(best_score, 2),
                "staging_led_by_ms": time_delta_ms,
            })
            if time_delta_ms > 0:
                # Prod fired first — staging is echoing a production problem
                leading_signals.append({
                    **best_prod,
                    "staging_echo":        s_ev,
                    "prod_led_by_minutes": round(time_delta_ms / 60_000, 1),
                    "note": (
                        f"Production {best_prod.get('service')} anomaly appeared "
                        f"{round(time_delta_ms/60_000, 1)}m before staging — "
                        "likely propagating from prod."
                    ),
                })
        elif best_score < 0.7:
            # No matching prod signal — staging is ahead of prod (canary warning)
            risk_predictions.append({
                **s_ev,
                "note": (
                    f"Staging {s_ev.get('service')} shows {s_ev.get('anomaly_type')} "
                    "with no matching production signal yet — potential early warning."
                ),
            })

    # Correlation score: fraction of staging anomalies matched in prod
    total = len(staging_events)
    if total == 0:
        score = 0.0
    else:
        matched_count = len(matched_pairs)
        score = matched_count / total

    return {
        "leading_signals":   leading_signals,
        "risk_predictions":  risk_predictions,
        "matched_pairs":     matched_pairs,
        "correlation_score": round(score, 2),
    }


def cross_env_context(staging_env: str, prod_env: str,
                      window_minutes: int = 60) -> str:
    """
    Returns a concise context string for inclusion in agent.py's Claude prompt.
    Empty string if no cross-env signal is found.
    """
    if not staging_env or not prod_env or staging_env == prod_env:
        return ""

    staging_events = _fetch_events(staging_env, window_minutes)
    prod_events    = _fetch_events(prod_env, window_minutes)

    if not staging_events and not prod_events:
        return ""

    result = correlate(staging_events, prod_events)
    lines: list[str] = []

    if result["risk_predictions"]:
        lines.append(
            f"CROSS-ENV EARLY WARNING ({staging_env} → {prod_env}): "
            f"{len(result['risk_predictions'])} staging anomaly(ies) with no matching "
            "production signal yet:"
        )
        for p in result["risk_predictions"][:3]:
            lines.append(f"  - {p.get('service')} [{p.get('anomaly_type')}]: {p.get('note', '')}")

    if result["leading_signals"]:
        lines.append(
            f"CROSS-ENV PROPAGATION: production anomalies that preceded staging signal "
            f"(prod→staging pattern):"
        )
        for ls in result["leading_signals"][:3]:
            lines.append(f"  - {ls.get('note', '')}")

    if result["correlation_score"] >= 0.6:
        lines.append(
            f"High cross-env correlation score: {result['correlation_score']:.0%} of "
            f"staging anomalies have matching production signals — environments are behaving similarly."
        )

    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--staging",    required=True, help="Staging environment name")
    parser.add_argument("--production", required=True, help="Production environment name")
    parser.add_argument("--window-minutes", type=int, default=60,
                        help="Look-back window in minutes (default: 60)")
    parser.add_argument("--json", action="store_true",
                        help="Output full JSON result instead of summary")
    args = parser.parse_args()

    staging_events = _fetch_events(args.staging, args.window_minutes)
    prod_events    = _fetch_events(args.production, args.window_minutes)

    result = correlate(staging_events, prod_events)
    result["staging_anomalies"] = staging_events
    result["prod_anomalies"]    = prod_events
    result["staging_env"]       = args.staging
    result["prod_env"]          = args.production
    result["window_minutes"]    = args.window_minutes

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\nCross-environment correlation: {args.staging} → {args.production}")
        print(f"  Window:             {args.window_minutes}m")
        print(f"  Staging events:     {len(staging_events)}")
        print(f"  Production events:  {len(prod_events)}")
        print(f"  Correlation score:  {result['correlation_score']:.0%}")
        if result["risk_predictions"]:
            print(f"\nEarly warnings (staging → prod prediction):")
            for p in result["risk_predictions"]:
                print(f"  {p.get('note', '')}")
        if result["leading_signals"]:
            print(f"\nLeading signals (prod preceded staging):")
            for ls in result["leading_signals"]:
                print(f"  {ls.get('note', '')}")
        if not result["risk_predictions"] and not result["leading_signals"]:
            print("  No cross-environment correlation signals found.")


if __name__ == "__main__":
    main()
