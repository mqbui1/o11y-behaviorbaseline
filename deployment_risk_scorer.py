#!/usr/bin/env python3
"""
Behavioral Baseline — Deployment Risk Scorer
=============================================
Computes a risk score for a deployment before it ships, using behavioral
baseline data to predict how likely a change is to cause a detectable incident.

Today: notify_deployment.py just downgrades alert severity after the fact.
This scores BEFORE the deploy ships, integrating into CI/CD as a pre-deploy gate.

Risk dimensions:
  baseline_stability   — how diverse/churny is the service's trace fingerprint set?
                          A service with 1 fingerprint (all traffic looks the same)
                          will fire immediately on any change. A service with 30
                          fingerprints already has high churn — less likely to alert.

  error_baseline_health — does the service already have incident-era error signatures?
                          Deploying on top of a dirty baseline = guaranteed false alarms.

  downstream_blast_radius — how many services call this one? A change to a shared
                             dependency (mysql, config-server) affects everyone.

  recent_anomaly_rate  — has this service been firing anomalies recently?
                          Deploying into an already-unstable service is higher risk.

  threshold_tightness  — what are the per-service thresholds? Tighter thresholds
                          (set by adaptive_thresholds.py) mean lower tolerance for change.

Output:
  Risk score 0-100, grade (LOW/MEDIUM/HIGH/CRITICAL), and a specific rationale
  for each dimension. Exits with code 1 if score >= BLOCK_THRESHOLD (default 75)
  so it can gate CI/CD pipelines.

Usage:
  python deployment_risk_scorer.py --service api-gateway --environment petclinicmbtest
  python deployment_risk_scorer.py --service vets-service --environment petclinicmbtest --version v2.1
  python deployment_risk_scorer.py --service mysql --environment prod --block-threshold 60

  # CI/CD integration:
  python deployment_risk_scorer.py --service $SERVICE --environment $ENV || exit 1

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
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
APP_URL    = f"https://app.{REALM}.signalfx.com"
STREAM_URL = f"https://stream.{REALM}.signalfx.com"

THRESHOLDS_PATH = Path(os.environ.get("THRESHOLDS_PATH", "./thresholds.json"))
BLOCK_THRESHOLD = int(os.environ.get("RISK_BLOCK_THRESHOLD", "75"))

# Lookback for recent anomaly rate
ANOMALY_LOOKBACK_HOURS = 24

_INCIDENT_ERROR_TYPES = {
    "503", "502", "504", "java.net.ConnectException",
    "java.net.SocketTimeoutException", "CannotCreateTransactionException",
    "Connection refused", "ECONNREFUSED",
}


# ── HTTP ──────────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL, timeout: float = 20.0) -> Any:
    url     = f"{base_url}{path}"
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        raise RuntimeError(f"API {e.code}: {raw[:200]}")


def _signalflow_events(event_type: str, start_ms: int, end_ms: int,
                       environment: str | None, timeout: float = 12.0) -> int:
    """Return count of anomaly events for the environment in the window."""
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url, data=program.encode(),
        headers={"X-SF-Token": ACCESS_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    count = 0
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
                        dims = msg.get("metadata", {})
                        props = msg.get("properties", {})
                        ev = dims.get("environment") or props.get("environment", "all")
                        svc = (dims.get("service")
                               or props.get("service")
                               or (dims.get("root_operation","").split(":")[0]
                                   if ":" in dims.get("root_operation","") else None))
                        if (not environment or ev in (environment, "all")):
                            count += 1
                    if msg.get("event") in ("STREAM_STOP", "END_OF_CHANNEL"):
                        break
    except Exception:
        pass
    return count


# ── Data collection ────────────────────────────────────────────────────────────

def load_trace_baseline(service: str, environment: str | None) -> dict | None:
    script_dir = Path(__file__).parent
    for pattern in [f"baseline.{environment}.json", "baseline.json"]:
        fp = script_dir / pattern
        if fp.exists():
            try:
                data = json.loads(fp.read_text())
                return data
            except Exception:
                pass
    return None


def load_error_baseline(service: str, environment: str | None) -> dict | None:
    script_dir = Path(__file__).parent
    for pattern in [f"error_baseline.{environment}.json", "error_baseline.json"]:
        fp = script_dir / pattern
        if fp.exists():
            try:
                return json.loads(fp.read_text())
            except Exception:
                pass
    return None


def load_thresholds(service: str) -> dict:
    if THRESHOLDS_PATH.exists():
        try:
            data = json.loads(THRESHOLDS_PATH.read_text())
            return data.get("services", {}).get(service, {})
        except Exception:
            pass
    return {}


def fetch_topology(environment: str | None) -> dict:
    """Returns downstream callers and shared dep info."""
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - 2 * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [{"name": "sf_environment", "operator": "equals",
                               "value": environment, "scope": "global"}]
    try:
        result    = _request("POST", "/v2/apm/topology", body)
        edges_raw = (result.get("data") or {}).get("edges", [])
        edges     = [(e["fromNode"], e["toNode"]) for e in edges_raw
                     if e["fromNode"] != e["toNode"]]
        # callers_of[X] = services that call X
        callers_of: dict[str, set] = defaultdict(set)
        callees_of: dict[str, set] = defaultdict(set)
        for src, dst in edges:
            callers_of[dst].add(src)
            callees_of[src].add(dst)
        return {"callers_of": dict(callers_of),
                "callees_of": dict(callees_of)}
    except Exception as e:
        print(f"  [warn] topology: {e}", file=sys.stderr)
        return {"callers_of": {}, "callees_of": {}}


# ── Risk dimensions ────────────────────────────────────────────────────────────

def score_baseline_stability(service: str, baseline: dict | None) -> tuple[int, str]:
    """
    Stable service (1 fingerprint) → HIGH risk: any change fires immediately.
    Churny service (many fingerprints) → LOW risk: already tolerates diversity.
    Score: 0-30
    """
    if baseline is None:
        return 20, "No trace baseline found — cannot assess stability. Treat as medium risk."

    fps = baseline.get("fingerprints", {})
    # Filter to this service's root ops
    svc_fps = {h: v for h, v in fps.items()
               if service in v.get("services", [])
               or v.get("root_op", "").startswith(service + ":")}

    count = len(svc_fps)
    if count == 0:
        return 25, (f"No fingerprints for '{service}' in baseline — "
                    "watch will fire on first trace seen after deploy.")
    elif count == 1:
        return 30, (f"Only 1 fingerprint for '{service}' — extremely stable baseline. "
                    "Any execution path change will fire NEW_FINGERPRINT immediately.")
    elif count <= 3:
        return 20, (f"{count} fingerprints for '{service}' — low diversity. "
                    "Minor routing changes likely to trigger alerts.")
    elif count <= 8:
        return 10, (f"{count} fingerprints for '{service}' — moderate diversity. "
                    "Significant changes will alert, minor variations may not.")
    else:
        return 5,  (f"{count} fingerprints for '{service}' — high diversity baseline. "
                    "Service already tolerates execution path variation.")


def score_error_baseline_health(service: str,
                                  error_baseline: dict | None) -> tuple[int, str]:
    """
    Incident artifacts in error baseline → HIGH risk: deploy will cause false alarms.
    Score: 0-25
    """
    if error_baseline is None:
        return 5, "No error baseline found — no error patterns to conflict with."

    sigs = error_baseline.get("signatures", {})
    svc_sigs = {h: v for h, v in sigs.items() if v.get("service") == service}

    if not svc_sigs:
        return 0, f"No error signatures for '{service}' — clean baseline."

    artifact_sigs = [v for v in svc_sigs.values()
                     if any(art.lower() in v.get("error_type", "").lower()
                            for art in _INCIDENT_ERROR_TYPES)]
    total = len(svc_sigs)
    artifacts = len(artifact_sigs)

    if artifacts > 0:
        return 25, (f"ERROR BASELINE CONTAMINATED: {artifacts}/{total} signatures "
                    f"for '{service}' are incident artifacts "
                    f"({', '.join(v['error_type'] for v in artifact_sigs[:3])}). "
                    "Deploy will immediately cause false SIGNATURE_VANISHED alerts. "
                    "Run: error_fingerprint.py learn --reset first.")
    else:
        return 0, (f"{total} clean error signature(s) for '{service}' — "
                   "error baseline is healthy.")


def score_blast_radius(service: str, topology: dict) -> tuple[int, str]:
    """
    More callers = more services impacted by a bad deploy.
    Score: 0-25
    """
    callers = topology["callers_of"].get(service, set())
    callees = topology["callees_of"].get(service, set())
    n_callers = len(callers)
    n_callees = len(callees)

    if n_callers == 0 and n_callees == 0:
        return 5, (f"'{service}' has no dependency edges in APM topology — "
                   "isolated service, low blast radius.")
    elif n_callers >= 4:
        return 25, (f"'{service}' is called by {n_callers} service(s) "
                    f"({', '.join(sorted(callers)[:4])}{'...' if n_callers>4 else ''}). "
                    "A bad deploy will cascade to all callers immediately.")
    elif n_callers >= 2:
        return 15, (f"'{service}' is called by {n_callers} service(s) "
                    f"({', '.join(sorted(callers))}). Moderate blast radius.")
    else:
        caller_desc = f"called by {list(callers)[0]}" if callers else "leaf service"
        return 8,  (f"'{service}' is a {caller_desc} with {n_callees} callees. "
                    "Limited blast radius.")


def score_recent_anomaly_rate(service: str, environment: str | None) -> tuple[int, str]:
    """
    Service already firing anomalies → HIGH risk: deploy into instability.
    Score: 0-20
    """
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - ANOMALY_LOOKBACK_HOURS * 3600 * 1000

    trace_count = _signalflow_events("trace.path.drift", start_ms, now_ms, environment)
    error_count = _signalflow_events("error.signature.drift", start_ms, now_ms, environment)
    total = trace_count + error_count

    # Per-hour rate
    rate = total / ANOMALY_LOOKBACK_HOURS

    if rate >= 10:
        return 20, (f"Environment has {total} anomaly events in last "
                    f"{ANOMALY_LOOKBACK_HOURS}h ({rate:.1f}/h) — "
                    "already highly unstable. Deploying now will obscure new incidents.")
    elif rate >= 3:
        return 12, (f"{total} anomaly events in last {ANOMALY_LOOKBACK_HOURS}h "
                    f"({rate:.1f}/h) — some instability present.")
    elif rate >= 1:
        return 6,  (f"{total} anomaly events in last {ANOMALY_LOOKBACK_HOURS}h "
                    f"({rate:.1f}/h) — minor background noise, acceptable.")
    else:
        return 0,  (f"{total} anomaly event(s) in last {ANOMALY_LOOKBACK_HOURS}h — "
                    "environment is quiet, good time to deploy.")


# ── Score aggregation ─────────────────────────────────────────────────────────

def compute_risk(service: str, environment: str | None,
                 version: str | None = None,
                 block_threshold: int = BLOCK_THRESHOLD) -> dict:
    """
    Compute and return the full risk assessment.
    """
    print(f"[risk-scorer] Assessing deployment risk for '{service}' "
          f"(env={environment or 'all'})...")

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=4) as pool:
        tb_future   = pool.submit(load_trace_baseline, service, environment)
        eb_future   = pool.submit(load_error_baseline, service, environment)
        topo_future = pool.submit(fetch_topology, environment)
        rate_future = pool.submit(score_recent_anomaly_rate, service, environment)

        trace_bl = tb_future.result()
        error_bl = eb_future.result()
        topology = topo_future.result()
        rate_score, rate_rationale = rate_future.result()

    thresholds = load_thresholds(service)

    s1, r1 = score_baseline_stability(service, trace_bl)
    s2, r2 = score_error_baseline_health(service, error_bl)
    s3, r3 = score_blast_radius(service, topology)
    s4, r4 = rate_score, rate_rationale

    # Threshold tightness modifier: tight thresholds = more sensitive = higher risk
    dom = float(thresholds.get("missing_service_dominance_threshold", 0.60))
    span_mult = float(thresholds.get("span_count_spike_multiplier", 2.0))
    threshold_modifier = 0
    threshold_rationale = ""
    if dom <= 0.50:
        threshold_modifier += 5
        threshold_rationale = (f"Tight dominance threshold ({dom}) set by adaptive tuner — "
                               "lower tolerance for change on this service.")
    elif dom >= 0.75:
        threshold_modifier -= 5
        threshold_rationale = (f"Loose dominance threshold ({dom}) — higher tolerance "
                               "for path variation.")
    if span_mult <= 1.5:
        threshold_modifier += 3

    raw_score = s1 + s2 + s3 + s4 + threshold_modifier
    score     = max(0, min(100, raw_score))

    if score >= 75:
        grade = "CRITICAL"
    elif score >= 55:
        grade = "HIGH"
    elif score >= 35:
        grade = "MEDIUM"
    else:
        grade = "LOW"

    return {
        "service":     service,
        "environment": environment,
        "version":     version,
        "score":       score,
        "grade":       grade,
        "block":       score >= block_threshold,
        "dimensions": [
            {"name": "baseline_stability",     "score": s1, "max": 30, "rationale": r1},
            {"name": "error_baseline_health",  "score": s2, "max": 25, "rationale": r2},
            {"name": "blast_radius",           "score": s3, "max": 25, "rationale": r3},
            {"name": "recent_anomaly_rate",    "score": s4, "max": 20, "rationale": r4},
            {"name": "threshold_tightness",    "score": threshold_modifier,
             "max": 8, "rationale": threshold_rationale or "Default thresholds in use."},
        ],
    }


def print_risk_report(risk: dict, block_threshold: int = BLOCK_THRESHOLD) -> None:
    grade_icon = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}
    icon = grade_icon.get(risk["grade"], "•")
    ver  = f" v{risk['version']}" if risk.get("version") else ""

    print(f"\n{'='*65}")
    print(f"DEPLOYMENT RISK ASSESSMENT")
    print(f"  Service:     {risk['service']}{ver}")
    print(f"  Environment: {risk['environment'] or 'all'}")
    print(f"  Score:       {risk['score']}/100")
    print(f"  Grade:       {icon} {risk['grade']}")
    if risk["block"]:
        print(f"  Decision:    ❌ BLOCK — score ≥ {block_threshold} (pipeline gate: exit 1)")
    else:
        print(f"  Decision:    ✅ PROCEED — score < {block_threshold}")
    print(f"{'='*65}")

    print(f"\n  Risk Dimensions:")
    for d in risk["dimensions"]:
        bar = "█" * d["score"] + "░" * (d["max"] - max(0, d["score"]))
        print(f"\n  {d['name']:<28} {d['score']:>3}/{d['max']}  {bar}")
        print(f"    {d['rationale']}")

    print()


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Deployment Risk Scorer — pre-deploy behavioral baseline risk gate"
    )
    parser.add_argument("--service",     required=True)
    parser.add_argument("--environment", default=None)
    parser.add_argument("--version",     default=None)
    parser.add_argument("--block-threshold", type=int, default=BLOCK_THRESHOLD,
                        help=f"Score at which to exit 1 (default: {BLOCK_THRESHOLD})")
    parser.add_argument("--json", action="store_true",
                        help="Output risk assessment as JSON")
    args = parser.parse_args()

    block_threshold = args.block_threshold

    risk = compute_risk(args.service, args.environment, args.version,
                        block_threshold=block_threshold)

    if args.json:
        print(json.dumps(risk, indent=2))
    else:
        print_risk_report(risk, block_threshold=block_threshold)

    sys.exit(1 if risk["block"] else 0)


if __name__ == "__main__":
    main()
