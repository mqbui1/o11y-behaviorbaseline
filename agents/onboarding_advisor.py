#!/usr/bin/env python3
"""
Behavioral Baseline — Onboarding Advisor
=========================================
Inspects a new environment's topology, traffic volume, and error patterns,
then recommends appropriate configuration before onboarding begins.

Today, onboard.py --auto applies the same defaults to every environment:
  - watch every 5m, learn 120m, all anomaly types enabled, same thresholds

This is wrong for:
  - Low-traffic dev envs: too few traces for a stable baseline →
    SIGNATURE_VANISHED fires constantly, thresholds need loosening
  - High-traffic prod envs: 5m watch is too slow for fast-moving incidents,
    tighter multipliers catch spikes earlier
  - Single-service envs: MISSING_SERVICE is meaningless (no dependencies),
    TIER2_TIER3 correlation never fires
  - Infra-heavy envs: many DB/cache nodes inflate SPAN_COUNT_SPIKE noise

How it works:
  1. Fetch topology: service count, edge count, shared dependencies
  2. Sample traces (5 min window): measure traces/min, avg span count
  3. Sample error traces: measure error rate
  4. Score the environment on 4 dimensions:
       traffic_tier   LOW / MEDIUM / HIGH  (traces/min)
       error_tier     QUIET / NORMAL / NOISY  (error rate)
       complexity     SIMPLE / MEDIUM / COMPLEX  (service count + edges)
       stability      (will be set by adaptive_thresholds over time)
  5. Map tiers to concrete config recommendations:
       - watch_interval_minutes
       - learn_window_minutes
       - enabled_anomaly_types (which to suppress)
       - threshold overrides (dominance, spike multipliers)
  6. Write recommendations to thresholds.json under the environment's
     services block, and print a human-readable advisory report

Usage:
  python onboarding_advisor.py --environment petclinicmbtest
  python onboarding_advisor.py --environment my-dev-env --dry-run
  python onboarding_advisor.py --environment prod --apply    # write thresholds

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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL = f"https://api.{REALM}.signalfx.com"
APP_URL  = f"https://app.{REALM}.signalfx.com"

THRESHOLDS_PATH = Path(os.environ.get("THRESHOLDS_PATH", str(Path(__file__).parent.parent / "data" / "thresholds.json")))

# Traffic tier thresholds (traces/min)
TRAFFIC_LOW_MAX    = 2.0    # < 2/min  → LOW
TRAFFIC_HIGH_MIN   = 20.0   # ≥ 20/min → HIGH
# Error rate tier thresholds
ERROR_QUIET_MAX    = 0.02   # < 2%  → QUIET
ERROR_NOISY_MIN    = 0.15   # ≥ 15% → NOISY
# Complexity thresholds (real service count)
COMPLEXITY_SIMPLE_MAX  = 3
COMPLEXITY_COMPLEX_MIN = 8

_DB_KEYWORDS = {
    "mysql", "postgres", "postgresql", "mongodb", "redis", "cassandra",
    "elasticsearch", "dynamo", "sqlite", "oracle", "sqlserver", "mssql",
    "mariadb", "cockroach",
}


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: Any = None,
             base_url: str = BASE_URL, timeout: float = 30.0) -> Any:
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


# ── Data collection ────────────────────────────────────────────────────────────

def fetch_topology(environment: str | None) -> dict:
    """Fetch topology and compute service/edge/shared-dep counts."""
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - 2 * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [{"name": "sf_environment", "operator": "equals",
                               "value": environment, "scope": "global"}]
    try:
        result     = _request("POST", "/v2/apm/topology", body)
        nodes      = (result.get("data") or {}).get("nodes", [])
        edges_raw  = (result.get("data") or {}).get("edges", [])
        services   = [n["serviceName"] for n in nodes if not n.get("inferred")]
        inferred   = [n["serviceName"] for n in nodes if n.get("inferred")]
        edges      = [(e["fromNode"], e["toNode"]) for e in edges_raw
                      if e["fromNode"] != e["toNode"]]

        # Shared deps: called by 2+ services
        from collections import defaultdict
        callers_of: dict[str, set] = defaultdict(set)
        for src, dst in edges:
            callers_of[dst].add(src)
        shared_deps = [dep for dep, callers in callers_of.items()
                       if len(callers) >= 2]
        db_nodes    = [n for n in inferred
                       if any(k in n.lower() for k in _DB_KEYWORDS)]

        # Ingress = no inbound edges
        has_inbound = {dst for _, dst in edges if dst in services}
        ingress     = [s for s in services if s not in has_inbound]

        return {
            "services":    services,
            "inferred":    inferred,
            "db_nodes":    db_nodes,
            "edges":       edges,
            "shared_deps": shared_deps,
            "ingress":     ingress,
        }
    except Exception as e:
        print(f"  [warn] topology fetch: {e}", file=sys.stderr)
        return {"services": [], "inferred": [], "db_nodes": [],
                "edges": [], "shared_deps": [], "ingress": []}


def _search_traces(environment: str | None, has_errors: bool,
                   limit: int = 50, window_minutes: int = 30) -> list[dict]:
    """Search for traces (optionally error-only) in the last window_minutes."""
    now_ms   = int(time.time() * 1000)
    start_ms = now_ms - window_minutes * 60 * 1000
    tag_filters: list[dict] = []
    if environment:
        tag_filters.append({"tag": "sf_environment", "operation": "IN",
                             "values": [environment]})
    if has_errors:
        tag_filters.append({"tag": "sf_error", "operation": "IN",
                             "values": ["true"]})
    parameters = {
        "sharedParameters": {
            "timeRangeMillis": {"gte": start_ms, "lte": now_ms},
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
        r      = _request("POST", "/v2/apm/graphql?op=StartAnalyticsSearch",
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
            r2       = _request("POST", "/v2/apm/graphql?op=GetAnalyticsSearch",
                                get_body, base_url=APP_URL)
            sections = (((r2.get("data") or {}).get("getAnalyticsSearch") or {})
                        .get("sections", []))
            for section in sections:
                if (section.get("sectionType") == "traceExamples"
                        and section.get("isComplete")):
                    return section.get("legacyTraceExamples") or []
            time.sleep(delay)
            elapsed += delay
            delay = min(delay * 2, 2.0)
    except Exception as e:
        print(f"  [warn] trace search: {e}", file=sys.stderr)
    return []


def measure_traffic(environment: str | None,
                    window_minutes: int = 30) -> dict:
    """
    Sample traces to estimate traffic volume and error rate.
    Returns {traces_per_min, error_rate, avg_span_count, sample_size}
    """
    with ThreadPoolExecutor(max_workers=2) as pool:
        all_future   = pool.submit(_search_traces, environment, False, 100,
                                   window_minutes)
        error_future = pool.submit(_search_traces, environment, True,  50,
                                   window_minutes)
        all_traces   = all_future.result()
        error_traces = error_future.result()

    sample_size   = len(all_traces)
    # Estimate true rate: if we hit the limit (100) assume we only saw a fraction
    # of real traffic. Use a conservative estimate.
    traces_per_min = sample_size / window_minutes

    error_rate = (len(error_traces) / sample_size) if sample_size > 0 else 0.0

    # Avg span count from examples that include it
    span_counts = []
    for t in all_traces:
        sc = t.get("spanCount") or t.get("totalSpanCount")
        if sc:
            span_counts.append(int(sc))
    avg_span_count = sum(span_counts) / len(span_counts) if span_counts else 0

    return {
        "traces_per_min": round(traces_per_min, 2),
        "error_rate":     round(error_rate, 4),
        "avg_span_count": round(avg_span_count, 1),
        "sample_size":    sample_size,
        "window_minutes": window_minutes,
    }


# ── Tier classification ────────────────────────────────────────────────────────

def classify_environment(topology: dict, traffic: dict) -> dict:
    """
    Classify the environment into tiers across 3 dimensions.
    Returns {traffic_tier, error_tier, complexity, service_count,
             has_dependencies, has_shared_deps}
    """
    tpm = traffic["traces_per_min"]
    if tpm < TRAFFIC_LOW_MAX:
        traffic_tier = "LOW"
    elif tpm >= TRAFFIC_HIGH_MIN:
        traffic_tier = "HIGH"
    else:
        traffic_tier = "MEDIUM"

    er = traffic["error_rate"]
    if er < ERROR_QUIET_MAX:
        error_tier = "QUIET"
    elif er >= ERROR_NOISY_MIN:
        error_tier = "NOISY"
    else:
        error_tier = "NORMAL"

    svc_count = len(topology["services"])
    if svc_count <= COMPLEXITY_SIMPLE_MAX:
        complexity = "SIMPLE"
    elif svc_count >= COMPLEXITY_COMPLEX_MIN:
        complexity = "COMPLEX"
    else:
        complexity = "MEDIUM"

    return {
        "traffic_tier":    traffic_tier,
        "error_tier":      error_tier,
        "complexity":      complexity,
        "service_count":   svc_count,
        "has_dependencies": len(topology["edges"]) > 0,
        "has_shared_deps":  len(topology["shared_deps"]) > 0,
        "db_node_count":   len(topology["db_nodes"]),
    }


# ── Recommendation generation ──────────────────────────────────────────────────

def generate_recommendations(environment: str | None, topology: dict,
                              traffic: dict, profile: dict) -> dict:
    """
    Map environment profile to concrete configuration recommendations.
    Returns a recommendations dict consumed by --apply and the report.
    """
    rec: dict = {
        "watch_interval_minutes": 5,
        "learn_window_minutes":   120,
        "correlate_window_minutes": 15,
        "enabled_anomaly_types":  [
            "NEW_FINGERPRINT", "MISSING_SERVICE", "SPAN_COUNT_SPIKE",
            "NEW_ERROR_SIGNATURE", "SIGNATURE_SPIKE", "SIGNATURE_VANISHED",
        ],
        "per_service_overrides":  {},
        "rationale":              [],
        "caveats":                [],
    }

    tt  = profile["traffic_tier"]
    et  = profile["error_tier"]
    cx  = profile["complexity"]
    svc = profile["service_count"]

    # ── Watch interval ────────────────────────────────────────────────────────
    if tt == "HIGH":
        rec["watch_interval_minutes"] = 2
        rec["rationale"].append(
            f"HIGH traffic ({traffic['traces_per_min']:.1f} traces/min): "
            f"2-minute watch interval for faster incident detection."
        )
    elif tt == "LOW":
        rec["watch_interval_minutes"] = 10
        rec["rationale"].append(
            f"LOW traffic ({traffic['traces_per_min']:.1f} traces/min): "
            f"10-minute watch interval — 5-min would over-sample sparse data."
        )

    # ── Learn window ──────────────────────────────────────────────────────────
    if tt == "LOW":
        rec["learn_window_minutes"] = 240
        rec["rationale"].append(
            "LOW traffic: extending learn window to 4h to collect enough "
            "trace diversity for a stable baseline."
        )
    elif tt == "HIGH":
        rec["learn_window_minutes"] = 60
        rec["rationale"].append(
            "HIGH traffic: 1h learn window is sufficient — diverse patterns "
            "appear quickly at this volume."
        )

    # ── SIGNATURE_VANISHED suppression ────────────────────────────────────────
    if tt == "LOW":
        rec["enabled_anomaly_types"].remove("SIGNATURE_VANISHED")
        rec["rationale"].append(
            "Disabling SIGNATURE_VANISHED: low traffic means dominant error "
            "signatures fluctuate naturally — vanished detection fires too often "
            "on sparse baselines and produces false positives."
        )

    # ── MISSING_SERVICE suppression (single-service envs) ─────────────────────
    if not profile["has_dependencies"]:
        rec["enabled_anomaly_types"].remove("MISSING_SERVICE")
        rec["rationale"].append(
            f"Disabling MISSING_SERVICE: '{environment or 'this environment'}' "
            f"has no service dependencies in APM topology — detection would "
            f"never fire meaningfully."
        )

    # ── Per-service threshold overrides ───────────────────────────────────────
    all_services = topology["services"]

    for svc_name in all_services:
        overrides: dict = {}
        svc_rationale: list[str] = []

        # Ingress services (api-gateway, frontend) tend to have high churn
        is_ingress = svc_name in topology["ingress"]
        if is_ingress and tt != "LOW":
            overrides["missing_service_dominance_threshold"] = 0.70
            svc_rationale.append(
                "ingress service — raised dominance threshold (0.70) to reduce "
                "false positives from A/B routing and canary traffic"
            )

        # DB/infra nodes should never change — tightest thresholds
        is_db = any(k in svc_name.lower() for k in _DB_KEYWORDS)
        if is_db:
            overrides["missing_service_dominance_threshold"] = 0.50
            overrides["span_count_spike_multiplier"]         = 1.5
            svc_rationale.append(
                "DB/infra node — tightest thresholds: dominance=0.50, "
                "span_spike=1.5× (any change to infra is high-signal)"
            )

        # High error rate services: loosen error spike multiplier
        if et == "NOISY" and not is_db:
            overrides["error_spike_multiplier"] = 4.0
            svc_rationale.append(
                "NOISY error environment — raised error_spike_multiplier to "
                "4.0 to reduce alert fatigue on already-elevated baseline"
            )

        # HIGH traffic: tighter span spike (more data = more confidence)
        if tt == "HIGH" and not is_db:
            overrides["span_count_spike_multiplier"] = 1.5
            svc_rationale.append(
                "HIGH traffic — tightened span_spike to 1.5× (dense baseline "
                "means span count outliers are more reliable signal)"
            )

        if overrides:
            rec["per_service_overrides"][svc_name] = {
                "overrides":  overrides,
                "rationale":  svc_rationale,
            }

    # ── Caveats ───────────────────────────────────────────────────────────────
    if traffic["sample_size"] < 10:
        rec["caveats"].append(
            f"Only {traffic['sample_size']} traces sampled in the last "
            f"{traffic['window_minutes']}m — recommendations are based on "
            f"limited data. Re-run after more traffic flows."
        )
    if cx == "SIMPLE" and svc == 1:
        rec["caveats"].append(
            "Single-service environment: cross-tier correlation (TIER2_TIER3) "
            "will never fire. Consider tier 1b detectors as primary signal."
        )
    if profile["db_node_count"] > 3:
        rec["caveats"].append(
            f"{profile['db_node_count']} inferred DB/infra nodes detected. "
            "SPAN_COUNT_SPIKE thresholds have been tightened on these nodes."
        )

    return rec


# ── Report formatting ──────────────────────────────────────────────────────────

def print_report(environment: str | None, topology: dict,
                 traffic: dict, profile: dict, rec: dict) -> None:
    env_label = environment or "(all environments)"
    print(f"\n{'='*65}")
    print(f"ONBOARDING ADVISORY — {env_label}")
    print(f"{'='*65}")

    print(f"\n  Environment Profile")
    print(f"  {'─'*45}")
    print(f"  Services:        {profile['service_count']}  "
          f"({', '.join(topology['services'][:6])}"
          f"{'...' if len(topology['services']) > 6 else ''})")
    if topology["db_nodes"]:
        print(f"  DB/infra nodes:  {', '.join(topology['db_nodes'][:4])}")
    if topology["shared_deps"]:
        print(f"  Shared deps:     {', '.join(topology['shared_deps'][:4])}")
    print(f"  Traffic:         {profile['traffic_tier']}  "
          f"({traffic['traces_per_min']:.1f} traces/min, "
          f"sample={traffic['sample_size']} over {traffic['window_minutes']}m)")
    print(f"  Error rate:      {profile['error_tier']}  "
          f"({traffic['error_rate']:.1%})")
    print(f"  Complexity:      {profile['complexity']}")

    print(f"\n  Recommended Configuration")
    print(f"  {'─'*45}")
    print(f"  Watch interval:  every {rec['watch_interval_minutes']} min")
    print(f"  Learn window:    {rec['learn_window_minutes']} min")
    print(f"  Correlate window: {rec['correlate_window_minutes']} min")
    enabled = rec["enabled_anomaly_types"]
    all_types = ["NEW_FINGERPRINT", "MISSING_SERVICE", "SPAN_COUNT_SPIKE",
                 "NEW_ERROR_SIGNATURE", "SIGNATURE_SPIKE", "SIGNATURE_VANISHED"]
    disabled  = [t for t in all_types if t not in enabled]
    print(f"  Enabled types:   {', '.join(enabled)}")
    if disabled:
        print(f"  Disabled types:  {', '.join(disabled)}")

    if rec["per_service_overrides"]:
        print(f"\n  Per-Service Threshold Overrides")
        print(f"  {'─'*45}")
        for svc_name, info in sorted(rec["per_service_overrides"].items()):
            print(f"  {svc_name}:")
            for k, v in info["overrides"].items():
                print(f"    {k} = {v}")
            for r in info["rationale"]:
                print(f"    → {r}")

    if rec["rationale"]:
        print(f"\n  Rationale")
        print(f"  {'─'*45}")
        for r in rec["rationale"]:
            print(f"  • {r}")

    if rec["caveats"]:
        print(f"\n  Caveats")
        print(f"  {'─'*45}")
        for c in rec["caveats"]:
            print(f"  ⚠  {c}")

    print(f"\n  Suggested cron schedule:")
    wi = rec["watch_interval_minutes"]
    if wi == 2:
        sched = "*/2 * * * *"
    elif wi == 10:
        sched = "*/10 * * * *"
    else:
        sched = "*/5 * * * *"
    env_arg = f"--environment {environment}" if environment else ""
    print(f"  {sched}  trace_fingerprint.py {env_arg} watch --window-minutes {wi}")
    print(f"  {sched}  error_fingerprint.py {env_arg} watch --window-minutes {wi}")
    print(f"  {sched}  correlate.py {env_arg} "
          f"--window-minutes {rec['correlate_window_minutes']}")
    print(f"  0 2 * * *   trace_fingerprint.py {env_arg} learn "
          f"--window-minutes {rec['learn_window_minutes']}")
    print(f"  0 2 * * *   error_fingerprint.py {env_arg} learn "
          f"--window-minutes {rec['learn_window_minutes']}")
    print()


# ── Apply recommendations ──────────────────────────────────────────────────────

def apply_recommendations(environment: str | None, rec: dict) -> None:
    """Write per-service threshold overrides to thresholds.json."""
    if THRESHOLDS_PATH.exists():
        try:
            thresholds = json.loads(THRESHOLDS_PATH.read_text())
        except Exception:
            thresholds = {}
    else:
        thresholds = {}

    services_block = thresholds.setdefault("services", {})
    written = 0
    for svc_name, info in rec["per_service_overrides"].items():
        existing = services_block.get(svc_name, {})
        existing.update(info["overrides"])
        services_block[svc_name] = existing
        written += 1

    # Store environment-level config under a separate key
    env_key = environment or "__none__"
    thresholds.setdefault("environments", {})[env_key] = {
        "watch_interval_minutes":    rec["watch_interval_minutes"],
        "learn_window_minutes":      rec["learn_window_minutes"],
        "correlate_window_minutes":  rec["correlate_window_minutes"],
        "enabled_anomaly_types":     rec["enabled_anomaly_types"],
        "advised_at":                datetime.now(timezone.utc).isoformat(),
    }

    thresholds["_updated_at"] = datetime.now(timezone.utc).isoformat()
    thresholds.setdefault("_meta", {
        "description": (
            "Per-service threshold overrides and per-environment config. "
            "Written by onboarding_advisor.py and adaptive_thresholds.py."
        ),
    })

    THRESHOLDS_PATH.write_text(json.dumps(thresholds, indent=2))
    print(f"  Written {written} per-service override(s) + environment config "
          f"to {THRESHOLDS_PATH}")


# ── Main ──────────────────────────────────────────────────────────────────────

def advise(environment: str | None, apply: bool = False,
           window_minutes: int = 30) -> dict:
    """
    Full advisory flow. Returns the recommendations dict.
    Called by onboard.py for new environments when --advise is set.
    """
    print(f"[advisor] Inspecting environment '{environment or 'all'}'...")

    print(f"  Fetching topology...")
    topology = fetch_topology(environment)
    print(f"  {len(topology['services'])} services, "
          f"{len(topology['edges'])} edges, "
          f"{len(topology['shared_deps'])} shared deps")

    print(f"  Sampling traffic (last {window_minutes}m)...")
    traffic  = measure_traffic(environment, window_minutes)
    print(f"  {traffic['traces_per_min']:.1f} traces/min, "
          f"error_rate={traffic['error_rate']:.1%}, "
          f"sample={traffic['sample_size']}")

    profile  = classify_environment(topology, traffic)
    rec      = generate_recommendations(environment, topology, traffic, profile)

    print_report(environment, topology, traffic, profile, rec)

    if apply:
        apply_recommendations(environment, rec)

    return rec


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Onboarding Advisor — recommends per-environment baseline config"
    )
    parser.add_argument("--environment", default=None,
                        help="Environment to inspect (e.g. petclinicmbtest)")
    parser.add_argument("--apply", action="store_true",
                        help="Write recommendations to thresholds.json")
    parser.add_argument("--window-minutes", type=int, default=30,
                        help="Traffic sampling window in minutes (default: 30)")
    args = parser.parse_args()
    advise(args.environment, apply=args.apply,
           window_minutes=args.window_minutes)


if __name__ == "__main__":
    main()
