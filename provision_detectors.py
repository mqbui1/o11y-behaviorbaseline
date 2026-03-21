#!/usr/bin/env python3
"""
Behavioral Baseline Detector Provisioner
=========================================
Auto-discovers your APM topology from Splunk Observability and provisions
all SignalFlow detectors (Tiers 1, 3, 4) for any onboarded application.

No hardcoded service names. Everything is derived from the live service map.

What gets created:
  Tier 1a — New caller of any inferred database node          [Critical]
  Tier 1b — Call volume spike on any ingress service          [Major]
  Tier 1c — Missing edge (known DB caller goes silent)        [Major]
  Tier 3  — Error rate spike on any DB-calling service        [Major]
  Tier 4  — p99 latency drift on any DB-calling service       [Warning]

Usage:
  # Preview what would be created (dry run)
  python provision_detectors.py --dry-run

  # Provision detectors for all discovered services
  python provision_detectors.py

  # Provision for a specific environment tag
  python provision_detectors.py --environment production

  # Tear down all detectors created by this script
  python provision_detectors.py --teardown

Required env vars:
  SPLUNK_ACCESS_TOKEN
  SPLUNK_REALM          (default: us0)
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.", file=sys.stderr)
    sys.exit(1)

BASE_URL = f"https://api.{REALM}.signalfx.com"
APP_URL  = f"https://app.{REALM}.signalfx.com"

# Tag applied to every created detector so --teardown can find them all
MANAGED_TAG = "behavioral-baseline-managed"

# Lookback window for topology discovery
TOPOLOGY_LOOKBACK_HOURS = 48

# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url = f"{base_url}{path}"
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            detail = json.loads(raw)
        except Exception:
            detail = raw
        raise RuntimeError(f"Splunk API error {e.code}: {json.dumps(detail)}")


def _qs(params: dict) -> str:
    filtered = {k: str(v) for k, v in params.items() if v is not None}
    return ("?" + urllib.parse.urlencode(filtered)) if filtered else ""


# ── Topology discovery ─────────────────────────────────────────────────────────

def discover_topology(environment: str | None = None) -> dict:
    """
    Derive the full service topology from the live APM service map.
    If environment is given, topology is scoped to that sf_environment value.
    Returns:
      services      — instrumented services
      inferred      — inferred nodes (databases, queues, external calls)
      db_nodes      — inferred nodes identified as databases
      edges         — directed edges (self-loops excluded)
      ingress_nodes — services with no inbound edges (entry points)
      db_callers    — services that have a direct edge to any db_node
      environment   — the environment filter used (None = all environments)
    """
    now  = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    then = time.strftime("%Y-%m-%dT%H:%M:%SZ",
                         time.gmtime(time.time() - TOPOLOGY_LOOKBACK_HOURS * 3600))
    body: dict = {"timeRange": f"{then}/{now}"}
    if environment:
        body["tagFilters"] = [
            {"name": "sf_environment", "operator": "equals",
             "value": environment, "scope": "global"}
        ]
    result    = _request("POST", "/v2/apm/topology", body)
    nodes     = (result.get("data") or {}).get("nodes", [])
    edges_raw = (result.get("data") or {}).get("edges", [])

    services = [n["serviceName"] for n in nodes if not n.get("inferred")]
    inferred = [n["serviceName"] for n in nodes if n.get("inferred")]
    edges    = [(e["fromNode"], e["toNode"]) for e in edges_raw
                if e["fromNode"] != e["toNode"]]

    db_keywords = {
        "mysql", "postgres", "postgresql", "mongodb", "redis",
        "cassandra", "elasticsearch", "dynamo", "sqlite", "oracle",
        "sqlserver", "mssql", "mariadb", "cockroach",
    }
    db_nodes = [
        n for n in inferred
        if ":" in n or any(k in n.lower() for k in db_keywords)
    ]

    has_inbound   = {to for (_, to) in edges if to in services}
    ingress_nodes = [s for s in services if s not in has_inbound]

    db_callers = sorted({
        src for (src, dst) in edges
        if dst in db_nodes and src in services
    })

    return {
        "services":      services,
        "inferred":      inferred,
        "db_nodes":      db_nodes,
        "edges":         edges,
        "ingress_nodes": ingress_nodes,
        "db_callers":    db_callers,
        "environment":   environment,
    }


# ── SignalFlow program builders ────────────────────────────────────────────────
# Each function accepts an optional environment string.
# When provided, an sf_environment filter is ANDed into every data() call so
# the detector fires only for that environment — production, staging, dev, etc.
# When None, the detector covers all environments (useful for orgs with a
# single environment or where environment tagging is not yet configured).

def _env_filter_expr(environment: str | None) -> str:
    """Return a SignalFlow filter expression string for the given environment."""
    if environment:
        return f"filter('sf_environment', '{environment}')"
    return None


def program_new_db_caller(db_node: str, environment: str | None = None) -> str:
    """
    Tier 1a: Fire when any service calls a database node.
    Scoped to environment when provided.
    """
    env_f = _env_filter_expr(environment)
    svc_f = f"filter('sf_service', '{db_node}')"
    combined = f"{env_f} and {svc_f}" if env_f else svc_f
    return (
        f"A = data('spans.count', filter={combined})"
        f".sum(by=['sf_environment', 'sf_initiating_service']).mean(over='5m')\n"
        f"detect(when(A > 0)).publish('New caller of {db_node} detected')"
    )


def program_ingress_volume_spike(ingress_service: str,
                                  environment: str | None = None) -> str:
    """
    Tier 1b: Fire when an ingress service's call volume spikes to >10x
    the same 5-minute window from exactly 1 week ago (seasonality-aware).
    Using timeshift('1w') instead of a rolling hourly mean avoids false
    positives from legitimate time-of-day or day-of-week traffic patterns.
    Scoped to environment when provided.
    """
    env_f = _env_filter_expr(environment)
    svc_f = f"filter('sf_service', '{ingress_service}')"
    combined = f"{env_f} and {svc_f}" if env_f else svc_f
    return (
        f"A = data('spans.count', filter={combined})"
        f".sum(by=['sf_environment', 'sf_operation']).mean(over='5m')\n"
        f"B = data('spans.count', filter={combined})"
        f".sum(by=['sf_environment', 'sf_operation']).mean(over='5m')"
        f".timeshift('1w')\n"
        f"detect(when(A > B * 10))"
        f".publish('{ingress_service} edge volume spike (>10x same window last week)')"
    )


def program_error_rate_spike(db_callers: list[str],
                              environment: str | None = None) -> str:
    """
    Tier 3: Fire when the error span rate across DB-calling services exceeds
    3x their 1-hour rolling mean, sustained for 5 minutes.
    Scoped to environment when provided.
    """
    svc_list = ", ".join(f"'{s}'" for s in db_callers)
    env_f = _env_filter_expr(environment)
    base = (
        f"svc_filter = filter('sf_service', {svc_list})\n"
        f"err_filter = filter('error', 'true')\n"
    )
    if env_f:
        data_filter = f"{env_f} and svc_filter and err_filter"
    else:
        data_filter = "svc_filter and err_filter"
    return (
        base
        + f"A = data('spans.count', filter={data_filter})"
        f".sum(by=['sf_service', 'sf_environment']).mean(over='5m')\n"
        f"B = data('spans.count', filter={data_filter})"
        f".sum(by=['sf_service', 'sf_environment']).mean(over='1h')\n"
        f"detect(when(A > B * 3, lasting='5m'))"
        f".publish('DB service error rate spike (>3x hourly mean)')"
    )


def program_missing_db_caller(db_node: str, caller: str,
                               environment: str | None = None) -> str:
    """
    Tier 1c: Fire when a known DB caller goes silent — i.e. its span count
    drops to zero for a sustained window. This catches:
      - circuit breakers opening
      - service being removed or renamed
      - DB connection pool exhaustion causing fallback paths
    Fires when a 30-minute mean drops to 0 after a non-zero 6-hour mean.
    """
    env_f    = _env_filter_expr(environment)
    svc_f    = f"filter('sf_service', '{db_node}')"
    init_f   = f"filter('sf_initiating_service', '{caller}')"
    combined = " and ".join(f for f in [env_f, svc_f, init_f] if f)
    return (
        f"A = data('spans.count', filter={combined})"
        f".sum(by=['sf_environment', 'sf_initiating_service']).mean(over='30m')\n"
        f"B = data('spans.count', filter={combined})"
        f".sum(by=['sf_environment', 'sf_initiating_service']).mean(over='6h')\n"
        f"detect(when(A == 0 and B > 0, lasting='30m'))"
        f".publish('{caller} stopped calling {db_node}')"
    )


def program_p99_latency_drift(db_callers: list[str],
                               environment: str | None = None) -> str:
    """
    Tier 4: Fire when p99 latency for any DB-calling service exceeds 2x
    the same 15-minute window from exactly 1 week ago (seasonality-aware),
    sustained for 15 minutes. Using timeshift('1w') accounts for legitimate
    latency variation by time-of-day and day-of-week (e.g. batch jobs, peak
    hours) that would produce false positives with a simple rolling mean.
    Scoped to environment when provided.
    """
    svc_list = ", ".join(f"'{s}'" for s in db_callers)
    env_f = _env_filter_expr(environment)
    base = f"svc_filter = filter('sf_service', {svc_list})\n"
    data_filter = f"{env_f} and svc_filter" if env_f else "svc_filter"
    return (
        base
        + f"A = data('service.request.duration.ns.p99', filter={data_filter})"
        f".mean(by=['sf_service', 'sf_environment']).mean(over='15m')\n"
        f"B = data('service.request.duration.ns.p99', filter={data_filter})"
        f".mean(by=['sf_service', 'sf_environment']).mean(over='15m')"
        f".timeshift('1w')\n"
        f"detect(when(A > B * 2, lasting='15m'))"
        f".publish('DB service p99 latency drift (>2x same window last week)')"
    )


# ── Detector plan builder ──────────────────────────────────────────────────────

def build_detector_plan(topo: dict) -> list[dict]:
    """
    Given a topology dict (which includes topo["environment"]), return a list
    of detector specs to create. Detector names and tags are scoped per
    environment so multiple environments can coexist without name collisions.
    """
    detectors = []
    env       = topo.get("environment")          # None = all environments
    env_label = f" [{env}]" if env else ""        # appended to detector names
    env_tag   = f"env-{env}" if env else "env-all"
    ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # ── Tier 1a: one detector per database node ───────────────────────────────
    for db_node in topo["db_nodes"]:
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} New caller of {db_node}",
            "description": (
                f"Tier 1 topology anomaly{env_label}. Fires when any service "
                f"sends spans to {db_node}. Use the sf_initiating_service "
                f"dimension to identify callers and compare against your "
                f"known baseline set."
            ),
            "programText": program_new_db_caller(db_node, env),
            "rules": [{
                "severity":    "Critical",
                "detectLabel": f"New caller of {db_node} detected",
                "name":        f"New {db_node} caller",
                "description": (
                    f"A service is calling {db_node}. Verify it is an expected "
                    f"caller — unexpected DB access may indicate topology drift "
                    f"or unauthorized data access."
                ),
            }],
            "tags": [MANAGED_TAG, "topology-anomaly", "tier1", env_tag,
                     f"db-{db_node.replace(':', '-').replace(' ', '-')}",
                     f"provisioned-{ts}"],
        })

    # ── Tier 1b: one detector per ingress service ─────────────────────────────
    for svc in topo["ingress_nodes"]:
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} {svc} edge call volume spike",
            "description": (
                f"Tier 1 topology anomaly{env_label}. Fires when {svc}'s "
                f"5-minute call volume on any operation exceeds 10x the same "
                f"5-minute window from 1 week ago. Seasonality-aware: accounts "
                f"for time-of-day and day-of-week traffic patterns."
            ),
            "programText": program_ingress_volume_spike(svc, env),
            "rules": [{
                "severity":    "Major",
                "detectLabel": f"{svc} edge volume spike (>10x same window last week)",
                "name":        f"{svc} volume spike",
                "description": (
                    f"Outbound call volume from {svc} has exceeded 10x the "
                    f"same window from last week. Investigate for routing "
                    f"loops, retry storms, or unexpected fan-out."
                ),
            }],
            "tags": [MANAGED_TAG, "topology-anomaly", "tier1", env_tag,
                     f"svc-{svc}", f"provisioned-{ts}"],
        })

    # ── Tier 1c: one detector per (db_caller, db_node) pair ──────────────────
    for db_node in topo["db_nodes"]:
        for caller in topo["db_callers"]:
            detectors.append({
                "name": f"[Behavioral Baseline]{env_label} {caller} stopped calling {db_node}",
                "description": (
                    f"Tier 1 topology anomaly{env_label}. Fires when {caller} "
                    f"goes silent — its span count to {db_node} drops to zero "
                    f"over a 30-minute window after being non-zero in the prior "
                    f"6 hours. May indicate a circuit breaker opening, service "
                    f"removal, or DB connection failure."
                ),
                "programText": program_missing_db_caller(db_node, caller, env),
                "rules": [{
                    "severity":    "Major",
                    "detectLabel": f"{caller} stopped calling {db_node}",
                    "name":        f"{caller} missing edge to {db_node}",
                    "description": (
                        f"{caller} has stopped sending spans to {db_node}. "
                        f"Verify the service is healthy and its DB connection "
                        f"is intact. This may indicate a silent failure."
                    ),
                }],
                "tags": [MANAGED_TAG, "topology-anomaly", "tier1", "missing-edge",
                         env_tag,
                         f"db-{db_node.replace(':', '-').replace(' ', '-')}",
                         f"svc-{caller}", f"provisioned-{ts}"],
            })

    # ── Tier 3: one detector across all DB-calling services ───────────────────
    if topo["db_callers"]:
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} DB service error rate spike",
            "description": (
                f"Tier 3 error signature anomaly{env_label}. Fires when the "
                f"error span rate for any DB-calling service "
                f"({', '.join(topo['db_callers'])}) exceeds 3x its 1-hour "
                f"rolling mean, sustained for 5 minutes."
            ),
            "programText": program_error_rate_spike(topo["db_callers"], env),
            "rules": [{
                "severity":    "Major",
                "detectLabel": "DB service error rate spike (>3x hourly mean)",
                "name":        "DB service error rate spike",
                "description": (
                    "Error span rate has exceeded 3x the 1-hour rolling mean. "
                    "Investigate for new error signatures, failed queries, or "
                    "dependency changes."
                ),
            }],
            "tags": [MANAGED_TAG, "error-signature", "tier3", env_tag,
                     f"provisioned-{ts}"],
        })

    # ── Tier 4: one detector across all DB-calling services ───────────────────
    if topo["db_callers"]:
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} DB service p99 latency drift",
            "description": (
                f"Tier 4 latency drift anomaly{env_label}. Fires when p99 "
                f"latency for any DB-calling service "
                f"({', '.join(topo['db_callers'])}) exceeds 2x the same "
                f"15-minute window from 1 week ago, sustained for 15 minutes. "
                f"Seasonality-aware: accounts for legitimate latency variation "
                f"by time-of-day and day-of-week."
            ),
            "programText": program_p99_latency_drift(topo["db_callers"], env),
            "rules": [{
                "severity":    "Warning",
                "detectLabel": "DB service p99 latency drift (>2x same window last week)",
                "name":        "DB service p99 latency drift",
                "description": (
                    "p99 latency has sustained >2x the same window from last "
                    "week. Investigate for slow new dependencies, added "
                    "execution path hops, or query regressions."
                ),
            }],
            "tags": [MANAGED_TAG, "latency-drift", "tier4", env_tag,
                     f"provisioned-{ts}"],
        })

    return detectors


# ── Provisioning ───────────────────────────────────────────────────────────────

def create_detector(spec: dict, dry_run: bool = False) -> dict | None:
    """Create a single detector. Returns the API response or None on dry run."""
    if dry_run:
        print(f"  [dry-run] Would create: {spec['name']}")
        print(f"            Tags: {spec['tags']}")
        print(f"            Program preview:")
        for line in spec["programText"].splitlines():
            print(f"              {line}")
        return None

    result = _request("POST", "/v2/detector", spec)
    print(f"  [created] {spec['name']}")
    print(f"            ID: {result.get('id')}  Status: {result.get('status')}")
    return result


def teardown_managed_detectors(environment: str | None = None,
                               dry_run: bool = False) -> None:
    """
    Delete all detectors tagged with MANAGED_TAG.
    If environment is given, only delete detectors also tagged env-{environment}.
    """
    tag = f"env-{environment}" if environment else MANAGED_TAG
    label = f"environment '{environment}'" if environment else "all environments"
    print(f"[teardown] Finding detectors for {label} (tag: {tag})...")
    result = _request("GET", f"/v2/detector?tags={tag}&limit=200")
    detectors = result.get("results", [])
    # When filtering by env tag, also ensure MANAGED_TAG is present
    if environment:
        detectors = [d for d in detectors if MANAGED_TAG in d.get("tags", [])]
    if not detectors:
        print("  No managed detectors found.")
        return
    print(f"  Found {len(detectors)} detector(s) to remove:")
    for d in detectors:
        print(f"    {d['id']}  {d['name']}")
        if not dry_run:
            _request("DELETE", f"/v2/detector/{d['id']}")
            print(f"    Deleted.")
        else:
            print(f"    [dry-run] Would delete.")


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Auto-provision behavioral baseline detectors for any "
                    "Splunk Observability APM environment"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be created without making API calls",
    )
    parser.add_argument(
        "--teardown", action="store_true",
        help=f"Delete detectors tagged '{MANAGED_TAG}' (scoped by --environment if given)",
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help=(
            "APM environment (deployment.environment) to scope detectors to. "
            "Maps to sf_environment in SignalFlow. "
            "Omit to cover all environments."
        ),
    )
    args = parser.parse_args()

    if args.teardown:
        teardown_managed_detectors(environment=args.environment,
                                   dry_run=args.dry_run)
        return

    env_desc = f"environment '{args.environment}'" if args.environment else "all environments"
    print(f"[provision] Discovering APM topology for {env_desc}...")
    topo = discover_topology(environment=args.environment)
    print(f"  Services:      {sorted(topo['services'])}")
    print(f"  DB nodes:      {sorted(topo['db_nodes'])}")
    print(f"  Ingress nodes: {sorted(topo['ingress_nodes'])}")
    print(f"  DB callers:    {sorted(topo['db_callers'])}")
    print(f"  Missing-edge pairs: "
          f"{[(c, d) for d in topo['db_nodes'] for c in topo['db_callers']]}")

    if not topo["services"]:
        print(f"\n  No services found for {env_desc}. "
              "Ensure APM is instrumented and sending traces.", file=sys.stderr)
        sys.exit(1)

    plan = build_detector_plan(topo)
    print(f"\n  Detector plan: {len(plan)} detector(s) to create")
    for d in plan:
        tier = next((t for t in d["tags"] if t.startswith("tier")), "?")
        print(f"    [{tier}] {d['name']}")

    if args.dry_run:
        print("\n[provision] Dry run — printing programs:\n")
    else:
        print("\n[provision] Creating detectors...\n")

    created_ids = []
    for spec in plan:
        result = create_detector(spec, dry_run=args.dry_run)
        if result and result.get("id"):
            created_ids.append(result["id"])

    if args.dry_run:
        print(f"\n  Dry run complete. {len(plan)} detector(s) would be created.")
        print(f"  Run without --dry-run to provision.")
    else:
        print(f"\n  Provisioned {len(created_ids)} / {len(plan)} detector(s).")
        if created_ids:
            print(f"  IDs: {created_ids}")
            teardown_cmd = "python provision_detectors.py --teardown"
            if args.environment:
                teardown_cmd += f" --environment {args.environment}"
            print(f"\n  To remove these detectors later:")
            print(f"    {teardown_cmd}")


if __name__ == "__main__":
    main()
