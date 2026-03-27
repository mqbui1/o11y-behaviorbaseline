#!/usr/bin/env python3
"""
Behavioral Baseline Detector Provisioner
=========================================
Auto-discovers your APM topology from Splunk Observability and provisions
APM AutoDetect customization detectors (Tiers 3, 4) plus request rate
detectors for any onboarded application.

Uses Splunk's native APM AutoDetect detector library (signalfx.detectors.autodetect.apm)
which operates on the APM analytics path — no dependency on spans.count MTS
or APM MetricSets being configured.

What gets created:
  Tier 3  — Error rate spike per service         [Critical] (AutoDetectCustomization)
  Tier 4  — Latency drift per service            [Critical] (AutoDetectCustomization)
  Tier 1b — Request rate spike per ingress svc   [Critical] (AutoDetectCustomization)

Topology drift (new/missing DB callers) is handled by trace_fingerprint.py
since it requires trace-level analysis that SignalFlow cannot provide.

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
from concurrent.futures import ThreadPoolExecutor, as_completed
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


# ── AutoDetect parent detector IDs ─────────────────────────────────────────────
# These are the org-wide AutoDetect detectors created by Splunk.
# We create AutoDetectCustomization children scoped to specific services/envs.

AUTODETECT_ERROR_RATE_ID    = "GmlOPziA4AA"
AUTODETECT_LATENCY_ID       = "GmlOOWLAwAA"
AUTODETECT_REQUEST_RATE_ID  = "GmlOP2iA4AI"


# ── SignalFlow program builders ────────────────────────────────────────────────
# These use the signalfx.detectors.autodetect.apm library — same path as the
# built-in AutoDetect detectors. The filter_ kwarg accepts a SignalFlow filter
# expression to scope to a specific service and/or environment.

def _filter_expr(service: str, environment: str | None) -> str:
    """Build a SignalFlow filter() expression for service + environment."""
    parts = [f"filter('sf_service', '{service}')"]
    if environment:
        parts.append(f"filter('sf_environment', '{environment}')")
    return " and ".join(parts)


def program_error_rate(service: str, environment: str | None = None) -> tuple[str, str]:
    """
    Tier 3: Error rate sudden change detector scoped to a single service.
    Returns (programText, detectLabel).
    Uses APM autodetect library — no spans.count dependency.
    """
    label = f"[Behavioral Baseline] {service} error rate spike"
    filt  = _filter_expr(service, environment)
    program = (
        f"from signalfx.detectors.autodetect.apm import errors\n"
        f"errors.error_rate_sudden_change_detector("
        f"filter_={filt}"
        f").publish('{label}')"
    )
    return program, label


def program_latency(service: str, environment: str | None = None) -> tuple[str, str]:
    """
    Tier 4: Latency deviation from norm detector scoped to a single service.
    Returns (programText, detectLabel).
    Uses APM autodetect library — no spans.count dependency.
    """
    label = f"[Behavioral Baseline] {service} latency drift"
    filt  = _filter_expr(service, environment)
    program = (
        f"from signalfx.detectors.autodetect.apm import latency\n"
        f"latency.latency_deviations_from_norm_detector("
        f"filter_={filt}"
        f").publish('{label}')"
    )
    return program, label


def program_request_rate(service: str, environment: str | None = None) -> tuple[str, str]:
    """
    Tier 1b: Request rate sudden change detector scoped to a single ingress service.
    Returns (programText, detectLabel).
    Uses APM autodetect library — no spans.count dependency.
    """
    label = f"[Behavioral Baseline] {service} request rate spike"
    filt  = _filter_expr(service, environment)
    program = (
        f"from signalfx.detectors.autodetect.apm import requests\n"
        f"requests.request_rate_mean_std_detector("
        f"filter_={filt}"
        f").publish('{label}')"
    )
    return program, label


# ── Detector plan builder ──────────────────────────────────────────────────────

def build_detector_plan(topo: dict) -> list[dict]:
    """
    Given a topology dict (which includes topo["environment"]), return a list
    of AutoDetectCustomization detector specs to create. One error rate + one
    latency detector per service, plus one request rate detector per ingress
    service. All use the APM autodetect library path.
    """
    detectors = []
    env       = topo.get("environment")
    env_label = f" [{env}]" if env else ""
    env_tag   = f"env-{env}" if env else "env-all"
    ts        = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    all_services = sorted(set(topo["services"]))

    # ── Tier 3: error rate detector per service ───────────────────────────────
    for svc in all_services:
        program, label = program_error_rate(svc, env)
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} {svc} error rate spike",
            "description": (
                f"Tier 3 error anomaly{env_label}. Fires when {svc} error rate "
                f"suddenly increases. Uses APM autodetect analytics path."
            ),
            "programText": program,
            "detectorOrigin": "AutoDetectCustomization",
            "parentDetectorId": AUTODETECT_ERROR_RATE_ID,
            "rules": [{
                "severity":    "Critical",
                "detectLabel": label,
                "description": (
                    f"Error rate in {svc} has suddenly grown. Investigate for "
                    f"new error signatures, failed queries, or dependency changes."
                ),
            }],
            "tags": [MANAGED_TAG, "error-rate", "tier3", env_tag,
                     f"svc-{svc}", f"provisioned-{ts}"],
        })

    # ── Tier 4: latency detector per service ─────────────────────────────────
    for svc in all_services:
        program, label = program_latency(svc, env)
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} {svc} latency drift",
            "description": (
                f"Tier 4 latency anomaly{env_label}. Fires when {svc} latency "
                f"deviates from its norm. Uses APM autodetect analytics path."
            ),
            "programText": program,
            "detectorOrigin": "AutoDetectCustomization",
            "parentDetectorId": AUTODETECT_LATENCY_ID,
            "rules": [{
                "severity":    "Critical",
                "detectLabel": label,
                "description": (
                    f"Latency in {svc} has deviated from its historical norm. "
                    f"Investigate for slow dependencies or query regressions."
                ),
            }],
            "tags": [MANAGED_TAG, "latency-drift", "tier4", env_tag,
                     f"svc-{svc}", f"provisioned-{ts}"],
        })

    # ── Tier 1b: request rate detector per ingress service ────────────────────
    for svc in sorted(topo["ingress_nodes"]):
        program, label = program_request_rate(svc, env)
        detectors.append({
            "name": f"[Behavioral Baseline]{env_label} {svc} request rate spike",
            "description": (
                f"Tier 1b volume anomaly{env_label}. Fires when {svc} request "
                f"rate suddenly changes. Uses APM autodetect analytics path."
            ),
            "programText": program,
            "detectorOrigin": "AutoDetectCustomization",
            "parentDetectorId": AUTODETECT_REQUEST_RATE_ID,
            "rules": [{
                "severity":    "Critical",
                "detectLabel": label,
                "description": (
                    f"Request rate on {svc} has suddenly changed. Investigate "
                    f"for routing loops, retry storms, or traffic anomalies."
                ),
            }],
            "tags": [MANAGED_TAG, "request-rate", "tier1b", env_tag,
                     f"svc-{svc}", f"provisioned-{ts}"],
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
        if dry_run:
            print(f"    [dry-run] Would delete.")

    if not dry_run:
        with ThreadPoolExecutor(max_workers=min(len(detectors), 10)) as pool:
            futures = {pool.submit(_request, "DELETE",
                                   f"/v2/detector/{d['id']}"): d for d in detectors}
            for future in as_completed(futures):
                d = futures[future]
                try:
                    future.result()
                    print(f"    Deleted: {d['id']}")
                except Exception as e:
                    print(f"    [error] deleting {d['id']}: {e}", file=sys.stderr)


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
    if args.dry_run:
        for spec in plan:
            create_detector(spec, dry_run=True)
    else:
        with ThreadPoolExecutor(max_workers=min(len(plan), 10)) as pool:
            futures = {pool.submit(create_detector, spec): spec for spec in plan}
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result and result.get("id"):
                        created_ids.append(result["id"])
                except Exception as e:
                    spec = futures[future]
                    print(f"  [error] {spec['name']}: {e}", file=sys.stderr)

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
