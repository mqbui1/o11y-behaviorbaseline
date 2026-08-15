#!/usr/bin/env python3
"""Injects real /v2/event anomaly events into a live Splunk Observability Cloud org.

Unlike the topology_server.py "demo scenario" buttons (which only broadcast to the
standalone local SSE topology UI), this script POSTs real events matching the schema
emitted by otel-processor/fingerprintprocessor/emitter.go, so they can be picked up by
olly app-apm's useBehavioralSignals hook (apps/app-apm/src/hooks/use-behavioral-signals/)
and rendered on the real Troubleshooting Service Graph.

Payloads are derived from topology_server.py's _DEMO_SCENARIOS_OTEL (astronomy-shop
service names: cart, checkout, valkey-cart, product-catalog, frontend, payment).

Usage:
    python3 inject_real_events.py --list
    python3 inject_real_events.py kill-service
    python3 inject_real_events.py db-incident --delay-ms 800

Reads SPLUNK_INGEST_TOKEN / SPLUNK_REALM / SPLUNK_ENVIRONMENT from environment variables,
falling back to autonomous-o11y-agent/deploy/.env if not set.
"""
import argparse
import os
import sys
import time
import json
from pathlib import Path

import requests

DEPLOY_ENV_PATH = Path.home() / "Documents" / "autonomous-o11y-agent" / "deploy" / ".env"


def _load_deploy_env(path: Path) -> dict:
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values[key.strip()] = val.strip()
    return values


def root_service(root_op: str) -> str:
    return root_op.split(":", 1)[0] if ":" in root_op else root_op


# Each entry: (anomaly_type, event_dict) -> pairs from topology_server.py's
# _DEMO_SCENARIOS_OTEL, trimmed to the fields actually used below.
SCENARIOS: dict[str, list[dict]] = {
    "kill-service": [
        {"anomaly_type": "MISSING_SERVICE", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "missing_services": ["checkout"],
         "hash": "synthetic:missing:checkout"},
    ],
    "new-call-path": [
        {"anomaly_type": "NEW_FINGERPRINT", "service": "product-catalog",
         "root_op": "load-generator:user_browse_product",
         "hash": "synthetic:fp:productcatalog-new-edge"},
        {"anomaly_type": "NEW_TOPOLOGY_EDGE", "caller": "product-catalog", "callee": "recommendation"},
    ],
    "new-error": [
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "product-catalog",
         "root_op": "load-generator:user_browse_product", "error_type": "DataAccessException",
         "operation": "GET /hipstershop.ProductCatalogService/GetProduct",
         "hash": "synthetic:err:productcatalog-DataAccessException"},
    ],
    "db-incident": [
        {"anomaly_type": "MISSING_SERVICE", "service": "valkey-cart",
         "root_op": "load-generator:user_add_to_cart", "missing_services": ["valkey-cart"],
         "hash": "synthetic:missing:valkey-cart"},
        {"anomaly_type": "MISSING_SERVICE", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "missing_services": ["valkey-cart"],
         "hash": "synthetic:missing:valkey-cart-caller"},
        {"anomaly_type": "MISSING_SERVICE", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "missing_services": ["valkey-cart"],
         "hash": "synthetic:missing:valkey-cart-checkout-caller"},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "error_type": "RedisConnectionException",
         "operation": "AddItem", "hash": "synthetic:err:cart-redis"},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "error_type": "RedisConnectionException",
         "operation": "PlaceOrder", "hash": "synthetic:err:checkout-redis"},
    ],
    "cascading": [
        {"anomaly_type": "MISSING_SERVICE", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "missing_services": ["checkout"],
         "hash": "synthetic:missing:checkout-cascade", "_delay_ms": 0},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "frontend",
         "root_op": "frontend-proxy:ingress", "error_type": "ServiceUnavailableException",
         "operation": "POST /api/checkout", "hash": "synthetic:err:frontend-checkout", "_delay_ms": 2000},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "error_type": "TimeoutException",
         "operation": "AddItem", "hash": "synthetic:err:cart-timeout", "_delay_ms": 2000},
    ],
    "latency-spike": [
        {"anomaly_type": "LATENCY_ANOMALY", "service": "product-catalog",
         "root_op": "load-generator:user_browse_product",
         "operation": "GET /hipstershop.ProductCatalogService/GetProduct",
         "current_mean_ms": "892.4", "baseline_mean_ms": "4.2", "z_score": "7340.0",
         "hash": "synthetic:latency:product-catalog"},
    ],
    "error-rate-spike": [
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "payment",
         "root_op": "load-generator:user_checkout_single", "error_type": "PaymentServiceException",
         "operation": "hipstershop.PaymentService/Charge", "hash": "synthetic:err:payment-exception",
         "_delay_ms": 800},
    ],
    "combined-metric": [
        {"anomaly_type": "MISSING_SERVICE", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "missing_services": ["checkout"],
         "hash": "synthetic:missing:checkout-combined", "_delay_ms": 0},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "payment",
         "root_op": "load-generator:user_checkout_single", "error_type": "PaymentServiceException",
         "operation": "hipstershop.PaymentService/Charge", "hash": "synthetic:err:payment-combined",
         "_delay_ms": 800},
    ],
    "slow-db": [
        {"anomaly_type": "LATENCY_ANOMALY", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "operation": "AddItem",
         "current_mean_ms": "3950", "baseline_mean_ms": "32", "z_score": "15.8",
         "hash": "synthetic:latency:cart-slow", "_delay_ms": 0},
        {"anomaly_type": "LATENCY_ANOMALY", "service": "checkout",
         "root_op": "load-generator:user_checkout_single", "operation": "PlaceOrder",
         "current_mean_ms": "4100", "baseline_mean_ms": "45", "z_score": "13.4",
         "hash": "synthetic:latency:checkout-slow", "_delay_ms": 500},
        {"anomaly_type": "LATENCY_ANOMALY", "service": "frontend",
         "root_op": "frontend-proxy:ingress", "operation": "POST /api/checkout",
         "current_mean_ms": "4250", "baseline_mean_ms": "55", "z_score": "11.9",
         "hash": "synthetic:latency:frontend-slow", "_delay_ms": 500},
    ],
    "oom-crash": [
        {"anomaly_type": "LATENCY_ANOMALY", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "operation": "AddItem",
         "current_mean_ms": "3600", "baseline_mean_ms": "32", "z_score": "11.8",
         "hash": "synthetic:latency:cart-oom", "_delay_ms": 0},
        {"anomaly_type": "MISSING_SERVICE", "service": "cart",
         "root_op": "load-generator:user_add_to_cart", "missing_services": ["cart"],
         "hash": "synthetic:missing:cart-oom", "_delay_ms": 4000},
        {"anomaly_type": "NEW_ERROR_SIGNATURE", "service": "frontend",
         "root_op": "frontend-proxy:ingress", "error_type": "ServiceUnavailableException",
         "operation": "POST /api/cart", "hash": "synthetic:err:frontend-cart-oom", "_delay_ms": 1000},
    ],
    # No sf_eventType exists in olly's BEHAVIORAL_SIGNAL_EVENT_TYPES for span-count semantics.
    # "span-count-drop" is approximated via the real service.throughput.drop eventType, which
    # olly maps to spanCountAnomaly='DROP'. "span-count-spike" has no visual counterpart at all
    # (mergeBehavioralSignals.ts only handles the DROP case) and is intentionally NOT injected.
    "span-count-drop": [
        {"anomaly_type": "THROUGHPUT_DROP", "service": "product-catalog",
         "root_op": "load-generator:user_browse_product",
         "current_rate_pm": "8", "baseline_rate_pm": "45",
         "hash": "synthetic:spandrop:product-catalog"},
    ],
}

UNSUPPORTED = {
    "span-count-spike": "No sf_eventType exists for SPAN_COUNT_SPIKE — mergeBehavioralSignals.ts "
                         "has no visual mapping. Skipping; requires an olly code change first.",
    "error-rate-spike-metric": "ERROR_RATE_ANOMALY has no matching sf_eventType in olly's "
                                "BEHAVIORAL_SIGNAL_EVENT_TYPES list — only NEW_ERROR_SIGNATURE renders.",
}


def build_event(env: str, ev: dict) -> dict:
    now_ms = int(time.time() * 1000)
    anomaly_type = ev["anomaly_type"]

    if anomaly_type == "MISSING_SERVICE":
        root_op = ev["root_op"]
        return {
            "eventType": "trace.path.drift",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "anomaly_type": "MISSING_SERVICE",
                "root_operation": root_op,
                "service": root_service(root_op),
            },
            "properties": {
                "root_op": root_op,
                "missing_services": ",".join(ev["missing_services"]),
                "last_seen_sec": "0",
                "detector": "synthetic-injector",
                "environment": env,
            },
            "timestamp": now_ms,
        }
    if anomaly_type == "NEW_FINGERPRINT":
        root_op = ev["root_op"]
        return {
            "eventType": "trace.path.drift",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "anomaly_type": "NEW_FINGERPRINT",
                "root_operation": root_op,
                "service": ev["service"],
                "fp_hash": ev["hash"],
            },
            "properties": {
                "trace_id": "synthetic",
                "root_op": root_op,
                "hash": ev["hash"],
                "detector": "synthetic-injector",
                "environment": env,
            },
            "timestamp": now_ms,
        }
    if anomaly_type == "NEW_ERROR_SIGNATURE":
        return {
            "eventType": "error.signature.drift",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "anomaly_type": "NEW_ERROR_SIGNATURE",
                "service": ev["service"],
                "error_type": ev["error_type"],
                "sig_hash": ev["hash"],
            },
            "properties": {
                "trace_id": "synthetic",
                "service": ev["service"],
                "error_type": ev["error_type"],
                "operation": ev["operation"],
                "hash": ev["hash"],
                "detector": "synthetic-injector",
                "environment": env,
            },
            "timestamp": now_ms,
        }
    if anomaly_type == "LATENCY_ANOMALY":
        return {
            "eventType": "service.latency.anomaly",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "sf_service": ev["service"],
                "sf_operation": ev["operation"],
                "anomaly_type": "LATENCY_ANOMALY",
            },
            "properties": {
                "service": ev["service"],
                "operation": ev["operation"],
                "environment": env,
                "current_mean_ms": ev["current_mean_ms"],
                "baseline_mean_ms": ev["baseline_mean_ms"],
                "z_score": ev["z_score"],
                "detector": "synthetic-injector",
            },
            "timestamp": now_ms,
        }
    if anomaly_type == "THROUGHPUT_DROP":
        root_op = ev["root_op"]
        return {
            "eventType": "service.throughput.drop",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "anomaly_type": "THROUGHPUT_DROP",
                "service": ev["service"],
                "root_operation": root_op,
            },
            "properties": {
                "root_op": root_op,
                "service": ev["service"],
                "environment": env,
                "current_rate_pm": ev["current_rate_pm"],
                "baseline_rate_pm": ev["baseline_rate_pm"],
                "detector": "synthetic-injector",
            },
            "timestamp": now_ms,
        }
    if anomaly_type == "NEW_TOPOLOGY_EDGE":
        return {
            "eventType": "topology.edge.drift",
            "category": "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "anomaly_type": "NEW_TOPOLOGY_EDGE",
                "caller": ev["caller"],
                "callee": ev["callee"],
            },
            "properties": {
                "caller": ev["caller"],
                "callee": ev["callee"],
                "environment": env,
                "detector": "synthetic-injector",
            },
            "timestamp": now_ms,
        }
    raise ValueError(f"Unhandled anomaly_type: {anomaly_type}")


def send(ingest_url: str, token: str, event: dict) -> None:
    resp = requests.post(
        f"{ingest_url}/v2/event",
        headers={"Content-Type": "application/json", "X-SF-Token": token},
        data=json.dumps([event]),
        timeout=15,
    )
    resp.raise_for_status()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="?", help="Scenario name (see --list)")
    parser.add_argument("--list", action="store_true", help="List available scenarios and exit")
    parser.add_argument("--delay-ms", type=int, default=800,
                         help="Default delay between events lacking an explicit _delay_ms")
    parser.add_argument("--environment", default=None, help="Override SPLUNK_ENVIRONMENT")
    args = parser.parse_args()

    if args.list:
        print("Available scenarios:")
        for name in SCENARIOS:
            print(f"  {name}")
        for name, reason in UNSUPPORTED.items():
            print(f"  {name}  [NOT INJECTED: {reason}]")
        return 0

    if not args.scenario:
        parser.error("scenario is required (or pass --list)")

    if args.scenario in UNSUPPORTED:
        print(f"Skipping '{args.scenario}': {UNSUPPORTED[args.scenario]}", file=sys.stderr)
        return 1

    if args.scenario not in SCENARIOS:
        parser.error(f"Unknown scenario '{args.scenario}'. Use --list to see options.")

    deploy_env = _load_deploy_env(DEPLOY_ENV_PATH)
    token = os.environ.get("SPLUNK_INGEST_TOKEN") or deploy_env.get("SPLUNK_INGEST_TOKEN")
    realm = os.environ.get("SPLUNK_REALM") or deploy_env.get("SPLUNK_REALM", "us1")
    environment = args.environment or os.environ.get("SPLUNK_ENVIRONMENT") or deploy_env.get(
        "SPLUNK_ENVIRONMENT", "astroshop-local"
    )
    if not token:
        print("Missing SPLUNK_INGEST_TOKEN (env var or autonomous-o11y-agent/deploy/.env)", file=sys.stderr)
        return 1

    ingest_url = f"https://ingest.{realm}.signalfx.com"

    events = SCENARIOS[args.scenario]
    print(f"Injecting scenario '{args.scenario}' into environment='{environment}' realm={realm}")
    for ev in events:
        wait_ms = ev.get("_delay_ms", args.delay_ms if len(events) > 1 else 0)
        if wait_ms:
            time.sleep(wait_ms / 1000)
        payload = build_event(environment, ev)
        send(ingest_url, token, payload)
        print(f"  sent {payload['eventType']} anomaly_type={ev['anomaly_type']} service={ev.get('service', ev.get('caller'))}")

    print("Done. Open olly app-apm Troubleshooting -> Service Graph, environment "
          f"'{environment}', and refresh to see the change.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
