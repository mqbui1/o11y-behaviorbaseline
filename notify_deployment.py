#!/usr/bin/env python3
"""
Behavioral Baseline — Deployment Event Notifier
================================================
Emits a `deployment.started` custom event to Splunk Observability so that
the correlation engine can annotate anomaly alerts with deployment context.

Call this from your CI/CD pipeline immediately before (or after) deploying:

  # Minimal — service name only
  python notify_deployment.py --service api-gateway --environment production

  # Full context
  python notify_deployment.py \\
      --service api-gateway \\
      --environment production \\
      --version v2.4.1 \\
      --deployer github-actions \\
      --commit abc123def \\
      --description "Add new payment service integration"

  # Multiple services in one deployment
  python notify_deployment.py \\
      --service api-gateway customers-service \\
      --environment production \\
      --version v2.4.1

When correlate.py runs within DEPLOYMENT_CORRELATION_WINDOW_MINUTES of a
deployment event on the same service+environment, it downgrades the alert
severity and annotates the correlated anomaly with deployment context.

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
from datetime import datetime, timezone
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.",
          file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

# ── HTTP helper ────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url     = f"{base_url}{path}"
    headers = {"X-SF-Token": ACCESS_TOKEN, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
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


# ── Event emission ─────────────────────────────────────────────────────────────

def notify(
    services: list[str],
    environment: str | None,
    version: str | None,
    deployer: str | None,
    commit: str | None,
    description: str | None,
    dry_run: bool = False,
) -> None:
    now_ms  = int(time.time() * 1000)
    now_iso = datetime.now(timezone.utc).isoformat()
    env_label = environment or "all"

    for service in services:
        body = {
            "eventType": "deployment.started",
            "category":  "USER_DEFINED",
            "dimensions": {
                "service":     service,
                "environment": env_label,
            },
            "properties": {
                "message":     (
                    f"Deployment of {service} started"
                    + (f" ({version})" if version else "")
                    + (f" in {environment}" if environment else "")
                ),
                "service":     service,
                "environment": env_label,
                "version":     version     or "",
                "deployer":    deployer    or "",
                "commit":      commit      or "",
                "description": description or "",
                "timestamp":   now_iso,
            },
            "timestamp": now_ms,
        }

        if dry_run:
            print(f"  [dry-run] Would emit deployment.started for {service} "
                  f"({env_label})")
            print(f"    version={version or 'n/a'}  deployer={deployer or 'n/a'}  "
                  f"commit={commit or 'n/a'}")
        else:
            _request("POST", "/v2/event", body, base_url=INGEST_URL)
            print(f"  [sent] deployment.started  service={service}  "
                  f"environment={env_label}  version={version or 'n/a'}")


# ── CLI ────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Emit deployment.started events to Splunk Observability "
                    "for deployment-aware anomaly correlation"
    )
    parser.add_argument(
        "--service", nargs="+", required=True,
        help="Service name(s) being deployed",
    )
    parser.add_argument(
        "--environment", type=str, default=None,
        help="APM environment (deployment.environment / sf_environment)",
    )
    parser.add_argument(
        "--version", type=str, default=None,
        help="Version, tag, or image digest being deployed",
    )
    parser.add_argument(
        "--deployer", type=str, default=None,
        help="Who/what triggered the deployment (e.g. 'github-actions', 'jenkins')",
    )
    parser.add_argument(
        "--commit", type=str, default=None,
        help="Git commit SHA associated with this deployment",
    )
    parser.add_argument(
        "--description", type=str, default=None,
        help="Short human-readable description of what changed",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would be sent without making API calls",
    )
    args = parser.parse_args()

    notify(
        services=args.service,
        environment=args.environment,
        version=args.version,
        deployer=args.deployer,
        commit=args.commit,
        description=args.description,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
