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
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ── Config ─────────────────────────────────────────────────────────────────────

ACCESS_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN  = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM        = os.environ.get("SPLUNK_REALM", "us0")

if not ACCESS_TOKEN:
    print("Error: SPLUNK_ACCESS_TOKEN environment variable is required.",
          file=sys.stderr)
    sys.exit(1)

BASE_URL   = f"https://api.{REALM}.signalfx.com"
INGEST_URL = f"https://ingest.{REALM}.signalfx.com"

SCRIPT_DIR = Path(__file__).parent

# How long to wait after a deployment before re-learning the baseline.
# Should be long enough for new-version traces to start flowing.
RELEARN_DELAY_MINUTES = int(os.environ.get("RELEARN_DELAY_MINUTES", "5"))

# ── HTTP helper ────────────────────────────────────────────────────────────────

def _request(method: str, path: str, body: dict | None = None,
             base_url: str = BASE_URL) -> Any:
    url     = f"{base_url}{path}"
    token   = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
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


# ── Post-deploy re-learn ───────────────────────────────────────────────────────

def trigger_relearn(environment: str | None, delay_minutes: int = RELEARN_DELAY_MINUTES,
                    dry_run: bool = False) -> None:
    """
    Spawn a detached background process that waits `delay_minutes` then runs
    trace_fingerprint.py learn and error_fingerprint.py learn for the environment.
    Returns immediately — the CD pipeline is not blocked.
    """
    env_args = ["--environment", environment] if environment else []
    delay_s  = delay_minutes * 60
    learn_args = " ".join(env_args + ["learn", "--window-minutes", "30"])

    # Build a shell one-liner: sleep, then run both learns sequentially
    cmd = (
        f"sleep {delay_s} && "
        f"{sys.executable} {SCRIPT_DIR}/trace_fingerprint.py {learn_args} "
        f">> /tmp/bab_relearn_deploy.log 2>&1 && "
        f"{sys.executable} {SCRIPT_DIR}/error_fingerprint.py {learn_args} "
        f">> /tmp/bab_relearn_deploy.log 2>&1"
    )

    env_label = environment or "all"
    if dry_run:
        print(f"  [dry-run] Would trigger re-learn for '{env_label}' "
              f"in {delay_minutes}m")
        return

    # start_new_session=True detaches from the parent process group so it
    # survives even if the CI job exits immediately after this script returns.
    subprocess.Popen(
        cmd, shell=True, start_new_session=True,
        env={**os.environ},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    print(f"  [scheduled] baseline re-learn for '{env_label}' "
          f"in {delay_minutes}m (background)")


# ── Event emission ─────────────────────────────────────────────────────────────

def notify(
    services: list[str],
    environment: str | None,
    version: str | None,
    deployer: str | None,
    commit: str | None,
    description: str | None,
    relearn_delay: int = RELEARN_DELAY_MINUTES,
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
            _request("POST", "/v2/event", [body], base_url=INGEST_URL)
            print(f"  [sent] deployment.started  service={service}  "
                  f"environment={env_label}  version={version or 'n/a'}")

    # Schedule a baseline re-learn once per environment (not per service)
    trigger_relearn(environment, delay_minutes=relearn_delay, dry_run=dry_run)


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
        "--relearn-delay", type=int, default=RELEARN_DELAY_MINUTES,
        help=f"Minutes to wait after deploy before re-learning baseline "
             f"(default: {RELEARN_DELAY_MINUTES}, set 0 to disable)",
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
        relearn_delay=args.relearn_delay,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
