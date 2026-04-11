#!/usr/bin/env python3
"""
baseline-sync-sidecar.py — Watches Splunk for trace.fingerprint.promoted events
and patches the behavioral-baseline ConfigMap so all DaemonSet pods reload it.

Runs as a sidecar container alongside each otelcol-fingerprint pod. Only one
instance will win the ConfigMap patch race per event (idempotent — patching
with the same JSON twice is harmless). All instances eventually converge on
the same ConfigMap content because they all read the same promoted baseline
files from the shared emptyDir volume.

Flow:
  1. Poll Splunk SignalFlow every POLL_INTERVAL seconds for new
     trace.fingerprint.promoted events in the last LOOKBACK_SECONDS window
  2. On any promotion event, read /baseline/baseline.json and
     /baseline/error_baseline.json from the shared emptyDir volume
  3. Patch the behavioral-baseline ConfigMap with kubectl
  4. Log the patch — other pods pick up the change within baseline_reload_interval

Required env vars (same secret as the collector):
  SPLUNK_ACCESS_TOKEN   — API token for SignalFlow
  SPLUNK_REALM          — e.g. us1
  WORKSHOP_ENVIRONMENT  — environment filter for events

Optional env vars:
  POLL_INTERVAL         — seconds between SignalFlow polls (default: 30)
  LOOKBACK_SECONDS      — how far back to query for events (default: 120)
  BASELINE_PATH         — path to trace baseline JSON (default: /baseline/baseline.json)
  ERROR_BASELINE_PATH   — path to error baseline JSON (default: /baseline/error_baseline.json)
  CONFIGMAP_NAME        — ConfigMap to patch (default: behavioral-baseline)
  CONFIGMAP_NAMESPACE   — namespace (default: default)
  DRY_RUN               — set to "true" to log without patching (default: false)
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

SPLUNK_TOKEN  = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
REALM         = os.environ.get("SPLUNK_REALM", "us1")
ENVIRONMENT   = os.environ.get("WORKSHOP_ENVIRONMENT", "")
STREAM_URL    = f"https://stream.{REALM}.signalfx.com"

POLL_INTERVAL       = int(os.environ.get("POLL_INTERVAL", "30"))
LOOKBACK_SECONDS    = int(os.environ.get("LOOKBACK_SECONDS", "120"))
BASELINE_PATH       = os.environ.get("BASELINE_PATH", "/baseline/baseline.json")
ERROR_BASELINE_PATH = os.environ.get("ERROR_BASELINE_PATH", "/baseline/error_baseline.json")
CONFIGMAP_NAME      = os.environ.get("CONFIGMAP_NAME", "behavioral-baseline")
CONFIGMAP_NS        = os.environ.get("CONFIGMAP_NAMESPACE", "default")
DRY_RUN             = os.environ.get("DRY_RUN", "false").lower() == "true"

if not SPLUNK_TOKEN:
    print("ERROR: SPLUNK_ACCESS_TOKEN is required", flush=True)
    sys.exit(1)


def _signalflow_events(event_type: str, start_ms: int, end_ms: int) -> list[dict]:
    program = f'events(eventType="{event_type}").publish()'
    url = (f"{STREAM_URL}/v2/signalflow/execute"
           f"?start={start_ms}&stop={end_ms}&immediate=true")
    req = urllib.request.Request(
        url,
        data=program.encode(),
        headers={"X-SF-Token": SPLUNK_TOKEN, "Content-Type": "text/plain"},
        method="POST",
    )
    results = []
    try:
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            data_lines: list[str] = []
            for raw_line in resp:
                line = raw_line.decode()
                stripped = line.strip()
                if stripped.startswith("data:"):
                    data_lines.append(stripped[5:].strip())
                elif stripped == "" and data_lines:
                    payload = "".join(data_lines)
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
        print(f"[warn] SignalFlow query error: {e}", flush=True)
    return results


def has_promotion_events(start_ms: int, end_ms: int) -> bool:
    """Return True if any trace.fingerprint.promoted events exist in the window."""
    events = _signalflow_events("trace.fingerprint.promoted", start_ms, end_ms)
    if not events:
        return False
    # Filter to our environment if set
    if not ENVIRONMENT:
        return True
    for msg in events:
        dims  = msg.get("metadata", {})
        props = msg.get("properties", {})
        env   = dims.get("sf_environment") or props.get("environment", "")
        if not env or env == ENVIRONMENT:
            return True
    return False


def patch_configmap() -> bool:
    """
    Read current baseline files from disk and patch the ConfigMap.
    Returns True on success.
    """
    try:
        with open(BASELINE_PATH) as f:
            baseline_json = f.read()
    except Exception as e:
        print(f"[warn] Could not read {BASELINE_PATH}: {e}", flush=True)
        return False

    try:
        with open(ERROR_BASELINE_PATH) as f:
            error_baseline_json = f.read()
    except Exception as e:
        print(f"[warn] Could not read {ERROR_BASELINE_PATH}: {e}", flush=True)
        error_baseline_json = '{"signatures":{}}'

    # Validate both files are valid JSON before pushing
    try:
        json.loads(baseline_json)
        json.loads(error_baseline_json)
    except json.JSONDecodeError as e:
        print(f"[warn] Baseline file is not valid JSON, skipping patch: {e}", flush=True)
        return False

    fingerprint_count = len(json.loads(baseline_json).get("fingerprints", {}))
    sig_count = len(json.loads(error_baseline_json).get("signatures", {}))

    if DRY_RUN:
        print(f"[dry-run] Would patch ConfigMap {CONFIGMAP_NAME}: "
              f"{fingerprint_count} trace fingerprints, {sig_count} error signatures",
              flush=True)
        return True

    # Patch the ConfigMap directly via the Kubernetes API using the in-cluster
    # service account token — no kubectl binary required.
    try:
        token = open("/var/run/secrets/kubernetes.io/serviceaccount/token").read()
        ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    except Exception as e:
        print(f"[error] Could not read service account credentials: {e}", flush=True)
        return False

    patch = {
        "data": {
            "baseline.json":       baseline_json,
            "error_baseline.json": error_baseline_json,
        }
    }
    url = (f"https://kubernetes.default.svc/api/v1/namespaces/{CONFIGMAP_NS}"
           f"/configmaps/{CONFIGMAP_NAME}")
    ctx = ssl.create_default_context(cafile=ca_cert)
    req = urllib.request.Request(
        url,
        data=json.dumps(patch).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/strategic-merge-patch+json",
        },
        method="PATCH",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        print(f"[error] Kubernetes API patch failed {e.code}: {e.read().decode()}", flush=True)
        return False
    except Exception as e:
        print(f"[error] Kubernetes API request failed: {e}", flush=True)
        return False

    print(f"[sync] ConfigMap {CONFIGMAP_NAME} patched: "
          f"{fingerprint_count} trace fingerprints, {sig_count} error signatures",
          flush=True)
    return True


def main() -> None:
    print(f"[baseline-sync] starting — environment={ENVIRONMENT or 'any'} "
          f"poll={POLL_INTERVAL}s lookback={LOOKBACK_SECONDS}s "
          f"dry_run={DRY_RUN}", flush=True)

    # On startup, do an initial sync to ensure ConfigMap matches the local files
    # (handles the case where this pod restarted after a promotion)
    print("[baseline-sync] initial sync on startup...", flush=True)
    patch_configmap()

    last_seen_ms = int(time.time() * 1000)

    while True:
        time.sleep(POLL_INTERVAL)

        now_ms    = int(time.time() * 1000)
        start_ms  = now_ms - (LOOKBACK_SECONDS * 1000)

        # Only query events newer than what we've already processed
        query_start = max(start_ms, last_seen_ms)

        if has_promotion_events(query_start, now_ms):
            print("[baseline-sync] promotion event detected — syncing ConfigMap...",
                  flush=True)
            if patch_configmap():
                last_seen_ms = now_ms
        # else: no new promotions, nothing to do


if __name__ == "__main__":
    main()
