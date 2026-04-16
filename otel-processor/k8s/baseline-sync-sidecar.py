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
from pathlib import Path

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
# How many trace.path.restored events within the window trigger a re-learn job.
# A single restoration is normal (one service recovered). Multiple restorations
# within one poll window suggest a broader recovery — re-learn immediately.
RESTORE_RELEARN_THRESHOLD = int(os.environ.get("RESTORE_RELEARN_THRESHOLD", "1"))
LEARN_CRONJOB_NAME  = os.environ.get("LEARN_CRONJOB_NAME", "baseline-learn")
# Emit behavioral_baseline.stale event if ConfigMap not updated in this many seconds.
STALENESS_THRESHOLD_S = int(os.environ.get("STALENESS_THRESHOLD_S", str(24 * 3600)))
# baseline_reload_interval from the processor config (default 60s). Used to detect
# pods that stopped reloading their local baseline file.
BASELINE_RELOAD_INTERVAL_S = int(os.environ.get("BASELINE_RELOAD_INTERVAL_S", "60"))
# Ingest URL for emitting alert events (needs ingest token, not API token)
SPLUNK_INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN", "") or SPLUNK_TOKEN
SPLUNK_INGEST_URL   = os.environ.get("SPLUNK_INGEST_URL",
                                      f"https://ingest.{os.environ.get('SPLUNK_REALM', 'us1')}.signalfx.com")

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


def _filter_by_env(events: list[dict]) -> list[dict]:
    """Filter events to our environment. If ENVIRONMENT is unset, return all."""
    if not ENVIRONMENT:
        return events
    out = []
    for msg in events:
        dims = msg.get("metadata", {})
        props = msg.get("properties", {})
        env = dims.get("sf_environment") or props.get("environment", "")
        if not env or env == ENVIRONMENT:
            out.append(msg)
    return out


def has_promotion_events(start_ms: int, end_ms: int) -> bool:
    """Return True if any trace.fingerprint.promoted events exist in the window."""
    events = _filter_by_env(_signalflow_events("trace.fingerprint.promoted", start_ms, end_ms))
    return len(events) > 0


def count_restore_events(start_ms: int, end_ms: int) -> int:
    """Return the number of trace.path.restored events in the window."""
    events = _filter_by_env(_signalflow_events("trace.path.restored", start_ms, end_ms))
    return len(events)


def trigger_learn_job() -> bool:
    """
    Create a one-off Kubernetes Job from the baseline-learn CronJob template.
    Uses the in-cluster service account token to call the Kubernetes API directly
    (no kubectl binary needed in the sidecar container).
    Returns True on success.
    """
    import time as _time
    job_name = f"{LEARN_CRONJOB_NAME}-restore-{int(_time.time())}"

    try:
        sa_token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text()
        ca_cert  = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    except Exception as e:
        print(f"[warn] Could not read service account token: {e}", flush=True)
        return False

    ctx = ssl.create_default_context(cafile=ca_cert)

    # GET the CronJob spec to use as template for the Job
    cj_url = (f"https://kubernetes.default.svc/apis/batch/v1/namespaces/{CONFIGMAP_NS}"
              f"/cronjobs/{LEARN_CRONJOB_NAME}")
    get_req = urllib.request.Request(
        cj_url,
        headers={"Authorization": f"Bearer {sa_token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(get_req, context=ctx, timeout=10) as resp:
            cj = json.loads(resp.read().decode())
    except Exception as e:
        print(f"[warn] Could not fetch CronJob {LEARN_CRONJOB_NAME}: {e}", flush=True)
        return False

    # Build a Job from the CronJob's jobTemplate
    job_spec = cj.get("spec", {}).get("jobTemplate", {}).get("spec", {})
    job_body = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name":      job_name,
            "namespace": CONFIGMAP_NS,
            "labels":    {"app": "baseline-learn", "trigger": "restore"},
        },
        "spec": job_spec,
    }

    jobs_url = (f"https://kubernetes.default.svc/apis/batch/v1/namespaces/{CONFIGMAP_NS}/jobs")
    post_req = urllib.request.Request(
        jobs_url,
        data=json.dumps(job_body).encode(),
        headers={
            "Authorization": f"Bearer {sa_token}",
            "Content-Type":  "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(post_req, context=ctx, timeout=10) as resp:
            resp.read()
        print(f"[baseline-sync] triggered learn job: {job_name}", flush=True)
        return True
    except urllib.error.HTTPError as e:
        print(f"[warn] Could not create learn job {e.code}: {e.read().decode()[:200]}", flush=True)
        return False
    except Exception as e:
        print(f"[warn] Could not create learn job: {e}", flush=True)
        return False


def _emit_heartbeat() -> None:
    """
    Send a behavioral_baseline.sidecar.alive gauge metric (value=1) to Splunk.
    Build a Splunk detector on this metric with a missing-data condition to
    alert when the sidecar stops reporting (OOMKilled, crash-loop, etc.).
    """
    if DRY_RUN:
        return
    try:
        token = SPLUNK_INGEST_TOKEN
        dims  = {
            "sf_environment": ENVIRONMENT or "unknown",
            "component":      "baseline-sync-sidecar",
        }
        dim_str = ",".join(f"{k}={v}" for k, v in dims.items())
        # Use SignalFx ingest REST API for a single gauge datapoint
        body = json.dumps({
            "gauge": [{
                "metric":     "behavioral_baseline.sidecar.alive",
                "value":      1,
                "dimensions": dims,
            }]
        }).encode()
        req = urllib.request.Request(
            f"{SPLUNK_INGEST_URL}/v2/datapoint",
            data=body,
            headers={"X-SF-Token": token, "Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # heartbeat is best-effort — never disrupt the main loop


def _emit_event(event_type: str, properties: dict) -> None:
    """Emit a custom event to Splunk Observability (best-effort, never raises)."""
    if DRY_RUN:
        print(f"[dry-run] Would emit {event_type}: {properties}", flush=True)
        return
    body = json.dumps([{
        "eventType": event_type,
        "category":  "USER_DEFINED",
        "dimensions": {"sf_environment": ENVIRONMENT or "unknown",
                       "detector":       "baseline-sync-sidecar"},
        "properties": properties,
        "timestamp":  int(time.time() * 1000),
    }]).encode()
    req = urllib.request.Request(
        f"{SPLUNK_INGEST_URL}/v2/event",
        data=body,
        headers={"X-SF-Token": SPLUNK_INGEST_TOKEN, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[warn] Could not emit {event_type}: {e}", flush=True)


def get_configmap_update_time() -> float:
    """
    Return the last update timestamp of the behavioral-baseline ConfigMap as
    a Unix timestamp (float). Returns 0.0 on any error.
    """
    try:
        token  = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text()
        ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        ctx    = ssl.create_default_context(cafile=ca_cert)
        url    = (f"https://kubernetes.default.svc/api/v1/namespaces/{CONFIGMAP_NS}"
                  f"/configmaps/{CONFIGMAP_NAME}")
        req = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            cm = json.loads(resp.read().decode())
        ts_str = (cm.get("metadata", {}).get("managedFields", [{}])[-1]
                  .get("time", "") or
                  cm.get("metadata", {}).get("creationTimestamp", ""))
        if ts_str:
            import datetime
            dt = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            return dt.timestamp()
    except Exception as e:
        print(f"[warn] Could not read ConfigMap timestamp: {e}", flush=True)
    return 0.0


def check_baseline_empty_and_bootstrap() -> None:
    """
    On startup: if the local baseline has 0 fingerprints, trigger a learn job
    immediately so detection starts as soon as possible.
    """
    try:
        data = json.loads(Path(BASELINE_PATH).read_text())
        fp_count = len(data.get("fingerprints", {}))
    except Exception:
        fp_count = 0

    if fp_count == 0:
        print("[baseline-sync] baseline is empty — triggering bootstrap learn job...",
              flush=True)
        if DRY_RUN:
            print("[dry-run] Would trigger bootstrap learn job", flush=True)
        else:
            trigger_learn_job()
    else:
        print(f"[baseline-sync] baseline has {fp_count} fingerprint(s) — no bootstrap needed",
              flush=True)


def check_local_baseline_staleness() -> None:
    """
    Warn if the local baseline file hasn't been updated in > 2× reload interval.
    This catches cases where the processor stopped reloading (disk issue, permission
    problem, etc.) — the file mtime would be stuck at pod-start time.
    """
    try:
        mtime = Path(BASELINE_PATH).stat().st_mtime
        age_s = time.time() - mtime
        threshold_s = BASELINE_RELOAD_INTERVAL_S * 2
        if age_s > threshold_s:
            print(f"[warn] Local baseline file is {age_s:.0f}s old "
                  f"(threshold {threshold_s}s) — processor may not be reloading",
                  flush=True)
            _emit_event("behavioral_baseline.pod_stale", {
                "environment":    ENVIRONMENT or "unknown",
                "baseline_age_s": int(age_s),
                "threshold_s":    threshold_s,
                "message":        f"Baseline file not updated in {age_s:.0f}s — processor reload may be stuck",
            })
    except Exception:
        pass  # best-effort


def patch_configmap() -> bool:
    """
    Read current baseline files from disk and patch the ConfigMap.
    Returns True on success.
    """
    try:
        baseline_json = Path(BASELINE_PATH).read_text()
    except Exception as e:
        print(f"[warn] Could not read {BASELINE_PATH}: {e}", flush=True)
        return False

    try:
        error_baseline_json = Path(ERROR_BASELINE_PATH).read_text()
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
        token = Path("/var/run/secrets/kubernetes.io/serviceaccount/token").read_text()
        ca_cert = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    except Exception as e:
        print(f"[error] Could not read service account credentials: {e}", flush=True)
        return False

    url = (f"https://kubernetes.default.svc/api/v1/namespaces/{CONFIGMAP_NS}"
           f"/configmaps/{CONFIGMAP_NAME}")
    ctx = ssl.create_default_context(cafile=ca_cert)

    # Step 1: GET the current ConfigMap to obtain resourceVersion (required for PUT)
    get_req = urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(get_req, context=ctx, timeout=15) as resp:
            current = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        print(f"[error] Could not GET ConfigMap {e.code}: {e.read().decode()}", flush=True)
        return False
    except Exception as e:
        print(f"[error] ConfigMap GET failed: {e}", flush=True)
        return False

    # Step 2: PUT (full replacement) — avoids the last-applied-configuration
    # annotation caching problem that makes strategic-merge-patch silently ignore
    # new data. resourceVersion ensures we don't overwrite a concurrent update.
    resource_version = current.get("metadata", {}).get("resourceVersion", "")
    put_body = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name":            CONFIGMAP_NAME,
            "namespace":       CONFIGMAP_NS,
            "resourceVersion": resource_version,
        },
        "data": {
            "baseline.json":       baseline_json,
            "error_baseline.json": error_baseline_json,
        },
    }
    put_req = urllib.request.Request(
        url,
        data=json.dumps(put_body).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        method="PUT",
    )
    try:
        with urllib.request.urlopen(put_req, context=ctx, timeout=15) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        print(f"[error] Kubernetes API PUT failed {e.code}: {e.read().decode()}", flush=True)
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
          f"restore_relearn_threshold={RESTORE_RELEARN_THRESHOLD} "
          f"staleness_threshold={STALENESS_THRESHOLD_S}s "
          f"dry_run={DRY_RUN}", flush=True)

    # ── Startup: bootstrap if baseline is empty ──────────────────────────────
    check_baseline_empty_and_bootstrap()

    # ── Startup: sync ConfigMap to match local files ─────────────────────────
    print("[baseline-sync] initial sync on startup...", flush=True)
    patch_configmap()

    last_seen_ms      = int(time.time() * 1000)
    last_learn_ms     = 0   # track when we last triggered a learn to avoid spamming
    last_stale_alert_ms = 0  # rate-limit staleness alerts to once per staleness window

    while True:
        time.sleep(POLL_INTERVAL)

        now_ms      = int(time.time() * 1000)
        start_ms    = now_ms - (LOOKBACK_SECONDS * 1000)
        query_start = max(start_ms, last_seen_ms)

        # ── Promotion events: sync ConfigMap ────────────────────────────────
        if has_promotion_events(query_start, now_ms):
            print("[baseline-sync] promotion event detected — syncing ConfigMap...",
                  flush=True)
            if patch_configmap():
                last_seen_ms = now_ms

        # ── Restore events: trigger a full re-learn ──────────────────────────
        # When services recover (trace.path.restored), the healthy baseline
        # should be re-learned so future traces don't look like drift.
        # Rate-limit: don't trigger more than once per 10 minutes.
        restore_count = count_restore_events(query_start, now_ms)
        learn_cooldown_ms = 10 * 60 * 1000
        if (restore_count >= RESTORE_RELEARN_THRESHOLD
                and (now_ms - last_learn_ms) > learn_cooldown_ms):
            print(f"[baseline-sync] {restore_count} restore event(s) detected — "
                  f"triggering baseline re-learn job...", flush=True)
            if DRY_RUN:
                print("[dry-run] Would create learn job", flush=True)
                last_learn_ms = now_ms
            elif trigger_learn_job():
                last_learn_ms = now_ms

        # ── ConfigMap staleness check ─────────────────────────────────────────
        # Alert if the ConfigMap hasn't been updated in > STALENESS_THRESHOLD_S.
        # Rate-limit the alert to once per staleness window to avoid spam.
        stale_cooldown_ms = STALENESS_THRESHOLD_S * 1000
        if (now_ms - last_stale_alert_ms) > stale_cooldown_ms:
            cm_update_time = get_configmap_update_time()
            if cm_update_time > 0:
                age_s = time.time() - cm_update_time
                if age_s > STALENESS_THRESHOLD_S:
                    print(f"[baseline-sync] ConfigMap is {age_s/3600:.1f}h old — emitting staleness alert",
                          flush=True)
                    _emit_event("behavioral_baseline.stale", {
                        "environment":   ENVIRONMENT or "unknown",
                        "age_hours":     round(age_s / 3600, 1),
                        "threshold_hours": round(STALENESS_THRESHOLD_S / 3600, 1),
                        "message":       f"Baseline ConfigMap not updated in {age_s/3600:.1f}h — scheduled learn may have failed",
                    })
                    last_stale_alert_ms = now_ms

        # ── Local baseline file staleness check ───────────────────────────────
        # Warn if the processor seems to have stopped reloading its local copy.
        check_local_baseline_staleness()

        # ── Heartbeat metric ──────────────────────────────────────────────────
        # Emit a gauge=1 metric every poll cycle. A Splunk detector on
        # behavioral_baseline.sidecar.alive can alert when this goes silent
        # (sidecar OOMKilled, crash-loop, etc.).
        _emit_heartbeat()


if __name__ == "__main__":
    main()
