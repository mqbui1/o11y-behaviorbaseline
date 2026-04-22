#!/usr/bin/env python3
"""Tail OTel collector logs on the cluster for real-time drift event detection.

Default mode: human-readable live stream (Ctrl+C to stop).
  python3 poll_drift_events.py

Triage mode: wait for events, collect for a settle window, emit agent.py JSON, exit.
  python3 poll_drift_events.py --triage --environment $ENV | python3 agent.py --environment $ENV

  --settle-seconds N   Collect for N more seconds after first event (default: 5)
  --timeout-seconds N  Give up if no events arrive within N seconds (default: 120)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_REPO = Path(__file__).parent.parent  # demo/ -> repo root

# Load .env
_env = _REPO / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

EC2_IP   = os.environ.get("EC2_IP", "")
EC2_PORT = os.environ.get("EC2_PORT", "2222")
EC2_PASS = os.environ.get("EC2_PASS", os.environ.get("EC2_PASSWORD", ""))

if not EC2_IP or not EC2_PASS:
    print("ERROR: EC2_IP and EC2_PASS (or EC2_PASSWORD) must be set in .env")
    sys.exit(1)

DAEMONSET_LABEL = os.environ.get("OTEL_POD_LABEL", "app=otelcol-fingerprint")
OTEL_CONTAINER  = os.environ.get("OTEL_CONTAINER", "otelcol")
_DATA_DIR       = _REPO / "data"

def _make_ssh_cmd(since: str = "5s") -> str:
    return (
        "exec bash -c '"
        "for p in $(kubectl get pods -l " + DAEMONSET_LABEL + " -o jsonpath=\"{.items[*].metadata.name}\");"
        f" do kubectl logs -f --since={since} $p -c " + OTEL_CONTAINER + " 2>/dev/null & done;"
        " tail -f /dev/null'"
    )

def _make_proc(since: str = "5s"):
    return subprocess.Popen(
        ["sshpass", f"-p{EC2_PASS}",
         "ssh", "-T", "-p", EC2_PORT,
         "-o", "StrictHostKeyChecking=no",
         "-o", "RequestTTY=no",
         f"splunk@{EC2_IP}",
         _make_ssh_cmd(since)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )

def _dedup_path(env: str) -> Path:
    return _DATA_DIR / f"otel_dedup_state.{env}.json"

def _load_dedup(env: str) -> dict:
    p = _dedup_path(env)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {}

def _save_dedup(env: str, state: dict) -> None:
    _dedup_path(env).write_text(json.dumps(state))

drift_re    = re.compile(r'(trace drift detected|new trace fingerprint \(unknown root op\)|new error signature detected|missing service detected)')
hash_re     = re.compile(r'"hash": "([^"]+)"')
op_re       = re.compile(r'"root_op": "([^"]+)"')
svc_re      = re.compile(r'"service": "([^"]+)"')
path_re     = re.compile(r'"path": "([^"]+)"')
tid_re      = re.compile(r'"trace_id": "([^"]+)"')
env_re      = re.compile(r'"environment": "([^"]+)"')
etype_re    = re.compile(r'"error_type": "([^"]+)"')
op2_re      = re.compile(r'"operation": "([^"]+)"')
missing_re  = re.compile(r'"missing_services": \[([^\]]*)\]')

DEDUP_TTL = 90


def _parse_event(line: str) -> dict | None:
    """Parse a drift log line into an anomaly dict (agent.py schema)."""
    if not drift_re.search(line):
        return None
    is_error   = "error signature" in line
    is_missing = "missing service" in line
    h    = hash_re.search(line)
    op   = op_re.search(line)
    svc  = svc_re.search(line)
    tid  = tid_re.search(line)
    path = path_re.search(line)
    et   = etype_re.search(line)
    op2  = op2_re.search(line)
    miss = missing_re.search(line)

    h_val   = h.group(1)   if h   else ""
    op_val  = op.group(1)  if op  else ""
    svc_val = svc.group(1) if svc else (op_val.split(":")[0] if ":" in op_val else op_val)

    if is_missing:
        # Parse missing_services list from JSON-ish log field: ["svc1", "svc2"]
        missing_svcs: list[str] = []
        if miss:
            missing_svcs = [s.strip().strip('"') for s in miss.group(1).split(",") if s.strip().strip('"')]
        # Use the most specific missing service (not the root/gateway, prefer leaf)
        leaf_svc = missing_svcs[-1] if missing_svcs else svc_val
        return {
            "anomaly_type":     "MISSING_SERVICE",
            "service":          leaf_svc,
            "root_op":          op_val,
            "missing_services": missing_svcs,
            "message":          f"MISSING_SERVICE: {', '.join(missing_svcs)} absent from traces for root_op '{op_val}'",
            "hash":             h_val or f"missing:{op_val}",
            "source":           "otel-edge",
            "timestamp_ms":     int(time.time() * 1000),
        }
    elif is_error:
        et_val  = et.group(1)  if et  else ""
        op2_val = op2.group(1) if op2 else ""
        return {
            "anomaly_type": "NEW_ERROR_SIGNATURE",
            "service":      svc_val,
            "message":      f"New error signature in {svc_val}: {et_val} on {op2_val}",
            "error_type":   et_val,
            "operation":    op2_val,
            "trace_id":     tid.group(1) if tid else "",
            "hash":         h_val,
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }
    else:
        path_val = path.group(1) if path else ""
        return {
            "anomaly_type": "NEW_FINGERPRINT",
            "service":      svc_val,
            "root_op":      op_val,
            "message":      f"Trace path drift on '{op_val}' (OTel edge detector)",
            "detail":       f"Path: {path_val}" if path_val else "",
            "trace_id":     tid.group(1) if tid else "",
            "hash":         h_val,
            "source":       "otel-edge",
            "timestamp_ms": int(time.time() * 1000),
        }


def _load_baseline_root_services(env: str) -> set[str]:
    """
    Load the set of root service names from the Python baseline for the given
    environment. These are the services that appear as trace initiators in
    steady-state traffic (e.g. the ingress/gateway layer).

    OTel NEW_FINGERPRINT events whose root service is NOT in this set are
    direct service-to-service calls being auto-promoted by the OTel processor —
    not user-facing anomalies. Suppressing them prevents steady-state noise
    without hardcoding any service names.

    Falls back to an empty set (suppress nothing) if the baseline is missing.
    """
    baseline_path = _DATA_DIR / f"baseline.{env}.json"
    if not baseline_path.exists():
        return set()
    try:
        data = json.loads(baseline_path.read_text())
        return {
            info["root_op"].split(":")[0]
            for info in data.get("fingerprints", {}).values()
            if ":" in info.get("root_op", "")
        }
    except Exception:
        return set()


def _is_noise_fingerprint(event: dict, baseline_root_services: set[str]) -> bool:
    """
    Return True if this NEW_FINGERPRINT event is OTel auto-promotion noise.

    A NEW_FINGERPRINT is noise when its root service is not among the services
    that initiate traces in steady-state traffic (as known from the Python
    baseline). These are direct service-to-service calls that the OTel processor
    fires continuously until it auto-promotes them after 10 detections.
    Error signatures are never suppressed.
    """
    if event.get("anomaly_type") != "NEW_FINGERPRINT":
        return False
    if not baseline_root_services:
        return False  # no baseline loaded — keep everything
    root_op = event.get("root_op", "")
    root_svc = root_op.split(":")[0] if ":" in root_op else root_op
    return root_svc not in baseline_root_services


def _run_watch(triage: bool, environment: str, settle: int, timeout: int,
               dedup_ttl: int = DEDUP_TTL) -> None:
    """Live stream mode (triage=False) or triage mode (triage=True).

    Triage mode shares the same dedup state file as watch_otel_events.py so that
    hashes already suppressed there are also suppressed here, preventing steady-state
    OTel auto-promotion events from triggering spurious triage runs.
    """
    # In triage mode: use --since=30s to catch events that fired before we connected,
    # while relying on the shared dedup state to suppress already-seen steady-state hashes.
    # The dedup state is cleared by demo-reset.sh before each demo, so only events from
    # the current demo scenario will appear.
    since = "30s" if triage else "5s"
    dedup_state: dict = _load_dedup(environment) if triage else {}
    new_dedup:   dict = dict(dedup_state)
    baseline_roots: set[str] = _load_baseline_root_services(environment) if triage else set()

    hash_last_seen: dict = {}  # in-memory dedup for live stream mode
    collected: list[dict] = []
    missing_svc_seen: set[str] = set()  # dedup MISSING_SERVICE by leaf service name
    first_event_time: float | None = None
    last_event_time:  float | None = None

    proc = _make_proc(since)
    deadline = time.time() + timeout

    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()

            # In triage mode: exit once we've had `settle` seconds of silence
            # after the last event. This is a sliding window — new events extend
            # the collection period, so MISSING_SERVICE (~15s) is captured even
            # when error signatures fired earlier (~10s).
            if triage and last_event_time is not None:
                if time.time() - last_event_time >= settle:
                    break

            if not triage and not drift_re.search(line):
                continue

            event = _parse_event(line)
            if event is None:
                continue

            h_val = event.get("hash", "")
            now = time.time()

            if triage:
                # Skip direct-service NEW_FINGERPRINT events (OTel auto-promotion noise).
                # Uses the Python baseline's root services as the reference — no
                # hardcoded service names.
                if _is_noise_fingerprint(event, baseline_roots):
                    continue

                # For MISSING_SERVICE: deduplicate by leaf service name so that multiple
                # root_ops going silent for the same downed service emit only one event.
                if event.get("anomaly_type") == "MISSING_SERVICE":
                    leaf = event.get("service", "")
                    if leaf in missing_svc_seen:
                        continue
                    missing_svc_seen.add(leaf)

                # Use shared dedup state (same file watch_otel_events.py writes)
                # For MISSING_SERVICE: key on leaf service (no hash in log); for others: use hash.
                if event.get("anomaly_type") == "MISSING_SERVICE":
                    dedup_key = f"MISSING_SERVICE:{event.get('service', event.get('root_op', ''))}"
                else:
                    dedup_key = h_val if h_val else (
                        f"{event.get('anomaly_type')}:{event.get('service')}:{event.get('root_op') or event.get('error_type')}"
                    )
                last_seen_ms = dedup_state.get(dedup_key, 0)
                if now * 1000 - last_seen_ms < dedup_ttl * 1000:
                    continue
                new_dedup[dedup_key] = int(now * 1000)

                collected.append(event)
                if first_event_time is None:
                    first_event_time = now
                    print(f"  [{time.strftime('%H:%M:%S')}] {len(collected)} event(s) received — settling for {settle}s...",
                          file=sys.stderr)
                last_event_time = now
                if now >= deadline:
                    break
            else:
                # Live stream: in-memory dedup by hash (errors/fingerprints) or
                # by leaf service name (MISSING_SERVICE — no stable hash in logs).
                atype = event.get("anomaly_type", "")
                if atype == "MISSING_SERVICE":
                    dedup_key_live = f"MISSING_SERVICE:{event.get('service', '')}"
                else:
                    dedup_key_live = h_val
                if dedup_key_live:
                    if now - hash_last_seen.get(dedup_key_live, 0) < dedup_ttl:
                        continue
                    hash_last_seen[dedup_key_live] = now

                ts = time.strftime("%H:%M:%S")
                if atype == "NEW_ERROR_SIGNATURE":
                    etype = "error.signature.drift"
                elif atype == "MISSING_SERVICE":
                    etype = "trace.path.drift (MISSING_SERVICE)"
                else:
                    etype = "trace.path.drift"
                print(f"[{ts}] {etype}")
                print(f"  root_op={event.get('root_op') or event.get('service')}  hash={h_val or '?'}")
                if event.get("missing_services"):
                    print(f"  missing={','.join(event['missing_services'])}")
                if event.get("trace_id"):
                    print(f"  trace_id={event['trace_id']}")
                print()

    except KeyboardInterrupt:
        pass
    finally:
        try:
            proc.terminate()
        except Exception:
            pass

    if triage:
        if not collected:
            print("  No drift events received within timeout.", file=sys.stderr)
            sys.exit(1)
        _save_dedup(environment, new_dedup)
        result = {
            "environment":    environment,
            "timestamp":      datetime.now(timezone.utc).isoformat(),
            "window_minutes": 0,
            "source":         "otel-edge-direct",
            "checked":        len(collected),
            "anomalies":      collected,
        }
        print(json.dumps(result))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--triage", action="store_true",
                        help="Collect events and emit agent.py JSON instead of live stream")
    parser.add_argument("--environment", default=os.environ.get("ENV", ""),
                        help="Environment name (for JSON output)")
    parser.add_argument("--settle-seconds", type=int, default=5,
                        help="Seconds to keep collecting after first event (default: 5)")
    parser.add_argument("--timeout-seconds", type=int, default=120,
                        help="Give up if no events arrive within this many seconds (default: 120)")
    args = parser.parse_args()

    if not args.triage:
        print("Watching OTel collector for real-time drift events...")
        print("Press Ctrl+C to stop.\n")

    _run_watch(
        triage=args.triage,
        environment=args.environment,
        settle=args.settle_seconds,
        timeout=args.timeout_seconds,
    )


if __name__ == "__main__":
    main()
