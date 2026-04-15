#!/usr/bin/env python3
"""
Behavioral Baseline — Proactive Baseline Drift Monitor
=======================================================
Compares the current baseline against a saved snapshot to detect gradual
drift over time: fingerprints appearing, disappearing, or changing shape.

Run periodically (e.g. weekly via cron) to catch slow baseline decay before
it causes false positives or missed detections.

Usage:
  # Take a snapshot of the current baseline (run once to establish reference)
  python baseline_drift_monitor.py --environment petclinicmbtest snapshot

  # Diff current baseline against last snapshot and emit an event if changed
  python baseline_drift_monitor.py --environment petclinicmbtest diff

  # Diff without emitting (dry-run)
  python baseline_drift_monitor.py --environment petclinicmbtest diff --dry-run

Snapshots are saved to data/baseline_snapshot.<env>.json.
Diff results are emitted as behavioral_baseline.drift_summary events to Splunk.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────────

_ENV_FILE = Path(__file__).parent / ".env"
if _ENV_FILE.exists():
    for _line in _ENV_FILE.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

ACCESS_TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN")
INGEST_TOKEN = os.environ.get("SPLUNK_INGEST_TOKEN") or ACCESS_TOKEN
REALM        = os.environ.get("SPLUNK_REALM", "us1")
INGEST_URL   = f"https://ingest.{REALM}.signalfx.com"

_DATA_DIR = Path(__file__).parent / "data"

# Minimum number of changed fingerprints to emit an event
MIN_CHANGES_TO_EMIT = int(os.environ.get("BASELINE_DRIFT_MIN_CHANGES", "3"))


def _request(method, path, body=None, base_url=INGEST_URL):
    url     = f"{base_url}{path}"
    token   = INGEST_TOKEN if base_url == INGEST_URL else ACCESS_TOKEN
    headers = {"X-SF-Token": token, "Content-Type": "application/json"}
    data    = json.dumps(body).encode() if body is not None else None
    req     = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Splunk API {e.code}: {e.read().decode()[:200]}")


def load_baseline(env: str) -> dict:
    path = _DATA_DIR / f"baseline.{env}.json"
    if not path.exists():
        print(f"Error: baseline not found: {path}", file=sys.stderr)
        sys.exit(1)
    return json.loads(path.read_text())


def snapshot_path(env: str) -> Path:
    return _DATA_DIR / f"baseline_snapshot.{env}.json"


def cmd_snapshot(env: str) -> None:
    """Save the current baseline as a snapshot for future diffing."""
    baseline = load_baseline(env)
    dest = snapshot_path(env)
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(baseline, indent=2))
    fps = len(baseline.get("fingerprints", {}))
    print(f"Snapshot saved: {dest} ({fps} fingerprints)")


def cmd_diff(env: str, dry_run: bool = False) -> None:
    """Diff current baseline against the last snapshot and report changes."""
    snap_path = snapshot_path(env)
    if not snap_path.exists():
        print(f"No snapshot found at {snap_path}. Run with 'snapshot' first.",
              file=sys.stderr)
        sys.exit(1)

    current  = load_baseline(env)
    snapshot = json.loads(snap_path.read_text())

    curr_fps = current.get("fingerprints", {})
    snap_fps = snapshot.get("fingerprints", {})

    curr_hashes = set(curr_fps.keys())
    snap_hashes = set(snap_fps.keys())

    added   = curr_hashes - snap_hashes
    removed = snap_hashes - curr_hashes

    # Check for fingerprints that exist in both but changed shape (path/services)
    changed = []
    for h in curr_hashes & snap_hashes:
        c = curr_fps[h]
        s = snap_fps[h]
        if c.get("path") != s.get("path") or set(c.get("services", [])) != set(s.get("services", [])):
            changed.append({
                "hash":          h,
                "root_op":       c.get("root_op", ""),
                "old_path":      s.get("path", ""),
                "new_path":      c.get("path", ""),
                "old_services":  sorted(s.get("services", [])),
                "new_services":  sorted(c.get("services", [])),
            })

    total_changes = len(added) + len(removed) + len(changed)

    print(f"Baseline diff for {env}:")
    print(f"  Current:  {len(curr_fps)} fingerprints")
    print(f"  Snapshot: {len(snap_fps)} fingerprints")
    print(f"  Added:    {len(added)} new fingerprints")
    print(f"  Removed:  {len(removed)} fingerprints gone")
    print(f"  Changed:  {len(changed)} fingerprints with different paths/services")

    if added:
        print("\n  New fingerprints (added since snapshot):")
        for h in sorted(added)[:10]:
            e = curr_fps[h]
            print(f"    [{h[:8]}] {e.get('root_op', '?')} — {e.get('path', '')[:80]}")

    if removed:
        print("\n  Removed fingerprints (no longer in baseline):")
        for h in sorted(removed)[:10]:
            e = snap_fps[h]
            print(f"    [{h[:8]}] {e.get('root_op', '?')} — {e.get('path', '')[:80]}")

    if changed:
        print("\n  Changed fingerprints (path or services differ):")
        for c in changed[:5]:
            print(f"    [{c['hash'][:8]}] {c['root_op']}")
            if c["old_path"] != c["new_path"]:
                print(f"      path: {c['old_path'][:60]} → {c['new_path'][:60]}")
            if c["old_services"] != c["new_services"]:
                print(f"      services: {c['old_services']} → {c['new_services']}")

    if total_changes < MIN_CHANGES_TO_EMIT:
        print(f"\n  {total_changes} change(s) — below threshold ({MIN_CHANGES_TO_EMIT}). No event emitted.")
        return

    if dry_run:
        print(f"\n  [dry-run] Would emit behavioral_baseline.drift_summary event.")
        return

    if not ACCESS_TOKEN:
        print("Warning: SPLUNK_ACCESS_TOKEN not set — skipping event emission.", file=sys.stderr)
        return

    # Emit a summary event to Splunk
    try:
        _request("POST", "/v2/event", [{
            "eventType": "behavioral_baseline.drift_summary",
            "category":  "USER_DEFINED",
            "dimensions": {
                "sf_environment": env,
                "detector":       "baseline-drift-monitor",
            },
            "properties": {
                "environment":   env,
                "added":         len(added),
                "removed":       len(removed),
                "changed":       len(changed),
                "total_changes": total_changes,
                "current_fps":   len(curr_fps),
                "snapshot_fps":  len(snap_fps),
                "message": (
                    f"Baseline drift: +{len(added)}/-{len(removed)}/{len(changed)} changed "
                    f"fingerprints in {env} since last snapshot"
                ),
            },
            "timestamp": int(time.time() * 1000),
        }])
        print(f"\n  Event emitted: behavioral_baseline.drift_summary "
              f"(+{len(added)}/-{len(removed)}/{len(changed)} changed)")
    except Exception as e:
        print(f"\n  [warn] Failed to emit event: {e}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Proactive baseline drift monitor — detect gradual baseline decay"
    )
    parser.add_argument("--environment", required=True,
                        help="APM environment (e.g. petclinicmbtest)")
    parser.add_argument("command", choices=["snapshot", "diff"],
                        help="snapshot: save current baseline; diff: compare to snapshot")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print diff without emitting events (diff only)")
    args = parser.parse_args()

    if args.command == "snapshot":
        cmd_snapshot(args.environment)
    else:
        cmd_diff(args.environment, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
