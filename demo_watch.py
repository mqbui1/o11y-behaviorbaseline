#!/usr/bin/env python3
"""
demo_watch.py — Hands-off demo mode: autonomous detect → triage → correlate loop.
==================================================================================
Runs continuously. When the OTel edge processor fires a drift event, this script:

  1. Catches it from the collector logs directly (no Splunk indexing wait)
  2. Calls agent.py immediately for AI triage (~15s from kill to verdict)
  3. After a settle window, calls correlate.py for cross-tier correlation
  4. Loops — ready for the next scenario

Usage:
  python3 demo_watch.py --environment $ENV

  # Quiet: only print triage verdicts, not poll messages
  python3 demo_watch.py --environment $ENV --quiet

  # Custom settle before correlate (default: 60s — gives Splunk time to index)
  python3 demo_watch.py --environment $ENV --correlate-delay 90

Kill a service in another terminal and watch this detect + triage + correlate
with zero manual commands.

Output goes to stdout AND data/alerts.log (same as agent.py).
"""
import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Load .env ──────────────────────────────────────────────────────────────────
_env_file = Path(__file__).parent / ".env"
if _env_file.exists():
    for _line in _env_file.read_text().splitlines():
        _line = _line.strip()
        if _line and not _line.startswith("#") and "=" in _line:
            _k, _, _v = _line.partition("=")
            os.environ.setdefault(_k.strip(), _v.strip())

_REPO = Path(__file__).parent


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def _run_triage(environment: str, quiet: bool) -> bool:
    """
    Call poll_drift_events --triage | agent.py.
    Blocks until drift events arrive or timeout (120s).
    Returns True if triage ran, False if timeout (no events).
    """
    if not quiet:
        print(f"[{_ts()}] Waiting for drift events from OTel edge processor...", flush=True)

    poll_cmd = [
        sys.executable, str(_REPO / "poll_drift_events.py"),
        "--triage", "--environment", environment,
        "--timeout-seconds", "120",
        "--settle-seconds", "5",
    ]
    agent_cmd = [
        sys.executable, str(_REPO / "agent.py"),
        "--environment", environment,
    ]

    # pipe poll_drift_events stdout → agent.py stdin
    poll_proc  = subprocess.Popen(poll_cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE)
    agent_proc = subprocess.Popen(agent_cmd, stdin=poll_proc.stdout,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    poll_proc.stdout.close()  # allow poll_proc to receive SIGPIPE if agent exits

    output, _ = agent_proc.communicate()
    poll_proc.wait()

    if poll_proc.returncode != 0 and not output:
        # poll_drift_events timed out with no events
        return False

    if output:
        text = output.decode("utf-8", errors="replace")
        print(text, end="", flush=True)

    return True


def _run_correlate(environment: str, window_minutes: int, quiet: bool) -> None:
    """Call correlate.py and print its output."""
    if not quiet:
        print(f"\n[{_ts()}] Running cross-tier correlation...", flush=True)

    result = subprocess.run(
        [sys.executable, str(_REPO / "core" / "correlate.py"),
         "--environment", environment,
         "--window-minutes", str(window_minutes)],
        capture_output=True, text=True,
    )
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr and not quiet:
        print(result.stderr, end="", file=sys.stderr, flush=True)


def _clear_dedup(environment: str) -> None:
    """Clear OTel dedup state so the next scenario fires fresh."""
    for f in (_REPO / "data").glob(f"*dedup*{environment}*"):
        f.write_text("{}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--environment",
                        default=os.environ.get("ENV", ""),
                        help="APM environment (or set ENV)")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress poll/correlate status lines")
    parser.add_argument("--correlate-delay", type=int, default=60,
                        help="Seconds to wait after triage before running correlate (default: 60)")
    parser.add_argument("--correlate-window", type=int, default=20,
                        help="Window minutes passed to correlate.py (default: 20)")
    parser.add_argument("--no-correlate", action="store_true",
                        help="Skip correlate.py step (triage only)")
    args = parser.parse_args()

    if not args.environment:
        print("ERROR: --environment required (or set ENV)", file=sys.stderr)
        sys.exit(1)

    print(f"[demo_watch] env={args.environment} | watching for drift events...")
    print(f"  Kill a service in another terminal to trigger detection.")
    print(f"  Press Ctrl+C to stop.\n", flush=True)

    while True:
        try:
            fired = _run_triage(args.environment, args.quiet)

            if not fired:
                if not args.quiet:
                    print(f"[{_ts()}] No events in 120s — still watching...", flush=True)
                continue

            # Triage ran — wait for Splunk to index events before correlate
            if not args.no_correlate:
                if not args.quiet:
                    print(f"\n[{_ts()}] Triage complete. "
                          f"Waiting {args.correlate_delay}s for Splunk indexing "
                          f"before cross-tier correlation...", flush=True)
                time.sleep(args.correlate_delay)
                _run_correlate(args.environment, args.correlate_window, args.quiet)

            # Clear dedup so the next demo scenario fires fresh
            _clear_dedup(args.environment)

            print(f"\n[{_ts()}] Ready for next scenario. "
                  f"Kill a service to trigger again.\n", flush=True)

        except KeyboardInterrupt:
            print(f"\n[demo_watch] Stopped.", flush=True)
            sys.exit(0)


if __name__ == "__main__":
    main()
