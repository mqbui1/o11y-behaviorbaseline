#!/usr/bin/env python3
"""Poll Splunk for trace.path.drift and error.signature.drift events every 5s."""
import os, time, json, sys
from pathlib import Path

# Load .env
_env = Path(__file__).parent / ".env"
if _env.exists():
    for line in _env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            os.environ.setdefault(k.strip(), v.strip())

import urllib.request, urllib.parse

TOKEN = os.environ.get("SPLUNK_ACCESS_TOKEN", "")
REALM = os.environ.get("SPLUNK_REALM", "us1")
BASE  = f"https://api.{REALM}.signalfx.com"
LOOKBACK_MS = int(os.environ.get("POLL_LOOKBACK_MS", 120000))  # 2 min default

def fetch_events(event_type: str, lookback_ms: int) -> list:
    now = int(time.time() * 1000)
    params = urllib.parse.urlencode({
        "type": event_type,
        "startTime": now - lookback_ms,
        "limit": 10,
    })
    req = urllib.request.Request(
        f"{BASE}/v2/event?{params}",
        headers={"X-SF-TOKEN": TOKEN},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read()).get("results", [])
    except Exception as e:
        return []

print(f"Polling for drift events (every 5s, last {LOOKBACK_MS//1000}s window)...")
print("Press Ctrl+C to stop.\n")

seen = set()
while True:
    for etype in ["trace.path.drift", "error.signature.drift"]:
        events = fetch_events(etype, LOOKBACK_MS)
        for e in events:
            eid = e.get("id") or e.get("timestamp")
            if eid in seen:
                continue
            seen.add(eid)
            dims = e.get("dimensions", {})
            ts = time.strftime("%H:%M:%S", time.localtime(e.get("timestamp", 0) / 1000))
            print(f"[{ts}] {etype}")
            print(f"  service={dims.get('service')}  anomaly={dims.get('anomaly_type')}  root_op={dims.get('root_operation')}")
    time.sleep(5)
