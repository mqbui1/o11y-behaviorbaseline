#!/usr/bin/env python3
"""Tail OTel collector logs on the cluster for real-time drift event detection."""
import os, subprocess, sys, re, time
from pathlib import Path

# Load .env
_env = Path(__file__).parent / ".env"
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

print("Watching OTel collector for real-time drift events...")
print("Press Ctrl+C to stop.\n")

cmd = [
    "sshpass", f"-p{EC2_PASS}",
    "ssh", "-p", EC2_PORT, "-o", "StrictHostKeyChecking=no",
    f"splunk@{EC2_IP}",
    "kubectl logs -f --since=5s daemonset/otelcol-fingerprint 2>&1"
]

drift_re = re.compile(r'(trace drift detected|new trace fingerprint \(unknown root op\)|new error signature detected)')
hash_re  = re.compile(r'"hash": "([^"]+)"')
op_re    = re.compile(r'"root_op": "([^"]+)"')
svc_re   = re.compile(r'"service": "([^"]+)"')
tid_re   = re.compile(r'"trace_id": "([^"]+)"')
env_re   = re.compile(r'"environment": "([^"]+)"')

try:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        line = line.rstrip()
        if not drift_re.search(line):
            continue
        ts   = time.strftime("%H:%M:%S")
        op   = op_re.search(line)
        svc  = svc_re.search(line)
        h    = hash_re.search(line)
        tid  = tid_re.search(line)
        env  = env_re.search(line)
        etype = "error.signature.drift" if "error signature" in line else "trace.path.drift"
        print(f"[{ts}] {etype}")
        print(f"  root_op={op.group(1) if op else '?'}  hash={h.group(1) if h else '?'}")
        if tid:
            print(f"  trace_id={tid.group(1)}")
        print()
except KeyboardInterrupt:
    pass
finally:
    try:
        proc.terminate()
    except Exception:
        pass
