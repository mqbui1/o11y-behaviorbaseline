#!/usr/bin/env python3
"""
refresh_aws_creds.py — Write current AWS session credentials to .env.

Run this once before demoing whenever AWS tokens have rotated:
  python3 refresh_aws_creds.py

The script reads AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN,
and AWS_REGION from the current shell environment and writes them into .env
so that all scripts (agent.py, triage_agent.py, etc.) pick them up automatically
without needing the vars set in every terminal.
"""

import os
import sys
from pathlib import Path

AWS_KEYS = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION"]
ENV_FILE = Path(__file__).parent / ".env"

missing = [k for k in AWS_KEYS[:3] if not os.environ.get(k)]
if missing:
    print(f"[error] Missing AWS env vars: {missing}", file=sys.stderr)
    print("        Open a fresh terminal (Claude Code sets these automatically)", file=sys.stderr)
    print("        or re-authenticate via Okta, then re-run this script.", file=sys.stderr)
    sys.exit(1)

# Verify credentials work before writing
try:
    import boto3
    arn = boto3.client("sts", region_name=os.environ.get("AWS_REGION", "us-west-2")) \
              .get_caller_identity()["Arn"]
    print(f"  Credentials verified: {arn}")
except Exception as e:
    print(f"[error] Credential check failed: {e}", file=sys.stderr)
    sys.exit(1)

# Read existing .env, strip old AWS lines, append fresh ones
content = ENV_FILE.read_text() if ENV_FILE.exists() else ""
lines = [l for l in content.splitlines()
         if not l.startswith("AWS_") and not l.startswith("# AWS credentials")]

lines.append("")
lines.append("# AWS credentials (refresh before demo: python3 refresh_aws_creds.py)")
for k in AWS_KEYS:
    v = os.environ.get(k, "")
    if v:
        lines.append(f"{k}={v}")

ENV_FILE.write_text("\n".join(lines) + "\n")
print(f"  .env updated with fresh AWS credentials.")
print(f"  Run 'source .env' in your demo terminal to pick them up.")
