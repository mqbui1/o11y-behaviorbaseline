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

ENV_FILE = Path(__file__).parent / ".env"

# Use boto3's default credential chain (env vars, ~/.aws/config SSO, instance profile, etc.)
try:
    import boto3
    session = boto3.Session(region_name=os.environ.get("AWS_REGION", "us-west-2"))
    sts = session.client("sts")
    arn = sts.get_caller_identity()["Arn"]
    print(f"  Credentials verified: {arn}")
    creds = session.get_credentials().get_frozen_credentials()
except Exception as e:
    print(f"[error] Could not resolve AWS credentials: {e}", file=sys.stderr)
    print("        Run 'aws sso login' or re-authenticate via Okta, then retry.", file=sys.stderr)
    sys.exit(1)

region = session.region_name or "us-west-2"

# Read existing .env, strip old AWS lines, append fresh ones
content = ENV_FILE.read_text() if ENV_FILE.exists() else ""
lines = [l for l in content.splitlines()
         if not l.startswith("AWS_") and not l.startswith("# AWS credentials")]

lines.append("")
lines.append("# AWS credentials (refresh before demo: python3 refresh_aws_creds.py)")
lines.append(f"AWS_ACCESS_KEY_ID={creds.access_key}")
lines.append(f"AWS_SECRET_ACCESS_KEY={creds.secret_key}")
if creds.token:
    lines.append(f"AWS_SESSION_TOKEN={creds.token}")
lines.append(f"AWS_REGION={region}")

ENV_FILE.write_text("\n".join(lines) + "\n")
print(f"  .env updated with fresh AWS credentials.")
print(f"  Run 'source .env' in your demo terminal to pick them up.")
