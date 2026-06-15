#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations
import argparse
import sys
import urllib.error
import urllib.request

def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST SEMSIFT JSON findings from stdin to a webhook URL.",
    )
    ap.add_argument("--url", required=True, help="Target URL to POST findings to")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra HTTP header in 'Key: Value' form (repeatable)",
    )
    args = ap.parse_args()

    # Validate header format before reading stdin.
    for h in args.header:
        if ":" not in h:
            print(
                f"webhook: invalid --header {h!r}: expected 'Key: Value' format",
                file=sys.stderr,
            )
            return 2

    payload = sys.stdin.buffer.read()
    if not payload:
        print("webhook: no input on stdin; nothing to POST", file=sys.stderr)
        return 2

    req = urllib.request.Request(args.url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        k, _, v = h.partition(":")
        k = k.strip()
        v = v.strip()
        if not k:
            print(
                f"webhook: invalid --header {h!r}: header name must not be empty",
                file=sys.stderr,
            )
            return 2
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except urllib.error.HTTPError as e:
        print(f"webhook error: HTTP {e.code} {e.reason}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"webhook error: {e.reason}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"webhook error: {e}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
