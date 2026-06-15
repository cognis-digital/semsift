"""Command-line interface for SEMSIFT.

Primary subcommand: ``scan`` -- read a unified diff (from a file, stdin, or by
shelling out to ``git diff``) and report SAST findings on the added lines only.

Examples
--------
  # Scan a saved diff, human-readable table
  semsift scan change.diff

  # Scan the current unstaged git changes
  git diff | semsift scan -

  # Or let semsift run git for you (diff against a base ref)
  semsift scan --git HEAD~1

  # JSON for CI pipelines, fail the build on medium+ findings
  semsift scan change.diff --format json --fail-on medium

Exit codes
----------
  0  no findings at/above the --fail-on threshold
  1  findings at/above the threshold (CI gate)
  2  usage / runtime error
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import List, Optional, Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    Finding,
    SEVERITY_ORDER,
    findings_to_dicts,
    scan_diff_text,
)


def _read_diff(source: str, git_base: Optional[str]) -> str:
    if git_base is not None:
        try:
            proc = subprocess.run(
                ["git", "diff", "--unified=0" if False else "--unified=3", git_base],
                capture_output=True,
                text=True,
                check=False,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("git diff timed out after 120 s")
        except FileNotFoundError:
            raise RuntimeError("git executable not found on PATH")
        if proc.returncode != 0:
            raise RuntimeError(
                "git diff failed: " + (proc.stderr.strip() or "unknown error")
            )
        return proc.stdout
    if source == "-":
        return sys.stdin.read()
    try:
        with open(source, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        raise RuntimeError(f"could not read diff file {source!r}: {exc}")


def _render_table(findings: Sequence[Finding]) -> str:
    if not findings:
        return "semsift: no findings on added lines. ✓"
    lines: List[str] = []
    lines.append(f"semsift: {len(findings)} finding(s) on added lines\n")
    sev_w = max(len(f.severity) for f in findings)
    for f in findings:
        loc = f"{f.file}:{f.new_line}"
        cwe = f" [{f.cwe}]" if f.cwe else ""
        lines.append(
            f"  {f.severity.upper():<{sev_w}}  {f.rule_id}{cwe}\n"
            f"      {loc}\n"
            f"      {f.message}\n"
            f"      | {f.snippet}"
        )
    return "\n".join(lines)


def _count_at_or_above(findings: Sequence[Finding], threshold: str) -> int:
    floor = SEVERITY_ORDER[threshold]
    return sum(
        1 for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= floor
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Lightweight taint/pattern SAST that scans ONLY the added lines "
            "in a unified diff (differential SAST for PRs)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  semsift scan change.diff\n"
            "  git diff | semsift scan -\n"
            "  semsift scan --git origin/main --format json --fail-on high\n"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )

    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser(
        "scan",
        help="scan a unified diff for SAST findings on added lines",
        description="Scan the added lines of a unified diff for security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument(
        "diff",
        nargs="?",
        default="-",
        help="path to a unified diff file, or '-' for stdin (default: stdin)",
    )
    scan.add_argument(
        "--git",
        metavar="BASE",
        dest="git_base",
        default=None,
        help="run 'git diff BASE' to produce the diff instead of reading a file",
    )
    scan.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    scan.add_argument(
        "--fail-on",
        choices=tuple(SEVERITY_ORDER.keys()),
        default="low",
        help=(
            "minimum severity that causes a non-zero exit code "
            "(default: low). Use 'critical' to only fail on the worst."
        ),
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    if args.command == "scan":
        try:
            diff_text = _read_diff(args.diff, args.git_base)
        except RuntimeError as exc:
            print(f"semsift: error: {exc}", file=sys.stderr)
            return 2

        try:
            findings = scan_diff_text(diff_text)
        except Exception as exc:  # pragma: no cover
            print(f"semsift: internal error during scan: {exc}", file=sys.stderr)
            return 2

        if args.format == "json":
            payload = {
                "tool": TOOL_NAME,
                "version": TOOL_VERSION,
                "finding_count": len(findings),
                "findings": findings_to_dicts(findings),
            }
            print(json.dumps(payload, indent=2))
        else:
            print(_render_table(findings))

        gating = _count_at_or_above(findings, args.fail_on)
        return 1 if gating > 0 else 0

    parser.print_help()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
