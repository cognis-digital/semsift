"""Hardening tests: error paths, edge cases, and input validation.

These tests verify the new defensive behaviour added to cli.py, core.py,
mcp_server.py, and integrations/webhook.py.  They complement the existing
smoke suite without modifying it.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile

import pytest

from semsift.cli import main, _read_diff
from semsift.core import scan_diff_text, parse_unified_diff, AddedLine, scan_added_lines


# ---------------------------------------------------------------------------
# core.py edge cases
# ---------------------------------------------------------------------------


def test_scan_diff_text_empty_string():
    """Empty diff must return an empty list, not raise."""
    assert scan_diff_text("") == []


def test_scan_diff_text_whitespace_only():
    """Whitespace-only diff must return an empty list."""
    assert scan_diff_text("   \n\t\n  ") == []


def test_scan_diff_text_rejects_none():
    """Passing None must raise TypeError with a clear message."""
    with pytest.raises(TypeError, match="scan_diff_text expects a str"):
        scan_diff_text(None)  # type: ignore[arg-type]


def test_scan_diff_text_rejects_non_string():
    """Passing bytes must raise TypeError."""
    with pytest.raises(TypeError, match="scan_diff_text expects a str"):
        scan_diff_text(b"diff --git a/x b/x\n")  # type: ignore[arg-type]


def test_parse_unified_diff_empty():
    """parse_unified_diff on an empty string returns an empty list."""
    assert parse_unified_diff("") == []


def test_scan_added_lines_empty_iterable():
    """scan_added_lines on an empty list returns an empty list."""
    assert scan_added_lines([]) == []


def test_scan_added_lines_blank_line_skipped():
    """Blank added lines must be skipped without raising."""
    lines = [AddedLine("x.py", 1, "   ")]
    assert scan_added_lines(lines) == []


# ---------------------------------------------------------------------------
# cli.py error paths
# ---------------------------------------------------------------------------


def test_cli_missing_file_returns_exit_2(capsys):
    """A nonexistent diff file must print an error to stderr and return 2."""
    rc = main(["scan", "/nonexistent/path/does_not_exist.diff"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "semsift: error:" in err
    assert "does_not_exist.diff" in err


def test_cli_no_subcommand_returns_zero(capsys):
    """Running semsift with no subcommand prints help and returns 0."""
    rc = main([])
    assert rc == 0


def test_cli_empty_diff_file_returns_zero(capsys):
    """An empty diff file produces zero findings and returns exit 0."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".diff", delete=False, encoding="utf-8"
    ) as tf:
        tf.write("")
        path = tf.name
    try:
        rc = main(["scan", path, "--fail-on", "low"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "no findings" in out
    finally:
        os.unlink(path)


def test_cli_empty_diff_json_output(capsys):
    """An empty diff with --format json returns valid JSON with finding_count=0."""
    with tempfile.NamedTemporaryFile(
        "w", suffix=".diff", delete=False, encoding="utf-8"
    ) as tf:
        tf.write("")
        path = tf.name
    try:
        rc = main(["scan", path, "--format", "json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["finding_count"] == 0
        assert payload["findings"] == []
    finally:
        os.unlink(path)


def test_read_diff_nonexistent_raises():
    """_read_diff must raise RuntimeError for a missing file."""
    with pytest.raises(RuntimeError, match="could not read diff file"):
        _read_diff("/nonexistent/totally_missing.diff", None)


# ---------------------------------------------------------------------------
# mcp_server.py: module must import cleanly (no ImportError on scan/to_json)
# ---------------------------------------------------------------------------


def test_mcp_server_imports_cleanly():
    """mcp_server module must import without raising ImportError."""
    import importlib
    mod = importlib.import_module("semsift.mcp_server")
    assert callable(mod.serve)


# ---------------------------------------------------------------------------
# integrations/webhook.py edge cases (no network)
# ---------------------------------------------------------------------------


def test_webhook_invalid_header_returns_2():
    """A --header value without ':' must print an error and return 2."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [
            sys.executable,
            os.path.join(root, "integrations", "webhook.py"),
            "--url", "http://127.0.0.1:19999/nowhere",
            "--header", "BadHeader",
        ],
        input=b'{"findings":[]}',
        capture_output=True,
        cwd=root,
    )
    assert proc.returncode == 2
    assert b"BadHeader" in proc.stderr
