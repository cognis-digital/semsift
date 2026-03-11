"""Smoke tests for SEMSIFT. No network. Runs the engine on the bundled demo."""

import json
import os
import subprocess
import sys

import pytest

from semsift import (
    TOOL_NAME,
    TOOL_VERSION,
    parse_unified_diff,
    scan_diff_text,
    findings_to_dicts,
)
from semsift.cli import main, _count_at_or_above
from semsift.core import scan_added_lines, AddedLine


DEMO_DIFF = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "sample.diff",
)


def _load_demo():
    with open(DEMO_DIFF, "r", encoding="utf-8") as fh:
        return fh.read()


def test_metadata():
    assert TOOL_NAME == "semsift"
    assert TOOL_VERSION


def test_parse_only_added_lines():
    diff = _load_demo()
    added = parse_unified_diff(diff)
    # Every parsed line must be an added line tied to app.py.
    assert added
    assert all(isinstance(a, AddedLine) for a in added)
    assert all(a.file == "app.py" for a in added)
    # The removed line 'legacy = lookup(uid)' must never appear.
    assert all("lookup(uid)" not in a.text for a in added)


def test_line_numbers_are_post_image():
    diff = _load_demo()
    added = parse_unified_diff(diff)
    by_text = {a.text.strip(): a.new_line for a in added}
    # api_key is the first added line; hunk starts at new line 10.
    assert any("api_key" in t for t in by_text)
    # All reported line numbers are positive and within a sane range.
    assert all(a.new_line >= 10 for a in added)


def test_findings_on_demo():
    findings = scan_diff_text(_load_demo())
    rule_ids = {f.rule_id for f in findings}
    assert "py.sql-injection" in rule_ids
    assert "py.command-injection" in rule_ids
    assert "generic.hardcoded-secret" in rule_ids
    # Exactly three real findings expected.
    assert len(findings) == 3


def test_safe_parameterized_query_not_flagged():
    findings = scan_diff_text(_load_demo())
    for f in findings:
        assert "(uid,)" not in f.snippet, "parameterized query should be safe"


def test_severity_gating():
    findings = scan_diff_text(_load_demo())
    assert _count_at_or_above(findings, "critical") == 2
    assert _count_at_or_above(findings, "high") == 3
    assert _count_at_or_above(findings, "low") == 3


def test_clean_diff_has_no_findings():
    clean = (
        "diff --git a/ok.py b/ok.py\n"
        "--- a/ok.py\n"
        "+++ b/ok.py\n"
        "@@ -1,0 +1,2 @@\n"
        "+def add(a, b):\n"
        "+    return a + b\n"
    )
    assert scan_diff_text(clean) == []


def test_findings_to_dicts_shape():
    findings = scan_diff_text(_load_demo())
    dicts = findings_to_dicts(findings)
    assert dicts
    for d in dicts:
        assert set(d) == {
            "rule_id",
            "severity",
            "message",
            "file",
            "line",
            "cwe",
            "snippet",
        }


def test_scan_added_lines_directly():
    lines = [
        AddedLine("x.py", 1, 'eval("1+1")'),
        AddedLine("x.py", 2, "x = 1  # harmless"),
    ]
    findings = scan_added_lines(lines)
    assert len(findings) == 1
    assert findings[0].rule_id == "py.eval-exec"


def test_cli_exit_code_and_json(capsys):
    rc = main(["scan", DEMO_DIFF, "--format", "json", "--fail-on", "high"])
    assert rc == 1  # findings present -> CI gate trips
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload["tool"] == "semsift"
    assert payload["finding_count"] == 3
    assert len(payload["findings"]) == 3


def test_cli_fail_on_threshold_passes_when_below(capsys):
    # A diff whose only finding is 'medium' should pass a 'critical' gate.
    diff = (
        "diff --git a/h.py b/h.py\n"
        "--- a/h.py\n"
        "+++ b/h.py\n"
        "@@ -1,0 +1,1 @@\n"
        "+digest = hashlib.md5(data).hexdigest()\n"
    )
    import tempfile

    with tempfile.NamedTemporaryFile(
        "w", suffix=".diff", delete=False, encoding="utf-8"
    ) as tf:
        tf.write(diff)
        path = tf.name
    try:
        rc = main(["scan", path, "--fail-on", "critical"])
        assert rc == 0  # md5 is 'medium', below 'critical' gate
        rc2 = main(["scan", path, "--fail-on", "medium"])
        assert rc2 == 1
    finally:
        os.unlink(path)


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert TOOL_VERSION in capsys.readouterr().out


def test_module_entrypoint_runs():
    # Ensure 'python -m semsift' is wired up and exits non-zero on findings.
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    proc = subprocess.run(
        [sys.executable, "-m", "semsift", "scan", DEMO_DIFF, "--format", "json"],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    data = json.loads(proc.stdout)
    assert data["finding_count"] == 3
