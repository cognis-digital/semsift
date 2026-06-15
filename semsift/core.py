"""Core engine for SEMSIFT differential SAST.

The engine has two real parts:

1. A unified-diff parser that extracts *added* lines together with their
   post-image (new) line numbers and the file they belong to. Only added
   lines are analyzed -- that is what makes the scan "differential".

2. A pattern/taint rule set. Most rules are compiled regular expressions, but
   a couple of rules implement light taint tracking *within a single added
   line* (e.g. a tainted source like ``request.args`` flowing into a dangerous
   sink like an f-string SQL query or ``os.system``).

No third-party imports. No network. Pure standard library.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, List, Optional, Sequence


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class AddedLine:
    """A single added line extracted from a unified diff."""

    file: str
    new_line: int  # line number in the post-image (new) file, 1-based
    text: str      # the added line content (without the leading '+')


@dataclass(frozen=True)
class Finding:
    """A single rule match on an added line."""

    rule_id: str
    severity: str
    message: str
    file: str
    new_line: int
    snippet: str
    cwe: str = ""


@dataclass
class Rule:
    """A detection rule.

    A rule either supplies a compiled regex ``pattern`` or a ``matcher``
    callable that returns True when the (stripped) line is a finding. The
    matcher form is used for the small taint rules.
    """

    rule_id: str
    severity: str
    message: str
    cwe: str = ""
    pattern: Optional[re.Pattern] = None
    matcher: Optional[Callable[[str], bool]] = None
    # Languages this rule applies to, matched by file extension. Empty = any.
    extensions: Sequence[str] = field(default_factory=tuple)

    def applies_to(self, filename: str) -> bool:
        if not self.extensions:
            return True
        lower = filename.lower()
        return any(lower.endswith(ext) for ext in self.extensions)

    def test(self, line: str) -> bool:
        if self.matcher is not None:
            return self.matcher(line)
        if self.pattern is not None:
            return self.pattern.search(line) is not None
        return False


# --------------------------------------------------------------------------- #
# Taint helpers
# --------------------------------------------------------------------------- #

# Common tainted sources seen in web/back-end code.
_TAINT_SOURCES = re.compile(
    r"\b(request\.(args|form|values|json|data|cookies|headers|GET|POST)"
    r"|input\s*\(|sys\.argv|os\.environ|flask\.request|self\.request)\b"
)

# String formatting that mixes data into a command/query.
_FORMAT_FLOW = re.compile(r"(%[sdr]|\.format\s*\(|\+\s*\w|f['\"]|\{\w*\})")


def _taint_sql_injection(line: str) -> bool:
    """Heuristic taint: a SQL-ish statement built by string formatting.

    Flags lines that both look like SQL and use interpolation/concatenation.
    """
    has_sql = re.search(
        r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b", line, re.IGNORECASE
    )
    if not has_sql:
        return False
    has_exec = re.search(r"\b(execute|executemany|executescript|cursor)\b", line)
    return bool(_FORMAT_FLOW.search(line) and (has_exec or has_sql))


def _taint_command_injection(line: str) -> bool:
    """Heuristic taint: a shell sink that receives interpolated/tainted data."""
    sink = re.search(
        r"\b(os\.system|os\.popen|subprocess\.(call|run|Popen|check_output))\b",
        line,
    )
    if not sink:
        return False
    if "shell=True" in line:
        return True
    # Tainted source flowing into the sink, or formatted command string.
    return bool(_TAINT_SOURCES.search(line) or _FORMAT_FLOW.search(line))


# --------------------------------------------------------------------------- #
# Rule set
# --------------------------------------------------------------------------- #

RULES: List[Rule] = [
    Rule(
        rule_id="py.eval-exec",
        severity="high",
        message="Use of eval()/exec() can execute arbitrary code.",
        cwe="CWE-95",
        pattern=re.compile(r"(?<![\w.])(eval|exec)\s*\("),
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.sql-injection",
        severity="critical",
        message="Possible SQL injection: query built with string formatting.",
        cwe="CWE-89",
        matcher=_taint_sql_injection,
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.command-injection",
        severity="critical",
        message="Possible command injection via shell/subprocess with tainted or formatted input.",
        cwe="CWE-78",
        matcher=_taint_command_injection,
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.yaml-unsafe-load",
        severity="high",
        message="yaml.load() without SafeLoader can instantiate arbitrary objects.",
        cwe="CWE-502",
        pattern=re.compile(r"yaml\.load\s*\((?![^)]*Safe)"),
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.pickle-loads",
        severity="high",
        message="pickle.load/loads on untrusted data enables code execution.",
        cwe="CWE-502",
        pattern=re.compile(r"pickle\.loads?\s*\("),
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.weak-hash",
        severity="medium",
        message="Weak hash algorithm (md5/sha1) used; prefer sha256+.",
        cwe="CWE-327",
        pattern=re.compile(r"hashlib\.(md5|sha1)\s*\("),
        extensions=(".py",),
    ),
    Rule(
        rule_id="py.requests-no-verify",
        severity="medium",
        message="TLS verification disabled (verify=False).",
        cwe="CWE-295",
        pattern=re.compile(r"verify\s*=\s*False"),
        extensions=(".py",),
    ),
    Rule(
        rule_id="generic.hardcoded-secret",
        severity="high",
        message="Hardcoded secret/credential assigned in source.",
        cwe="CWE-798",
        pattern=re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|token|access[_-]?key)\b"
            r"\s*[:=]\s*['\"][^'\"]{6,}['\"]"
        ),
    ),
    Rule(
        rule_id="generic.private-key",
        severity="critical",
        message="Private key material committed to source.",
        cwe="CWE-798",
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    Rule(
        rule_id="generic.aws-access-key",
        severity="critical",
        message="AWS access key id committed to source.",
        cwe="CWE-798",
        pattern=re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    Rule(
        rule_id="js.eval",
        severity="high",
        message="Use of eval() in JavaScript can execute arbitrary code.",
        cwe="CWE-95",
        pattern=re.compile(r"(?<![\w.])eval\s*\("),
        extensions=(".js", ".ts", ".jsx", ".tsx"),
    ),
    Rule(
        rule_id="js.innerhtml",
        severity="medium",
        message="Assignment to innerHTML can introduce DOM XSS.",
        cwe="CWE-79",
        pattern=re.compile(r"\.innerHTML\s*="),
        extensions=(".js", ".ts", ".jsx", ".tsx", ".html"),
    ),
]


# --------------------------------------------------------------------------- #
# Diff parsing
# --------------------------------------------------------------------------- #

_DIFF_GIT_RE = re.compile(r"^diff --git a/(?P<a>.+?) b/(?P<b>.+)$")
_PLUSPLUS_RE = re.compile(r"^\+\+\+ (?:b/)?(?P<path>.+?)\s*$")
_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(?P<start>\d+)(?:,\d+)? @@")


def parse_unified_diff(diff_text: str) -> List[AddedLine]:
    """Parse a unified/git diff and return every added line.

    Tracks the current target file (from ``+++ b/...`` or ``diff --git`` lines)
    and the running new-file line number (from ``@@`` hunk headers), so each
    added line is reported with an accurate post-image line number.
    """
    added: List[AddedLine] = []
    current_file: Optional[str] = None
    new_lineno = 0
    in_hunk = False

    for raw in diff_text.splitlines():
        m = _DIFF_GIT_RE.match(raw)
        if m:
            current_file = m.group("b")
            in_hunk = False
            continue

        m = _PLUSPLUS_RE.match(raw)
        if m:
            path = m.group("path")
            if path != "/dev/null":
                current_file = path
            in_hunk = False
            continue

        if raw.startswith("--- "):
            # old-file header; ignore but reset hunk state
            in_hunk = False
            continue

        m = _HUNK_RE.match(raw)
        if m:
            new_lineno = int(m.group("start"))
            in_hunk = True
            continue

        if not in_hunk:
            continue

        if raw.startswith("+"):
            # Added line. Strip the leading '+'.
            content = raw[1:]
            if current_file is not None:
                added.append(
                    AddedLine(file=current_file, new_line=new_lineno, text=content)
                )
            new_lineno += 1
        elif raw.startswith("-"):
            # Removed line: present in old file only; new line number unchanged.
            continue
        elif raw.startswith("\\"):
            # "\ No newline at end of file" marker; ignore.
            continue
        else:
            # Context line (starts with space, or empty): advances new file.
            new_lineno += 1

    return added


# --------------------------------------------------------------------------- #
# Scanning
# --------------------------------------------------------------------------- #


def scan_added_lines(
    added: Iterable[AddedLine], rules: Optional[Sequence[Rule]] = None
) -> List[Finding]:
    """Run every applicable rule against each added line."""
    if rules is None:
        rules = RULES
    findings: List[Finding] = []
    for al in added:
        stripped = al.text.strip()
        if not stripped:
            continue
        for rule in rules:
            if not rule.applies_to(al.file):
                continue
            if rule.test(al.text):
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        message=rule.message,
                        file=al.file,
                        new_line=al.new_line,
                        snippet=stripped[:200],
                        cwe=rule.cwe,
                    )
                )
    # Stable, useful ordering: file, then line, then severity desc.
    findings.sort(
        key=lambda f: (f.file, f.new_line, -SEVERITY_ORDER.get(f.severity, 0))
    )
    return findings


def scan_diff_text(
    diff_text: str, rules: Optional[Sequence[Rule]] = None
) -> List[Finding]:
    """Convenience: parse a diff and scan its added lines in one call.

    Returns an empty list for empty/whitespace-only input.  Raises
    ``TypeError`` if *diff_text* is not a string.
    """
    if not isinstance(diff_text, str):
        raise TypeError(
            f"scan_diff_text expects a str, got {type(diff_text).__name__!r}"
        )
    if not diff_text.strip():
        return []
    return scan_added_lines(parse_unified_diff(diff_text), rules)


def findings_to_dicts(findings: Sequence[Finding]) -> List[dict]:
    """Serialize findings to plain dicts (for JSON output)."""
    return [
        {
            "rule_id": f.rule_id,
            "severity": f.severity,
            "message": f.message,
            "file": f.file,
            "line": f.new_line,
            "cwe": f.cwe,
            "snippet": f.snippet,
        }
        for f in findings
    ]
