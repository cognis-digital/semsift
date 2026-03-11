# Demo 01 - Basic differential SAST on a PR diff

This demo shows SEMSIFT doing its core job: scanning **only the added lines**
of a unified diff and reporting security findings, while ignoring pre-existing
code and removed lines.

## Input

`sample.diff` is a small git-style unified diff that simulates a pull request
touching a Python web handler. The PR:

- **adds** a SQL query built with f-string interpolation (SQL injection),
- **adds** an `os.system(...)` call with `shell`-style interpolation
  (command injection),
- **adds** a hardcoded API key,
- **adds** a benign, safe parameterized query (should NOT be flagged),
- **removes** an old line and keeps some context lines (must be ignored).

## Run it

```bash
# Human-readable table
python -m semsift scan demos/01-basic/sample.diff

# JSON for CI, fail the build on high+ findings
python -m semsift scan demos/01-basic/sample.diff --format json --fail-on high
```

## Expected result

SEMSIFT reports **3 findings**, all on added lines:

| rule_id                | severity  | file       | why |
|------------------------|-----------|------------|-----|
| `py.sql-injection`     | critical  | `app.py`   | f-string SQL query |
| `py.command-injection` | critical  | `app.py`   | `os.system` with interpolation |
| `generic.hardcoded-secret` | high  | `app.py`   | hardcoded `api_key = "..."` |

The safe parameterized query (`cursor.execute("... WHERE id = ?", (uid,))`),
the context lines, and the removed line are **not** flagged. The reported line
numbers correspond to the **new** (post-image) file.

Because there are findings at/above the threshold, the process exits with code
`1` -- which is exactly what a CI gate keys off of.
