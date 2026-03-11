# SEMSIFT — Architecture

> Lightweight semantic-aware SAST that runs curated taint rules over diffs only, so PRs get fast incremental SAST instead of whole-repo scan fatigue.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `semsift/core.py`.
- **score** ranks by severity.
- **MCP server** (`semsift mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
