"""SEMSIFT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from semsift.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-semsift[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-semsift[mcp]'")
        return 1
    app = FastMCP("semsift")

    @app.tool()
    def semsift_scan(target: str) -> str:
        """Lightweight semantic-aware SAST that runs curated taint rules over diffs only, so PRs get fast incremental SAST instead of whole-repo scan fatigue.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
