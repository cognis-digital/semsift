"""SEMSIFT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from semsift.core import findings_to_dicts, scan_diff_text


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-semsift[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-semsift[mcp]'")
        return 1
    app = FastMCP("semsift")

    @app.tool()
    def semsift_scan(diff_text: str) -> str:
        """Scan the added lines of a unified diff for security findings.

        Accepts the text of a unified diff and returns JSON-encoded findings.
        Returns JSON findings.
        """
        if not isinstance(diff_text, str) or not diff_text.strip():
            return json.dumps({"findings": [], "finding_count": 0})
        findings = scan_diff_text(diff_text)
        return json.dumps(
            {"findings": findings_to_dicts(findings), "finding_count": len(findings)},
            indent=2,
        )

    app.run()
    return 0
