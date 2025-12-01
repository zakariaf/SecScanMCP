"""Runtime detection service for MCP servers."""

import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


class RuntimeDetectionService:
    """Detects runtime configuration for MCP servers."""

    ENTRY_POINT_CANDIDATES = [
        'main.py', 'server.py', 'app.py',
        'mcp_server.py', '__main__.py'
    ]

    def determine_runtime(
        self, project_info: Dict[str, Any], repo_path: str
    ) -> Dict[str, Any]:
        """Determine MCP server runtime configuration."""
        return {
            'language': project_info.get('language', 'python'),
            'entry_point': self._find_entry_point(repo_path),
            'transport': 'stdio',
            'timeout': 30
        }

    def _find_entry_point(self, repo_path: str) -> str:
        """Find the main entry point for the MCP server."""
        repo = Path(repo_path)
        for candidate in self.ENTRY_POINT_CANDIDATES:
            if (repo / candidate).exists():
                return candidate
        return 'main.py'
