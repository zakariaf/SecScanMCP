"""Config file loading and analysis service."""

import json
import yaml
import logging
from pathlib import Path
from typing import List

from models import Finding

logger = logging.getLogger(__name__)


class ConfigFileService:
    """Handles MCP configuration file discovery and loading."""

    CONFIG_PATTERNS = [
        'mcp.json', 'mcp.yaml', 'mcp.yml',
        '.mcp/*', 'config/mcp.*'
    ]

    def __init__(self, config_analyzer):
        self.config_analyzer = config_analyzer

    def analyze_configs(self, repo: Path) -> List[Finding]:
        """Analyze all MCP configuration files in repository."""
        findings = []
        for pattern in self.CONFIG_PATTERNS:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._analyze_file(config_file))
        return findings

    def _analyze_file(self, config_file: Path) -> List[Finding]:
        """Analyze single configuration file."""
        try:
            content = config_file.read_text()
            config = self._parse_config(config_file, content)
            if config is None:
                return []
            return self.config_analyzer.analyze_mcp_config(config, str(config_file))
        except Exception as e:
            logger.error(f"Error analyzing {config_file}: {e}")
            return []

    def _parse_config(self, config_file: Path, content: str):
        """Parse config file based on extension."""
        if config_file.suffix == '.json':
            return json.loads(content)
        elif config_file.suffix in ['.yaml', '.yml']:
            return yaml.safe_load(content)
        return None
