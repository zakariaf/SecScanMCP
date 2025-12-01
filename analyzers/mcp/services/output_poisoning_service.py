"""Output poisoning vulnerability analysis service."""

import logging
from pathlib import Path
from typing import List

from models import Finding
from .output_poisoning import ToolOutputAnalyzer, TemplateAnalyzer, ConfigAnalyzer

logger = logging.getLogger(__name__)


class OutputPoisoningService:
    """Detects output poisoning vulnerabilities in MCP tool responses."""

    def __init__(self):
        self.tool_analyzer = ToolOutputAnalyzer()
        self.template_analyzer = TemplateAnalyzer()
        self.config_analyzer = ConfigAnalyzer()

    async def analyze_output_poisoning(self, repo_path: str) -> List[Finding]:
        """Analyze repository for output poisoning vulnerabilities."""
        findings = []
        repo = Path(repo_path)

        findings.extend(self.tool_analyzer.analyze(repo))
        findings.extend(self.template_analyzer.analyze(repo))
        findings.extend(self.config_analyzer.analyze(repo))

        return findings
