"""Advanced prompt injection analysis service."""

import logging
from pathlib import Path
from typing import List

from models import Finding
from .prompt_injection import ConfigPromptAnalyzer, CodePromptAnalyzer

logger = logging.getLogger(__name__)


class AdvancedPromptInjectionService:
    """Detects advanced prompt injection vulnerabilities."""

    def __init__(self):
        self.config_analyzer = ConfigPromptAnalyzer()
        self.code_analyzer = CodePromptAnalyzer()

    async def analyze_resource_prompt_injection(self, repo_path: str) -> List[Finding]:
        """Analyze resource configurations for prompt injection."""
        findings = []
        repo = Path(repo_path)

        findings.extend(self.config_analyzer.analyze(repo))
        findings.extend(self.code_analyzer.analyze_resources(repo))

        return findings

    async def analyze_indirect_prompt_injection(self, repo_path: str) -> List[Finding]:
        """Analyze for indirect prompt injection vulnerabilities."""
        findings = []
        repo = Path(repo_path)

        findings.extend(self.code_analyzer.analyze_tools(repo))
        findings.extend(self.code_analyzer.analyze_data_processors(repo))

        return findings
