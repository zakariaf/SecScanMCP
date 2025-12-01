"""Capability and tool abuse detection service."""

import logging
from pathlib import Path
from typing import List

from models import Finding
from .capability_abuse import (
    ConfigCapabilityChecker,
    CodeCapabilityChecker,
    AccessPatternChecker,
    ToolChecker,
)

logger = logging.getLogger(__name__)


class CapabilityAbuseService:
    """Detects capability leakage and tool abuse vulnerabilities."""

    def __init__(self):
        self.config_checker = ConfigCapabilityChecker()
        self.code_checker = CodeCapabilityChecker()
        self.access_checker = AccessPatternChecker()
        self.tool_checker = ToolChecker()

    async def check_capability_leakage(self, repo_path: str) -> List[Finding]:
        """Check for capability leakage vulnerabilities."""
        findings = []
        repo = Path(repo_path)

        findings.extend(self.config_checker.check(repo))
        findings.extend(self.code_checker.check(repo))
        findings.extend(self.access_checker.check(repo))

        return findings

    async def check_tool_abuse_potential(self, repo_path: str) -> List[Finding]:
        """Check for tool abuse potential."""
        findings = []
        repo = Path(repo_path)

        findings.extend(self.tool_checker.check_implementations(repo))
        findings.extend(self.tool_checker.check_resource_patterns(repo))
        findings.extend(self.tool_checker.check_shadowing(repo))

        return findings
