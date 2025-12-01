"""Security analysis pipeline service."""

import logging
from typing import List

from models import Finding

logger = logging.getLogger(__name__)


class SecurityPipelineService:
    """Orchestrates all security analysis services."""

    def __init__(
        self, token_security, rug_pull, command_injection,
        cross_server, output_poisoning, prompt_injection, capability_abuse
    ):
        self.token_security = token_security
        self.rug_pull = rug_pull
        self.command_injection = command_injection
        self.cross_server = cross_server
        self.output_poisoning = output_poisoning
        self.prompt_injection = prompt_injection
        self.capability_abuse = capability_abuse

    async def run_all_analyses(self, repo_path: str) -> List[Finding]:
        """Run all security analyses."""
        findings = []
        findings.extend(await self._analyze_token_security(repo_path))
        findings.extend(await self._analyze_rug_pull(repo_path))
        findings.extend(await self._analyze_command_injection(repo_path))
        findings.extend(await self._analyze_cross_server(repo_path))
        findings.extend(await self._analyze_output_poisoning(repo_path))
        findings.extend(await self._analyze_prompt_injection(repo_path))
        findings.extend(await self._analyze_capability_abuse(repo_path))
        return findings

    async def _analyze_token_security(self, repo_path: str) -> List[Finding]:
        """Analyze OAuth token and credential security."""
        return await self.token_security.analyze_oauth_exposure(repo_path)

    async def _analyze_rug_pull(self, repo_path: str) -> List[Finding]:
        """Analyze for rug pull vulnerabilities."""
        return await self.rug_pull.analyze_rug_pull_vulnerabilities(repo_path)

    async def _analyze_command_injection(self, repo_path: str) -> List[Finding]:
        """Analyze for command injection vulnerabilities."""
        return await self.command_injection.analyze_command_injection(repo_path)

    async def _analyze_cross_server(self, repo_path: str) -> List[Finding]:
        """Analyze cross-server contamination risks."""
        return await self.cross_server.analyze_cross_server_risks(repo_path)

    async def _analyze_output_poisoning(self, repo_path: str) -> List[Finding]:
        """Analyze for output poisoning vulnerabilities."""
        return await self.output_poisoning.analyze_output_poisoning(repo_path)

    async def _analyze_prompt_injection(self, repo_path: str) -> List[Finding]:
        """Analyze for advanced prompt injection."""
        findings = []
        findings.extend(
            await self.prompt_injection.analyze_resource_prompt_injection(repo_path)
        )
        findings.extend(
            await self.prompt_injection.analyze_indirect_prompt_injection(repo_path)
        )
        return findings

    async def _analyze_capability_abuse(self, repo_path: str) -> List[Finding]:
        """Analyze for capability abuse and tool misuse."""
        findings = []
        findings.extend(
            await self.capability_abuse.check_capability_leakage(repo_path)
        )
        findings.extend(
            await self.capability_abuse.check_tool_abuse_potential(repo_path)
        )
        return findings
