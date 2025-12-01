"""Main MCP analyzer orchestrator with clean architecture."""

import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding
from analyzers.base import BaseAnalyzer
from analyzers.intelligent import IntelligentContextAnalyzer

from .services import (
    ConfigAnalyzer,
    CodeAnalyzer,
    TokenSecurityService,
    RugPullService,
    CommandInjectionService,
    CrossServerService,
    OutputPoisoningService,
    AdvancedPromptInjectionService,
    CapabilityAbuseService,
    ConfigFileService,
    SecurityPipelineService,
    SourceCodeService,
    IntelligentFilteringService
)
from .detectors.injection_detector import InjectionDetector
from .detectors.permission_detector import PermissionDetector

logger = logging.getLogger(__name__)


class MCPSpecificAnalyzer(BaseAnalyzer):
    """
    Clean architecture MCP security analyzer.

    Orchestrates specialized services to detect:
    - Tool Poisoning Attacks (TPAs)
    - Prompt injection vulnerabilities
    - Permission abuse patterns
    - Configuration security issues
    """

    def __init__(self):
        super().__init__()
        self._init_core_services()
        self._init_security_services()
        self._init_orchestration_services()

    def _init_core_services(self):
        """Initialize core analysis services."""
        self.config_analyzer = ConfigAnalyzer()
        self.code_analyzer = CodeAnalyzer()
        self.injection_detector = InjectionDetector()
        self.permission_detector = PermissionDetector()
        self.intelligent_analyzer = IntelligentContextAnalyzer()

    def _init_security_services(self):
        """Initialize advanced security services."""
        self.token_security = TokenSecurityService()
        self.rug_pull_service = RugPullService()
        self.command_injection = CommandInjectionService()
        self.cross_server = CrossServerService()
        self.output_poisoning = OutputPoisoningService()
        self.prompt_injection = AdvancedPromptInjectionService()
        self.capability_abuse = CapabilityAbuseService()

    def _init_orchestration_services(self):
        """Initialize orchestration services."""
        self.config_file_service = ConfigFileService(self.config_analyzer)
        self.source_code_service = SourceCodeService(self.code_analyzer)
        self.filtering_service = IntelligentFilteringService(self.intelligent_analyzer)
        self.security_pipeline = SecurityPipelineService(
            self.token_security, self.rug_pull_service, self.command_injection,
            self.cross_server, self.output_poisoning, self.prompt_injection,
            self.capability_abuse
        )

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Check if MCP analysis is applicable."""
        return project_info.get('is_mcp', False)

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Main analysis orchestration method."""
        findings = []
        repo = Path(repo_path)

        # Core analysis
        findings.extend(self.config_file_service.analyze_configs(repo))
        findings.extend(self.source_code_service.analyze_source_files(repo))

        # Advanced security analysis
        findings.extend(await self.security_pipeline.run_all_analyses(repo_path))

        # Apply intelligent context filtering
        findings = self.filtering_service.filter_findings(findings, repo_path)

        logger.info(f"MCP analysis found {len(findings)} security issues")
        return findings
