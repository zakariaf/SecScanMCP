"""Main MCP analyzer orchestrator with clean architecture."""

import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding
from analyzers.base import BaseAnalyzer
from analyzers.intelligent import IntelligentContextAnalyzer

from .services.config_analyzer import ConfigAnalyzer
from .services.code_analyzer import CodeAnalyzer
from .services.token_security_service import TokenSecurityService
from .services.rug_pull_service import RugPullService
from .services.command_injection_service import CommandInjectionService
from .services.cross_server_service import CrossServerService
from .services.output_poisoning_service import OutputPoisoningService
from .services.advanced_prompt_injection_service import AdvancedPromptInjectionService
from .services.capability_abuse_service import CapabilityAbuseService
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
        # Initialize core services
        self.config_analyzer = ConfigAnalyzer()
        self.code_analyzer = CodeAnalyzer()
        self.injection_detector = InjectionDetector()
        self.permission_detector = PermissionDetector()
        
        # Initialize advanced security services
        self.token_security = TokenSecurityService()
        self.rug_pull_service = RugPullService()
        self.command_injection = CommandInjectionService()
        self.cross_server = CrossServerService()
        self.output_poisoning = OutputPoisoningService()
        self.prompt_injection = AdvancedPromptInjectionService()
        self.capability_abuse = CapabilityAbuseService()
        
        # Initialize intelligent analyzer
        self.intelligent_analyzer = IntelligentContextAnalyzer()
    
    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Check if MCP analysis is applicable."""
        return project_info.get('is_mcp', False)
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """
        Main analysis orchestration method.
        
        Args:
            repo_path: Path to repository
            project_info: Project information
            
        Returns:
            List of security findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Core analysis (existing)
        findings.extend(self._analyze_configs(repo))
        findings.extend(self._analyze_source_code(repo))
        
        # Advanced security analysis
        findings.extend(await self._analyze_token_security(repo_path))
        findings.extend(await self._analyze_rug_pull_risks(repo_path))
        findings.extend(await self._analyze_command_injection(repo_path))
        findings.extend(await self._analyze_cross_server_risks(repo_path))
        findings.extend(await self._analyze_output_poisoning(repo_path))
        findings.extend(await self._analyze_prompt_injection(repo_path))
        findings.extend(await self._analyze_capability_abuse(repo_path))
        
        # Apply intelligent context filtering
        findings = self._apply_intelligent_filtering(findings, repo_path)
        
        logger.info(f"MCP analysis found {len(findings)} security issues")
        return findings
    
    def _analyze_configs(self, repo: Path) -> List[Finding]:
        """Analyze MCP configuration files."""
        findings = []
        
        # Common MCP config files
        config_patterns = [
            'mcp.json', 'mcp.yaml', 'mcp.yml',
            '.mcp/*', 'config/mcp.*'
        ]
        
        for pattern in config_patterns:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._analyze_config_file(config_file))
        
        return findings
    
    def _analyze_config_file(self, config_file: Path) -> List[Finding]:
        """Analyze single configuration file."""
        try:
            content = config_file.read_text()
            
            if config_file.suffix in ['.json']:
                config = json.loads(content)
            elif config_file.suffix in ['.yaml', '.yml']:
                config = yaml.safe_load(content)
            else:
                return []
            
            return self.config_analyzer.analyze_mcp_config(
                config, str(config_file)
            )
            
        except Exception as e:
            logger.error(f"Error analyzing {config_file}: {e}")
            return []
    
    def _analyze_source_code(self, repo: Path) -> List[Finding]:
        """Analyze Python source files."""
        findings = []
        
        # Find Python files
        python_files = list(repo.glob('**/*.py'))
        
        for py_file in python_files:
            if self._should_analyze_file(py_file):
                findings.extend(
                    self.code_analyzer.analyze_python_file(py_file)
                )
        
        return findings
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        exclude_patterns = [
            'test_', 'tests/', '__pycache__/',
            'venv/', '.venv/', 'node_modules/'
        ]
        
        file_str = str(file_path)
        return not any(pattern in file_str for pattern in exclude_patterns)
    
    def _apply_intelligent_filtering(self, findings: List[Finding],
                                    repo_path: str) -> List[Finding]:
        """Apply intelligent context analysis to reduce false positives."""
        if not findings:
            return findings
        
        try:
            # Use intelligent analyzer for context
            filtered_findings = []
            
            for finding in findings:
                # Apply context analysis for high-confidence findings
                if finding.confidence > 0.8:
                    filtered_findings.append(finding)
                else:
                    # Apply more sophisticated analysis
                    context_result = self._analyze_with_context(finding, repo_path)
                    if context_result:
                        filtered_findings.append(context_result)
            
            return filtered_findings
            
        except Exception as e:
            logger.error(f"Error in intelligent filtering: {e}")
            return findings
    
    def _analyze_with_context(self, finding: Finding,
                             repo_path: str) -> Finding:
        """Analyze finding with additional context."""
        # For now, return original finding
        # TODO: Integrate with intelligent analyzer
        return finding
    
    # Advanced security analysis methods
    
    async def _analyze_token_security(self, repo_path: str) -> List[Finding]:
        """Analyze OAuth token and credential security."""
        return await self.token_security.analyze_oauth_exposure(repo_path)
    
    async def _analyze_rug_pull_risks(self, repo_path: str) -> List[Finding]:
        """Analyze for rug pull vulnerabilities."""
        return await self.rug_pull_service.analyze_rug_pull_vulnerabilities(repo_path)
    
    async def _analyze_command_injection(self, repo_path: str) -> List[Finding]:
        """Analyze for command injection vulnerabilities."""
        return await self.command_injection.analyze_command_injection(repo_path)
    
    async def _analyze_cross_server_risks(self, repo_path: str) -> List[Finding]:
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