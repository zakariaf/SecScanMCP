"""
Main OpenGrep Static Analysis Analyzer

Orchestrates OpenGrep-based pattern matching static analysis
Following clean architecture principles with ≤100 lines per file
"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from ..base import BaseAnalyzer
from models import Finding
from .services.rule_service import RuleService
from .services.command_service import CommandService  
from .services.parser_service import ParserService

logger = logging.getLogger(__name__)


class OpenGrepAnalyzer(BaseAnalyzer):
    """Clean orchestrator for OpenGrep static analysis"""
    
    def __init__(self):
        super().__init__()
        self.rule_service = RuleService()
        self.command_service = CommandService()
        self.parser_service = ParserService(self.rule_service)
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run OpenGrep analysis on the repository"""
        findings = []
        ignore_file = None
        
        try:
            self.log_scan_summary(repo_path)
            
            # Create custom rules and ignore files
            custom_rules_file = self.rule_service.create_custom_rules_file()
            ignore_file = self.create_ignore_file(repo_path)
            
            # Run standard rulesets
            findings.extend(await self._run_standard_rulesets(repo_path, ignore_file))
            
            # Run custom MCP rules
            if custom_rules_file:
                findings.extend(await self._run_custom_rules(repo_path, custom_rules_file, ignore_file))
            
            self.logger.info(f"OpenGrep found {len(findings)} issues")
            return findings
            
        except Exception as e:
            self.logger.error(f"OpenGrep analysis failed: {e}")
            return []
        finally:
            self._cleanup_files(ignore_file)
            self.rule_service.cleanup_custom_rules_file()
    
    async def _run_standard_rulesets(self, repo_path: str, ignore_file: str) -> List[Finding]:
        """Run OpenGrep with standard rulesets"""
        findings = []
        rulesets = self.rule_service.get_standard_rulesets()
        
        for ruleset in rulesets:
            success, output = await self.command_service.run_with_ruleset(
                repo_path, ruleset, ignore_file
            )
            
            if success and output:
                ruleset_findings = self.parser_service.parse_opengrep_output(output)
                findings.extend(ruleset_findings)
                self.logger.debug(f"Ruleset {ruleset}: {len(ruleset_findings)} findings")
        
        return findings
    
    async def _run_custom_rules(self, repo_path: str, rules_file: str, ignore_file: str) -> List[Finding]:
        """Run OpenGrep with custom MCP rules"""
        success, output = await self.command_service.run_with_custom_rules(
            repo_path, rules_file, ignore_file
        )
        
        if success and output:
            custom_findings = self.parser_service.parse_opengrep_output(output)
            self.logger.debug(f"Custom rules: {len(custom_findings)} findings")
            return custom_findings
        
        return []
    
    def _cleanup_files(self, ignore_file: str):
        """Clean up temporary files"""
        if ignore_file and Path(ignore_file).exists():
            Path(ignore_file).unlink()