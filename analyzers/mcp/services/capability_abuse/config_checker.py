"""Configuration capability checking service."""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType
from .patterns import CapabilityPatterns

logger = logging.getLogger(__name__)


class ConfigCapabilityChecker:
    """Checks configuration files for capability issues."""

    CONFIG_PATTERNS = ['mcp.json', 'mcp.yaml', 'mcp.yml', '.mcp/**']

    def check(self, repo: Path) -> List[Finding]:
        """Check all config files for capability issues."""
        findings = []
        for pattern in self.CONFIG_PATTERNS:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._analyze_file(config_file))
        return findings

    def _analyze_file(self, config_file: Path) -> List[Finding]:
        """Analyze configuration file."""
        findings = []
        try:
            content = config_file.read_text()
            findings.extend(self._check_patterns(content, config_file))
            findings.extend(self._check_structured(content, config_file))
        except Exception as e:
            logger.warning(f"Error analyzing {config_file}: {e}")
        return findings

    def _check_patterns(self, content: str, config_file: Path) -> List[Finding]:
        """Check content for capability patterns."""
        findings = []
        for pattern_info in CapabilityPatterns.CAPABILITY_PATTERNS:
            for match in re.finditer(pattern_info['pattern'], content):
                findings.append(Finding(
                    title=f"Capability Issue: {pattern_info['title']}",
                    description="Potentially dangerous capability configuration",
                    severity=pattern_info['severity'],
                    vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                    location=str(config_file),
                    code_snippet=self._extract_context(content, match.start()),
                    confidence=0.8,
                    tool="capability_abuse_checker",
                    recommendation="Review and restrict capability configuration"
                ))
        return findings

    def _check_structured(self, content: str, config_file: Path) -> List[Finding]:
        """Check structured config data."""
        try:
            if config_file.suffix == '.json':
                data = json.loads(content)
            elif config_file.suffix in ['.yaml', '.yml']:
                import yaml
                data = yaml.safe_load(content)
            else:
                return []
            return self._analyze_structured(data, str(config_file)) if data else []
        except:
            return []

    def _analyze_structured(self, data: Dict, location: str) -> List[Finding]:
        """Analyze structured configuration data."""
        findings = []
        if isinstance(data, dict):
            if 'tools' in data and isinstance(data['tools'], list):
                for i, tool in enumerate(data['tools']):
                    findings.extend(self._check_tool_perms(tool, f"{location}:tools[{i}]"))
            if 'mcpServers' in data and isinstance(data['mcpServers'], dict):
                for name, cfg in data['mcpServers'].items():
                    findings.extend(self._check_server_env(cfg, f"{location}:mcpServers.{name}"))
        return findings

    def _check_tool_perms(self, tool: Dict, location: str) -> List[Finding]:
        """Check tool permissions."""
        if not isinstance(tool, dict) or 'permissions' not in tool:
            return []
        perms = tool['permissions']
        if isinstance(perms, list) and ('all' in perms or '*' in perms):
            return [Finding(
                title="Overly Broad Tool Permissions",
                description="Tool granted 'all' or wildcard permissions",
                severity=SeverityLevel.HIGH,
                vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                location=location, confidence=0.9,
                tool="capability_abuse_checker",
                recommendation="Apply principle of least privilege to tool permissions"
            )]
        return []

    def _check_server_env(self, server_config: Dict, location: str) -> List[Finding]:
        """Check server environment variables."""
        if not isinstance(server_config, dict) or 'env' not in server_config:
            return []
        findings = []
        env_vars = server_config.get('env', {})
        for var_name, var_value in env_vars.items():
            if f"{var_name}={var_value}" in CapabilityPatterns.DANGEROUS_ENV_VALUES:
                findings.append(Finding(
                    title="Dangerous Environment Variable",
                    description=f"Dangerous env var: {var_name}={var_value}",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                    location=location, confidence=0.7,
                    tool="capability_abuse_checker",
                    recommendation="Remove or secure dangerous environment variables"
                ))
        return findings

    def _extract_context(self, content: str, pos: int, chars: int = 150) -> str:
        """Extract context around position."""
        start = max(0, pos - chars // 2)
        end = min(len(content), pos + chars // 2)
        return content[start:end].strip()
