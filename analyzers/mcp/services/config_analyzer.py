"""Configuration analysis service for MCP files."""

import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType
from ..detectors.injection_detector import InjectionDetector

logger = logging.getLogger(__name__)


class ConfigAnalyzer:
    """Analyzes MCP configuration files for security issues."""
    
    def __init__(self):
        self.injection_detector = InjectionDetector()
    
    def analyze_mcp_config(self, config: Dict[str, Any],
                          config_file: str) -> List[Finding]:
        """
        Analyze complete MCP configuration.
        
        Args:
            config: MCP configuration dictionary
            config_file: Path to config file
            
        Returns:
            List of findings
        """
        findings = []
        
        # Analyze tools
        if 'tools' in config:
            findings.extend(self._analyze_tools(config['tools'], config_file))
        
        # Analyze resources
        if 'resources' in config:
            findings.extend(self._analyze_resources(config['resources'], config_file))
        
        # Analyze prompts
        if 'prompts' in config:
            findings.extend(self._analyze_prompts(config['prompts'], config_file))
        
        # Analyze client servers
        if 'mcpServers' in config:
            findings.extend(self._analyze_servers(config['mcpServers'], config_file))
        
        return findings
    
    def _analyze_tools(self, tools: List[Dict], config_file: str) -> List[Finding]:
        """Analyze tool configurations."""
        findings = []
        
        for tool in tools:
            location = f"{config_file}:tool:{tool.get('name', 'unknown')}"
            
            # Check tool description
            if 'description' in tool:
                findings.extend(
                    self.injection_detector.check_text_for_injection(
                        tool['description'], location, "tool"
                    )
                )
            
            # Check input schema
            if 'inputSchema' in tool:
                findings.extend(
                    self._analyze_schema(tool['inputSchema'], location)
                )
            
            # Check for dangerous tool patterns
            findings.extend(
                self._check_dangerous_tool(tool, location)
            )
        
        return findings
    
    def _analyze_resources(self, resources: List[Dict], config_file: str) -> List[Finding]:
        """Analyze resource configurations."""
        findings = []
        
        for resource in resources:
            location = f"{config_file}:resource:{resource.get('name', 'unknown')}"
            
            # Check resource description
            if 'description' in resource:
                findings.extend(
                    self.injection_detector.check_text_for_injection(
                        resource['description'], location, "resource"
                    )
                )
            
            # Check URI patterns
            if 'uri' in resource:
                findings.extend(
                    self._check_dangerous_uri(resource['uri'], location)
                )
        
        return findings
    
    def _analyze_prompts(self, prompts: List[Dict], config_file: str) -> List[Finding]:
        """Analyze prompt configurations."""
        findings = []
        
        for prompt in prompts:
            location = f"{config_file}:prompt:{prompt.get('name', 'unknown')}"
            
            # Check prompt content
            if 'content' in prompt:
                findings.extend(
                    self.injection_detector.check_text_for_injection(
                        prompt['content'], location, "prompt"
                    )
                )
            
            # Check prompt description
            if 'description' in prompt:
                findings.extend(
                    self.injection_detector.check_text_for_injection(
                        prompt['description'], location, "prompt"
                    )
                )
        
        return findings
    
    def _analyze_servers(self, servers: Dict, config_file: str) -> List[Finding]:
        """Analyze MCP server configurations."""
        findings = []
        
        for server_name, server_config in servers.items():
            location = f"{config_file}:server:{server_name}"
            
            # Check for exposed credentials
            if 'env' in server_config:
                findings.extend(
                    self._check_exposed_credentials(server_config['env'], location)
                )
        
        return findings
    
    def _analyze_schema(self, schema: Dict, location: str) -> List[Finding]:
        """Analyze input schema for security issues."""
        findings = []
        
        # Check for injection in schema
        findings.extend(
            self.injection_detector.check_schema_for_injection(schema, location)
        )
        
        # Check for dangerous input types
        if schema.get('type') == 'string' and not schema.get('maxLength'):
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.SCHEMA_INJECTION,
                severity=SeverityLevel.MEDIUM,
                confidence=0.7,
                title="Unbounded string input",
                description="String input without max length can lead to DoS",
                location=location,
                recommendation="Add maxLength constraint to string inputs",
                references=[],
                evidence={"schema": schema},
                tool="mcp_specific"
            ))
        
        return findings
    
    def _check_dangerous_tool(self, tool: Dict, location: str) -> List[Finding]:
        """Check for dangerous tool patterns."""
        findings = []
        dangerous_names = ['eval', 'exec', 'system', 'shell']
        
        tool_name = tool.get('name', '').lower()
        for danger in dangerous_names:
            if danger in tool_name:
                findings.append(Finding(
                    vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    title=f"Dangerous tool name: {tool_name}",
                    description="Tool name suggests dangerous operations",
                    location=location,
                    recommendation="Review tool functionality for security",
                    references=[],
                    evidence={"tool": tool},
                    tool="mcp_specific"
                ))
        
        return findings
    
    def _check_dangerous_uri(self, uri: str, location: str) -> List[Finding]:
        """Check for dangerous URI patterns."""
        findings = []
        
        if uri.startswith('file://'):
            path = uri[7:]
            if '..' in path or path.startswith('/etc/') or path.startswith('/root/'):
                findings.append(Finding(
                    vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                    severity=SeverityLevel.HIGH,
                    confidence=0.85,
                    title="Dangerous file path in resource URI",
                    description=f"Resource accesses sensitive path: {path}",
                    location=location,
                    recommendation="Restrict file access to safe directories",
                    references=[],
                    evidence={"uri": uri},
                    tool="mcp_specific"
                ))
        
        return findings
    
    def _check_exposed_credentials(self, env: Dict, location: str) -> List[Finding]:
        """Check for exposed credentials in environment."""
        findings = []
        sensitive_keys = ['api_key', 'token', 'secret', 'password', 'credential']
        
        for key, value in env.items():
            for sensitive in sensitive_keys:
                if sensitive in key.lower() and value and not value.startswith('${'):
                    findings.append(Finding(
                        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                        severity=SeverityLevel.CRITICAL,
                        confidence=0.9,
                        title=f"Exposed credential: {key}",
                        description="Hardcoded credential in configuration",
                        location=location,
                        recommendation="Use environment variables or secure vaults",
                        references=[],
                        evidence={"key": key},
                        tool="mcp_specific"
                    ))
        
        return findings