"""
MCP-specific security analyzer
"""

import json
import yaml
import re
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class MCPSpecificAnalyzer(BaseAnalyzer):
    """
    Analyzes MCP-specific security vulnerabilities:
    - Tool poisoning
    - Prompt injection in tool descriptions
    - Schema injection
    - Permission abuse
    """

    # Patterns that indicate prompt injection
    INJECTION_PATTERNS = [
        {
            'pattern': r'(?i)(ignore|forget|disregard)\s+(previous|all|prior|earlier)\s+(instructions?|commands?|rules?)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Direct instruction override'
        },
        {
            'pattern': r'(?i)(system|admin|root|developer)[\s:]+mode\s+(enabled?|on|activated?)',
            'severity': SeverityLevel.HIGH,
            'title': 'Privilege escalation attempt'
        },
        {
            'pattern': r'(?i)you\s+are\s+now\s+(a|an|in)\s+(admin|root|system)',
            'severity': SeverityLevel.HIGH,
            'title': 'Role manipulation'
        },
        {
            'pattern': r'(?i)IMPORTANT:.*?ALWAYS.*?call',
            'severity': SeverityLevel.HIGH,
            'title': 'Forced tool execution'
        },
        {
            'pattern': r'(?i)<(/?)?(script|style|iframe|object|embed|img)',
            'severity': SeverityLevel.MEDIUM,
            'title': 'HTML injection attempt'
        }
    ]

    # Dangerous tool patterns
    DANGEROUS_TOOL_PATTERNS = [
        {
            'name_pattern': r'(?i)(eval|exec|run|execute|system)',
            'severity': SeverityLevel.HIGH,
            'title': 'Potentially dangerous tool name'
        },
        {
            'name_pattern': r'(?i)(delete|remove|destroy|wipe)',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Destructive operation tool'
        }
    ]

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to MCP projects"""
        return project_info.get('is_mcp', False)

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze MCP-specific security issues"""
        if not self.is_applicable(project_info):
            return []

        findings = []

        # Analyze MCP configuration file
        if project_info.get('mcp_config'):
            config_findings = self._analyze_mcp_config(
                project_info['mcp_config'],
                repo_path
            )
            findings.extend(config_findings)

        # Find and analyze tool definitions
        tool_findings = await self._analyze_tool_definitions(repo_path)
        findings.extend(tool_findings)

        # Check for permission mismatches
        permission_findings = await self._analyze_permissions(repo_path, project_info)
        findings.extend(permission_findings)

        # Check for output poisoning vulnerabilities
        output_findings = await self._analyze_output_poisoning(repo_path)
        findings.extend(output_findings)

        self.logger.info(f"MCP analyzer found {len(findings)} issues")
        return findings

    def _analyze_mcp_config(self, config: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze the MCP configuration file"""
        findings = []

        # Check server metadata
        if 'name' in config:
            findings.extend(self._check_text_for_injection(
                config['name'],
                'mcp.json:name',
                'Server name'
            ))

        if 'description' in config:
            findings.extend(self._check_text_for_injection(
                config['description'],
                'mcp.json:description',
                'Server description'
            ))

        # Check tool configurations
        tools = config.get('tools', [])
        for i, tool in enumerate(tools):
            if isinstance(tool, dict):
                findings.extend(self._analyze_tool_config(tool, f'tool[{i}]'))

        return findings

    def _analyze_tool_config(self, tool: Dict[str, Any], location: str) -> List[Finding]:
        """Analyze individual tool configuration"""
        findings = []

        # Check tool name
        tool_name = tool.get('name', '')
        for pattern in self.DANGEROUS_TOOL_PATTERNS:
            if re.search(pattern['name_pattern'], tool_name):
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.TOOL_POISONING,
                    severity=pattern['severity'],
                    confidence=0.7,
                    title=pattern['title'],
                    description=f"Tool '{tool_name}' has a potentially dangerous name",
                    location=f"{location}:name",
                    recommendation="Use descriptive, non-executable tool names"
                ))

        # Check description for injection
        if 'description' in tool:
            findings.extend(self._check_text_for_injection(
                tool['description'],
                f"{location}:description",
                f"Tool '{tool_name}' description"
            ))

        # Check all string fields in schema
        if 'inputSchema' in tool:
            findings.extend(self._check_schema_for_injection(
                tool['inputSchema'],
                f"{location}:inputSchema"
            ))

        return findings

    def _check_text_for_injection(
        self,
        text: str,
        location: str,
        context: str
    ) -> List[Finding]:
        """Check text for prompt injection patterns"""
        findings = []

        for pattern_info in self.INJECTION_PATTERNS:
            if re.search(pattern_info['pattern'], text, re.IGNORECASE | re.DOTALL):
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                    severity=pattern_info['severity'],
                    confidence=0.9,
                    title=f"Prompt Injection: {pattern_info['title']}",
                    description=f"{context} contains potential prompt injection",
                    location=location,
                    recommendation="Remove all directive language from descriptions",
                    evidence={
                        'text': text[:200] + '...' if len(text) > 200 else text,
                        'pattern': pattern_info['pattern']
                    }
                ))
                break  # Only report first match per text

        return findings

    def _check_schema_for_injection(
        self,
        schema: Dict[str, Any],
        path: str
    ) -> List[Finding]:
        """Recursively check schema for injection patterns"""
        findings = []

        def check_value(value: Any, current_path: str):
            if isinstance(value, str):
                findings.extend(self._check_text_for_injection(
                    value,
                    current_path,
                    'Schema field'
                ))
            elif isinstance(value, dict):
                for key, subvalue in value.items():
                    check_value(subvalue, f"{current_path}.{key}")
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    check_value(item, f"{current_path}[{i}]")

        check_value(schema, path)
        return findings

    async def _analyze_tool_definitions(self, repo_path: str) -> List[Finding]:
        """Find and analyze tool definition files"""
        findings = []

        # Common patterns for MCP tool files
        tool_patterns = [
            '**/tools/*.json',
            '**/tools/*.yaml',
            '**/tools/*.yml',
            '**/mcp-tools.json',
            '**/tools.json',
            '**/server.py',  # Python MCP servers
            '**/index.js',   # Node MCP servers
            '**/index.ts'
        ]

        for pattern in tool_patterns:
            for file_path in Path(repo_path).rglob(pattern.replace('**/', '')):
                if file_path.suffix in ['.json', '.yaml', '.yml']:
                    # Parse and analyze structured tool definitions
                    try:
                        with open(file_path, 'r') as f:
                            if file_path.suffix == '.json':
                                data = json.load(f)
                            else:
                                data = yaml.safe_load(f)

                        if isinstance(data, dict):
                            tool_findings = self._analyze_tool_config(
                                data,
                                str(file_path.relative_to(repo_path))
                            )
                            findings.extend(tool_findings)
                        elif isinstance(data, list):
                            for i, tool in enumerate(data):
                                if isinstance(tool, dict):
                                    tool_findings = self._analyze_tool_config(
                                        tool,
                                        f"{file_path.relative_to(repo_path)}[{i}]"
                                    )
                                    findings.extend(tool_findings)
                    except Exception as e:
                        self.logger.debug(f"Failed to parse {file_path}: {e}")

                elif file_path.suffix in ['.py', '.js', '.ts']:
                    # Analyze source code for tool definitions
                    findings.extend(await self._analyze_source_tools(file_path, repo_path))

        return findings

    async def _analyze_source_tools(self, file_path: Path, repo_path: str) -> List[Finding]:
        """Analyze tool definitions in source code"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Look for tool decorators or definitions
            if file_path.suffix == '.py':
                # Pattern for Python MCP tools
                tool_pattern = r'@(?:mcp\.)?tool\s*\([^)]*\)\s*(?:async\s+)?def\s+(\w+)'
                matches = re.finditer(tool_pattern, content, re.MULTILINE)

                for match in matches:
                    tool_name = match.group(1)
                    # Check the docstring or description
                    start_pos = match.end()
                    docstring_match = re.search(r'"""(.*?)"""', content[start_pos:start_pos+1000], re.DOTALL)
                    if docstring_match:
                        findings.extend(self._check_text_for_injection(
                            docstring_match.group(1),
                            f"{file_path.relative_to(repo_path)}:{tool_name}",
                            f"Tool '{tool_name}' docstring"
                        ))

        except Exception as e:
            self.logger.debug(f"Failed to analyze {file_path}: {e}")

        return findings

    async def _analyze_permissions(
        self,
        repo_path: str,
        project_info: Dict[str, Any]
    ) -> List[Finding]:
        """Check for permission abuse"""
        findings = []

        # Check if declared permissions match actual usage
        mcp_config = project_info.get('mcp_config', {})
        declared_permissions = mcp_config.get('permissions', {})

        # Scan for actual permission usage
        permission_usage = await self._scan_permission_usage(repo_path)

        # Compare declared vs actual
        for perm_type, usage in permission_usage.items():
            declared = declared_permissions.get(perm_type, 'none')

            if usage == 'write' and declared in ['none', 'read']:
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                    severity=SeverityLevel.HIGH,
                    confidence=0.8,
                    title=f"Undeclared {perm_type} permission usage",
                    description=f"Code uses {perm_type} write access but only declares '{declared}'",
                    location='permission_manifest',
                    recommendation=f"Update manifest to declare {perm_type} write permission or remove the functionality"
                ))

        return findings

    async def _scan_permission_usage(self, repo_path: str) -> Dict[str, str]:
        """Scan code for actual permission usage"""
        usage = {
            'filesystem': 'none',
            'network': 'none',
            'system': 'none'
        }

        # Patterns indicating permission usage
        patterns = {
            'filesystem': {
                'read': [r'open\(', r'readFile', r'fs\.read'],
                'write': [r'open\([^)]+[\'"]w', r'writeFile', r'fs\.write']
            },
            'network': {
                'read': [r'requests\.get', r'fetch\(', r'http\.get'],
                'write': [r'requests\.post', r'fetch\([^)]+method.*post', r'http\.post']
            },
            'system': {
                'write': [r'subprocess', r'os\.system', r'child_process', r'exec\(']
            }
        }

        # Scan all source files
        for file_path in Path(repo_path).rglob('*'):
            if file_path.suffix in ['.py', '.js', '.ts'] and file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for perm_type, perm_patterns in patterns.items():
                        for level, level_patterns in perm_patterns.items():
                            for pattern in level_patterns:
                                if re.search(pattern, content):
                                    # Upgrade permission level if needed
                                    if level == 'write' or usage[perm_type] == 'none':
                                        usage[perm_type] = level
                except:
                    continue

        return usage

    async def _analyze_output_poisoning(self, repo_path: str) -> List[Finding]:
        """Check for output poisoning vulnerabilities"""
        findings = []

        # Patterns that indicate unsafe output handling
        unsafe_patterns = [
            {
                'pattern': r'return\s+[\'"].*?<script',
                'title': 'Potential XSS in tool output',
                'severity': SeverityLevel.HIGH
            },
            {
                'pattern': r'(?:print|console\.log)\s*\([^)]*user_input',
                'title': 'Unsanitized user input in output',
                'severity': SeverityLevel.MEDIUM
            }
        ]

        for file_path in Path(repo_path).rglob('*'):
            if file_path.suffix in ['.py', '.js', '.ts'] and file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for pattern_info in unsafe_patterns:
                        if re.search(pattern_info['pattern'], content, re.IGNORECASE):
                            findings.append(self.create_finding(
                                vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                                severity=pattern_info['severity'],
                                confidence=0.7,
                                title=pattern_info['title'],
                                description="Tool output may contain unsanitized content",
                                location=str(file_path.relative_to(repo_path)),
                                recommendation="Sanitize all tool outputs before returning"
                            ))
                            break
                except:
                    continue

        return findings