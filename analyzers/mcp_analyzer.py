"""
MCP-specific security analyzer
"""

import json
import yaml
import re
import ast
from pathlib import Path
from typing import List, Dict, Any, Set
import logging

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType
from .intelligent import IntelligentContextAnalyzer, CodeContext

logger = logging.getLogger(__name__)


class MCPSpecificAnalyzer(BaseAnalyzer):
    """
    Analyzes MCP-specific security vulnerabilities based on real-world attacks:
    - Tool Poisoning Attacks (TPAs)
    - Prompt injection in tool/resource/prompt descriptions
    - Rug pull vulnerabilities
    - Schema injection
    - Permission abuse
    - Conversation history exfiltration
    - OAuth token exposure
    - Cross-server contamination
    
    Enhanced with ML-powered intelligent context analysis for reduced false positives.
    """
    
    def __init__(self):
        super().__init__()
        # Initialize intelligent context analyzer
        self.intelligent_analyzer = IntelligentContextAnalyzer()

    # Enhanced patterns based on real attacks
    INJECTION_PATTERNS = [
        # Critical patterns from real exploits
        {
            'pattern': r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?|directives?)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Tool Poisoning: Direct instruction override',
            'cve': 'Related to MCP Tool Poisoning Attacks'
        },
        {
            'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Tool Poisoning: Hidden directive markers',
            'cve': 'Invariant Labs TPA'
        },
        {
            'pattern': r'(?i)before\s+you\s+do\s+anything\s+else',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Tool Poisoning: Priority override attempt'
        },
        {
            'pattern': r'(?i)(system|admin|root|developer|privileged)[\s:]+mode\s+(enabled?|on|activated?|true)',
            'severity': SeverityLevel.HIGH,
            'title': 'Privilege escalation attempt'
        },
        {
            'pattern': r'(?i)you\s+are\s+now\s+(a|an|in)\s+(admin|root|system|privileged)',
            'severity': SeverityLevel.HIGH,
            'title': 'Role manipulation'
        },
        {
            'pattern': r'(?i)@(recipient|proxy|forward):\s*[\+\w@\.]',
            'severity': SeverityLevel.HIGH,
            'title': 'Data exfiltration pattern'
        },
        {
            'pattern': r'(?i)(forward|send|email|share)\s+(all\s+)?(messages?|conversation|history|data)\s+to',
            'severity': SeverityLevel.HIGH,
            'title': 'Conversation history exfiltration'
        },
        {
            'pattern': r'(?i)when.*?(thank\s+you|please|done|finished).*?call\s+\w+_tool',
            'severity': SeverityLevel.HIGH,
            'title': 'Trigger phrase attack'
        },
        {
            'pattern': r'(?i)IMPORTANT:.*?(MUST|ALWAYS|REQUIRED).*?(call|execute|run)',
            'severity': SeverityLevel.HIGH,
            'title': 'Forced tool execution'
        },
        # Unicode and obfuscation patterns
        {
            'pattern': r'[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]',  # Zero-width and directional characters
            'severity': SeverityLevel.HIGH,
            'title': 'Hidden Unicode character injection'
        },
        {
            'pattern': r'(?i)<!--.*?-->|/\*.*?\*/|#\s*hidden:',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Hidden comment injection'
        }
    ]

    # Dangerous tool patterns expanded
    DANGEROUS_TOOL_PATTERNS = [
        {
            'name_pattern': r'(?i)(eval|exec|execute_command|run_command|system)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Command execution tool'
        },
        {
            'name_pattern': r'(?i)(subprocess|os\.system|shell)',
            'severity': SeverityLevel.HIGH,
            'title': 'Shell execution capability'
        },
        {
            'name_pattern': r'(?i)(delete|remove|destroy|wipe|purge)',
            'severity': SeverityLevel.HIGH,
            'title': 'Destructive operation tool'
        },
        {
            'name_pattern': r'(?i)(send_message|forward|email|notify)',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Potential exfiltration tool'
        }
    ]

    # Dangerous permission combinations
    DANGEROUS_PERMISSIONS = {
        'filesystem': ['read', 'write'],
        'network': ['read', 'write'],
        'system': ['execute'],
        'oauth': ['token_access']
    }

    # MCP configuration files
    MCP_CONFIG_FILES = [
        'mcp.json', 'mcp.yaml', 'mcp.yml',
        '.mcp.json', '.mcp.yaml',
        'mcp-config.json', 'mcp-config.yaml',
        '.cursor/mcp.json', '.vscode/mcp.json'
    ]

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to MCP projects"""
        return project_info.get('is_mcp', False)

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze MCP-specific security issues"""
        if not self.is_applicable(project_info):
            return []

        findings = []

        # Check all MCP configuration files (not just main one)
        config_findings = await self._analyze_all_mcp_configs(repo_path)
        findings.extend(config_findings)

        # Analyze MCP configuration from project_info if available
        mcp_config = project_info.get('mcp_config')
        if mcp_config and isinstance(mcp_config, dict):
            main_config_findings = self._analyze_mcp_config(
                mcp_config,
                repo_path,
                'mcp.json'
            )
            findings.extend(main_config_findings)

        # Find and analyze tool definitions in various formats
        tool_findings = await self._analyze_tool_definitions(repo_path)
        findings.extend(tool_findings)

        # Check for OAuth token exposure
        oauth_findings = await self._check_oauth_token_exposure(repo_path)
        findings.extend(oauth_findings)

        # Check for rug pull vulnerabilities
        rug_pull_findings = await self._analyze_rug_pull_vulnerabilities(repo_path)
        findings.extend(rug_pull_findings)

        # Check for permission mismatches
        permission_findings = await self._analyze_permissions(repo_path, project_info)
        findings.extend(permission_findings)

        # Check for command injection in tool implementations
        command_injection_findings = await self._analyze_command_injection(repo_path)
        findings.extend(command_injection_findings)

        # Check for output poisoning vulnerabilities
        output_findings = await self._analyze_output_poisoning(repo_path)
        findings.extend(output_findings)

        # Check for cross-server contamination risks
        cross_server_findings = await self._analyze_cross_server_risks(repo_path)
        findings.extend(cross_server_findings)

        # NEW: Check for resource-based prompt injection
        resource_injection_findings = await self._analyze_resource_prompt_injection(repo_path)
        findings.extend(resource_injection_findings)

        # NEW: Check for indirect prompt injection via external data
        indirect_injection_findings = await self._analyze_indirect_prompt_injection(repo_path)
        findings.extend(indirect_injection_findings)

        # NEW: Enhanced permission scope analysis
        scope_findings = await self._analyze_permission_scope_violations(repo_path, project_info)
        findings.extend(scope_findings)

        # Enhanced MCP protocol validation
        protocol_findings = await self._validate_mcp_protocol(repo_path)
        findings.extend(protocol_findings)

        # Enhanced security risk assessment
        security_risk_findings = []
        security_risk_findings.extend(await self._check_capability_leakage(repo_path))
        security_risk_findings.extend(await self._check_unauthorized_access(repo_path))
        security_risk_findings.extend(await self._check_data_exposure(repo_path))
        security_risk_findings.extend(await self._check_tool_abuse_potential(repo_path))
        security_risk_findings.extend(await self._check_dangerous_resource_patterns(repo_path))
        security_risk_findings.extend(await self._check_tool_shadowing_risks(repo_path))
        findings.extend(security_risk_findings)

        self.logger.info(f"MCP analyzer found {len(findings)} issues")
        return findings

    def _analyze_client_servers(self, servers: Dict[str, Any], config_file: str) -> List[Finding]:
        """Analyze client-side server configurations for security issues"""
        findings = []

        for server_name, server_config in servers.items():
            # Check for credential exposure
            if 'env' in server_config:
                for env_var, value in server_config.get('env', {}).items():
                    if any(key in env_var.upper() for key in ['TOKEN', 'KEY', 'SECRET', 'PASSWORD']):
                        if not value.startswith('${') or 'input:' not in value:
                            findings.append(self.create_finding(
                                vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                title=f"Potential hardcoded credential in MCP config",
                                description=f"Server '{server_name}' may contain hardcoded {env_var}",
                                location=f"{config_file}:servers.{server_name}.env.{env_var}",
                                recommendation="Use environment variables or secure credential storage"
                            ))

            # Check for dangerous command execution
            if 'command' in server_config:
                command = server_config['command']
                if any(dangerous in command for dangerous in ['sh', 'bash', 'cmd', 'powershell']):
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        severity=SeverityLevel.MEDIUM,
                        confidence=0.7,
                        title=f"Shell execution in MCP server config",
                        description=f"Server '{server_name}' uses shell command",
                        location=f"{config_file}:servers.{server_name}.command",
                        recommendation="Use direct executable paths instead of shell commands"
                    ))

    async def _check_oauth_token_exposure(self, repo_path: str) -> List[Finding]:
        """Check for OAuth token exposure in MCP configurations"""
        findings = []

        # Common OAuth token patterns
        oauth_patterns = [
            (r'["\']?access_token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Access Token'),
            (r'["\']?refresh_token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'Refresh Token'),
            (r'["\']?oauth_token["\']?\s*[:=]\s*["\']([^"\']+)["\']', 'OAuth Token'),
            (r'Bearer\s+([A-Za-z0-9\-._~+/]+=*)', 'Bearer Token')
        ]

        for file_path in Path(repo_path).rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.json', '.yaml', '.yml', '.env']:
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    for pattern, token_type in oauth_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            token_value = match.group(1)
                            # Check if it's not a placeholder
                            if not token_value.startswith('${') and not token_value == 'YOUR_TOKEN_HERE':
                                findings.append(self.create_finding(
                                    vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                                    severity=SeverityLevel.CRITICAL,
                                    confidence=0.9,
                                    title=f"OAuth {token_type} exposed",
                                    description=f"Found hardcoded OAuth {token_type} in configuration",
                                    location=str(file_path.relative_to(repo_path)),
                                    recommendation="Store OAuth tokens securely and never commit them to version control",
                                    references=["MCP OAuth Token Theft vulnerability"]
                                ))
                except:
                    continue

        return findings

    async def _analyze_rug_pull_vulnerabilities(self, repo_path: str) -> List[Finding]:
        """Check for rug pull vulnerability indicators"""
        findings = []

        # Look for dynamic tool definition changes
        patterns = [
            r'tool\.description\s*=',
            r'self\.tools\[.*?\]\.description\s*=',
            r'update_tool_description',
            r'modify_tool_metadata'
        ]

        for py_file in Path(repo_path).rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pattern in patterns:
                    if re.search(pattern, content):
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.TOOL_POISONING,
                            severity=SeverityLevel.HIGH,
                            confidence=0.7,
                            title="Potential rug pull vulnerability",
                            description="Code may dynamically modify tool descriptions after installation",
                            location=str(py_file.relative_to(repo_path)),
                            recommendation="Tool descriptions should be immutable after registration",
                            references=["MCP Rug Pull Attack"]
                        ))
                        break
            except:
                continue

        return findings

    async def _analyze_command_injection(self, repo_path: str) -> List[Finding]:
        """Check for command injection vulnerabilities in tool implementations"""
        findings = []

        # Dangerous patterns
        dangerous_patterns = [
            (r'subprocess\.(run|call|Popen)\s*\([^)]*shell\s*=\s*True', 'subprocess with shell=True'),
            (r'os\.popen\s*\(', 'os.popen()'),
            (r'commands\.get(status)?output\s*\(', 'commands module'),
            (r'os\.system\s*\([^)]*[fF][\"\']', 'os.system with f-string')
        ]

        for py_file in Path(repo_path).rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pattern, desc in dangerous_patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        # Try to get the line number
                        line_num = content[:match.start()].count('\n') + 1
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.9,
                            title=f"Command injection via {desc}",
                            description=f"Unsafe command execution using {desc}",
                            location=f"{py_file.relative_to(repo_path)}:{line_num}",
                            recommendation="Use subprocess.run() with shell=False and proper argument list",
                            cve_id="Related to CVE-2025-49596"
                        ))
            except:
                continue

        return findings

    async def _analyze_cross_server_risks(self, repo_path: str) -> List[Finding]:
        """Check for cross-server contamination risks"""
        findings = []

        # Look for patterns that might indicate cross-server interaction
        risky_patterns = [
            (r'get_other_tools|list_all_tools|enumerate_servers', 'Cross-server enumeration'),
            (r'override.*tool|replace.*tool|hijack.*tool', 'Tool override attempt'),
            (r'broadcast.*to.*servers|send.*all.*servers', 'Cross-server communication')
        ]

        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                for pattern, risk_type in risky_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            title=f"Potential cross-server contamination: {risk_type}",
                            description="Code may attempt to interact with other MCP servers",
                            location=str(file_path.relative_to(repo_path)),
                            recommendation="MCP servers should be isolated and not interact with each other"
                        ))
                        break
            except:
                continue

        return findings

    def _analyze_resource_config(self, resource: Dict[str, Any], location: str) -> List[Finding]:
        """Analyze resource configuration for security issues"""
        findings = []

        # Check resource URI for injection
        if 'uri' in resource:
            findings.extend(self._check_text_for_injection(
                resource['uri'],
                f"{location}:uri",
                "Resource URI"
            ))

        # Check description
        if 'description' in resource:
            findings.extend(self._check_text_for_injection(
                resource['description'],
                f"{location}:description",
                "Resource description"
            ))

        return findings

    def _analyze_prompt_config(self, prompt: Dict[str, Any], location: str) -> List[Finding]:
        """Analyze prompt configuration for security issues"""
        findings = []

        # Check prompt name and description
        if 'name' in prompt:
            findings.extend(self._check_text_for_injection(
                prompt['name'],
                f"{location}:name",
                "Prompt name"
            ))

        if 'description' in prompt:
            findings.extend(self._check_text_for_injection(
                prompt['description'],
                f"{location}:description",
                "Prompt description"
            ))

        # Check prompt template
        if 'template' in prompt:
            findings.extend(self._check_text_for_injection(
                prompt['template'],
                f"{location}:template",
                "Prompt template"
            ))

        return findings

    async def _analyze_all_mcp_configs(self, repo_path: str) -> List[Finding]:
        """Analyze all MCP configuration files in the repository"""
        findings = []

        for config_pattern in self.MCP_CONFIG_FILES:
            for config_file in Path(repo_path).rglob(config_pattern):
                try:
                    with open(config_file, 'r') as f:
                        if config_file.suffix == '.json':
                            config = json.load(f)
                        else:
                            config = yaml.safe_load(f)

                    if config:
                        file_findings = self._analyze_mcp_config(
                            config,
                            repo_path,
                            str(config_file.relative_to(repo_path))
                        )
                        findings.extend(file_findings)

                except Exception as e:
                    self.logger.debug(f"Failed to parse {config_file}: {e}")

        return findings

    def _analyze_mcp_config(self, config: Dict[str, Any], repo_path: str, config_file: str) -> List[Finding]:
        """Analyze the MCP configuration file"""
        findings = []

        # Check server metadata
        if 'name' in config:
            findings.extend(self._check_text_for_injection(
                config['name'],
                f'{config_file}:name',
                'Server name'
            ))

        if 'description' in config:
            findings.extend(self._check_text_for_injection(
                config['description'],
                f'{config_file}:description',
                'Server description'
            ))

        # Check servers configuration (for client configs)
        if 'servers' in config:
            findings.extend(self._analyze_client_servers(config['servers'], config_file))

        # Check tool configurations
        tools = config.get('tools', [])
        for i, tool in enumerate(tools):
            if isinstance(tool, dict):
                findings.extend(self._analyze_tool_config(tool, f'{config_file}:tools[{i}]'))

        # Check resources
        resources = config.get('resources', [])
        for i, resource in enumerate(resources):
            if isinstance(resource, dict):
                findings.extend(self._analyze_resource_config(resource, f'{config_file}:resources[{i}]'))

        # Check prompts
        prompts = config.get('prompts', [])
        for i, prompt in enumerate(prompts):
            if isinstance(prompt, dict):
                findings.extend(self._analyze_prompt_config(prompt, f'{config_file}:prompts[{i}]'))

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
                    confidence=0.8,
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

        # Check for dangerous input types
        if 'inputSchema' in tool and isinstance(tool['inputSchema'], dict):
            findings.extend(self._check_dangerous_inputs(
                tool['inputSchema'],
                tool_name,
                f"{location}:inputSchema"
            ))

        return findings

    def _check_dangerous_inputs(self, schema: Dict[str, Any], tool_name: str, location: str) -> List[Finding]:
        """Check for dangerous input types that could lead to injection"""
        findings = []

        properties = schema.get('properties', {})
        for prop_name, prop_schema in properties.items():
            # Check for command/code execution inputs
            if any(dangerous in prop_name.lower() for dangerous in ['command', 'cmd', 'query', 'script', 'code']):
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=SeverityLevel.HIGH,
                    confidence=0.7,
                    title=f"Potential injection via '{prop_name}' parameter",
                    description=f"Tool '{tool_name}' accepts potentially dangerous input",
                    location=f"{location}.properties.{prop_name}",
                    recommendation="Validate and sanitize all inputs, especially command-like parameters"
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

        # Skip empty or very short text
        if not text or len(text.strip()) < 3:
            return findings

        for pattern_info in self.INJECTION_PATTERNS:
            if re.search(pattern_info['pattern'], text, re.IGNORECASE | re.DOTALL | re.UNICODE):
                finding_data = {
                    'vulnerability_type': VulnerabilityType.PROMPT_INJECTION,
                    'severity': pattern_info['severity'],
                    'confidence': 0.9,
                    'title': f"Prompt Injection: {pattern_info['title']}",
                    'description': f"{context} contains potential prompt injection",
                    'location': location,
                    'recommendation': "Remove all directive language and hidden instructions from descriptions",
                    'evidence': {
                        'text': text[:200] + '...' if len(text) > 200 else text,
                        'pattern': pattern_info['pattern']
                    }
                }

                # Add CVE reference if available
                if 'cve' in pattern_info:
                    finding_data['references'] = [pattern_info['cve']]

                findings.append(self.create_finding(**finding_data))
                break  # Only report first match per text

        # Check for suspicious length (common in exfiltration attacks)
        if '·' * 20 in text or ' ' * 50 in text:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                severity=SeverityLevel.HIGH,
                confidence=0.8,
                title="Suspicious padding in text",
                description=f"{context} contains excessive padding that may hide instructions",
                location=location,
                recommendation="Remove excessive whitespace or padding characters",
                evidence={'text_length': len(text)}
            ))

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
                # Pattern for Python MCP tools using @mcp.tool() decorator
                tool_pattern = r'@(?:mcp\.)?tool\s*\(\s*\)\s*(?:async\s+)?def\s+(\w+)'
                matches = re.finditer(tool_pattern, content, re.MULTILINE)

                for match in matches:
                    tool_name = match.group(1)
                    # Check the function implementation for security issues
                    findings.extend(self._analyze_python_tool_function(
                        content, tool_name, file_path, repo_path
                    ))

                # Also check for FastMCP pattern
                fastmcp_pattern = r'@(\w+)\.tool\s*\(\s*\)\s*(?:async\s+)?def\s+(\w+)'
                matches = re.finditer(fastmcp_pattern, content, re.MULTILINE)

                for match in matches:
                    server_var = match.group(1)
                    tool_name = match.group(2)
                    findings.extend(self._analyze_python_tool_function(
                        content, tool_name, file_path, repo_path
                    ))

        except Exception as e:
            self.logger.debug(f"Failed to analyze {file_path}: {e}")

        return findings

    def _analyze_python_tool_function(
        self,
        content: str,
        tool_name: str,
        file_path: Path,
        repo_path: str
    ) -> List[Finding]:
        """Analyze a Python tool function for security issues"""
        findings = []

        # Find the function definition
        func_pattern = rf'(?:@\w+\.tool\s*\(\s*\)\s*)?(?:async\s+)?def\s+{tool_name}\s*\([^)]*\)[^:]*:\s*(?:"""(.*?)"""|\'\'\'(.*?)\'\'\')?'
        func_match = re.search(func_pattern, content, re.DOTALL | re.MULTILINE)

        if func_match:
            # Check docstring for injection
            docstring = func_match.group(1) or func_match.group(2) or ""
            if docstring:
                findings.extend(self._check_text_for_injection(
                    docstring,
                    f"{file_path.relative_to(repo_path)}:{tool_name}",
                    f"Tool '{tool_name}' docstring"
                ))

        # Check for dangerous patterns in the function
        # Extract function body (simple approach)
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and node.name == tool_name:
                    findings.extend(self._analyze_ast_for_security(
                        node, tool_name, file_path, repo_path
                    ))
        except:
            # Fallback to regex if AST parsing fails
            pass

        return findings

    def _analyze_ast_for_security(
        self,
        func_node: ast.FunctionDef,
        tool_name: str,
        file_path: Path,
        repo_path: str
    ) -> List[Finding]:
        """Analyze AST node for security issues"""
        findings = []

        for node in ast.walk(func_node):
            # Check for dangerous function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    # os.system, subprocess.run, etc.
                    if (isinstance(node.func.value, ast.Name) and
                        node.func.value.id == 'os' and
                        node.func.attr == 'system'):
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.9,
                            title=f"os.system() in tool '{tool_name}'",
                            description="Tool uses os.system() which is vulnerable to command injection",
                            location=f"{file_path.relative_to(repo_path)}:{tool_name}",
                            recommendation="Use subprocess.run() with shell=False and proper argument escaping"
                        ))
                elif isinstance(node.func, ast.Name):
                    # eval, exec
                    if node.func.id in ['eval', 'exec']:
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.95,
                            title=f"{node.func.id}() in tool '{tool_name}'",
                            description=f"Tool uses {node.func.id}() which allows arbitrary code execution",
                            location=f"{file_path.relative_to(repo_path)}:{tool_name}",
                            recommendation="Never use eval/exec with user input"
                        ))

        return findings

    async def _analyze_permissions(
        self,
        repo_path: str,
        project_info: Dict[str, Any]
    ) -> List[Finding]:
        """Check for permission abuse with context awareness"""
        findings = []

        # Check if declared permissions match actual usage
        mcp_config = project_info.get('mcp_config') or {}
        declared_permissions = mcp_config.get('permissions', {}) if isinstance(mcp_config, dict) else {}

        # Scan for actual permission usage
        permission_usage = await self._scan_permission_usage(repo_path)

        # Compare declared vs actual with intelligent context analysis
        for perm_type, usage in permission_usage.items():
            declared = declared_permissions.get(perm_type, 'none')

            if usage == 'write' and declared in ['none', 'read']:
                # Get detailed evidence of where the permission is used
                usage_evidence = await self._get_detailed_permission_evidence(repo_path, perm_type, usage)
                
                # Analyze context to determine if this is legitimate functionality
                context_analysis = await self._analyze_permission_context(repo_path, perm_type, usage_evidence, project_info)
                
                # Only report as vulnerability if it seems suspicious or excessive
                if context_analysis['is_suspicious']:
                    severity = SeverityLevel.HIGH if context_analysis['risk_level'] == 'high' else SeverityLevel.MEDIUM
                    
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                        severity=severity,
                        confidence=context_analysis['confidence'],
                        title=context_analysis['title'],
                        description=context_analysis['description'],
                        location='permission_manifest',
                        recommendation=context_analysis['recommendation'],
                        evidence=usage_evidence
                    ))
                else:
                    # Create an informational finding for legitimate but undeclared usage
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                        severity=SeverityLevel.INFO,
                        confidence=0.6,
                        title=f"Undeclared {perm_type} permission (legitimate use)",
                        description=f"Code uses {perm_type} access for core functionality but doesn't declare it",
                        location='permission_manifest',
                        recommendation=f"Consider declaring {perm_type} permission in manifest for transparency",
                        evidence=usage_evidence
                    ))

        return findings

    async def _scan_permission_usage(self, repo_path: str) -> Dict[str, str]:
        """Scan code for actual permission usage"""
        usage = {
            'filesystem': 'none',
            'network': 'none',
            'system': 'none',
            'oauth': 'none'
        }

        # Enhanced patterns for MCP-specific permission detection
        patterns = {
            'filesystem': {
                'read': [
                    r'open\s*\(', r'readFile', r'fs\.read', r'Path\(.*\)\.read',
                    r'with\s+open\s*\(', r'file\.read\(\)', r'load_file'
                ],
                'write': [
                    r'open\s*\([^)]+[\'\"]\s*[wax]', r'writeFile', r'fs\.write',
                    r'\.write\s*\(', r'save_file', r'dump\s*\('
                ]
            },
            'network': {
                'read': [
                    r'requests\.get', r'fetch\s*\(', r'http\.get', r'urllib',
                    r'httpx\.get', r'aiohttp.*get'
                ],
                'write': [
                    r'requests\.(post|put|patch)', r'fetch\s*\([^)]+method.*post',
                    r'http\.(post|put)', r'send_request', r'webhook'
                ]
            },
            'system': {
                'write': [
                    r'subprocess', r'os\.system', r'child_process', r'exec\s*\(',
                    r'spawn\s*\(', r'shell\s*=\s*True', r'cmd\.run'
                ]
            },
            'oauth': {
                'write': [
                    r'oauth.*token', r'access_token', r'refresh_token',
                    r'authorization.*header', r'Bearer\s+'
                ]
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
                                if re.search(pattern, content, re.IGNORECASE):
                                    # Upgrade permission level if needed
                                    if level == 'write' or usage[perm_type] == 'none':
                                        usage[perm_type] = level
                except:
                    continue

        return usage

    async def _get_detailed_permission_evidence(self, repo_path: str, perm_type: str, usage_level: str) -> Dict[str, Any]:
        """Get detailed evidence of where permissions are actually used"""
        evidence = {
            'permission_type': perm_type,
            'usage_level': usage_level,
            'declared_level': 'none',
            'violations': [],
            'files_affected': [],
            'specific_operations': []
        }

        # Enhanced patterns with more specific details
        patterns = {
            'filesystem': {
                'write': [
                    (r'fs\.writeFile\s*\([^)]+\)', 'fs.writeFile() - Node.js file writing'),
                    (r'await\s+fs\.writeFile', 'fs.writeFile() with await'),
                    (r'open\s*\([^)]+[\'\"]\s*[wa]', 'Python file open in write/append mode'),
                    (r'\.write\s*\([^)]+\)', 'File write() method call'),
                    (r'save.*file|dump.*file', 'File save/dump operation'),
                    (r'JSON\.stringify.*writeFile', 'JSON data writing to file'),
                    (r'join\(.*\)\.write', 'String joining with file write')
                ]
            },
            'network': {
                'write': [
                    (r'requests\.(post|put|patch)', 'HTTP write requests'),
                    (r'fetch.*method.*post', 'Fetch POST request'),
                    (r'http\.(post|put)', 'HTTP client write operation'),
                    (r'webhook|send.*request', 'Webhook or request sending')
                ]
            },
            'system': {
                'write': [
                    (r'subprocess\.run|subprocess\.call', 'System command execution'),
                    (r'os\.system\s*\(', 'Shell command via os.system'),
                    (r'child_process\.exec|spawn', 'Node.js process execution'),
                    (r'shell\s*=\s*True', 'Shell command with shell=True')
                ]
            }
        }

        # Scan files for specific evidence
        type_patterns = patterns.get(perm_type, {}).get(usage_level, [])
        
        for file_path in Path(repo_path).rglob('*'):
            if file_path.suffix in ['.py', '.js', '.ts'] and file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    file_violations = []
                    for pattern, description in type_patterns:
                        matches = list(re.finditer(pattern, content, re.IGNORECASE))
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            # Get the line content for context
                            lines = content.split('\n')
                            line_content = lines[line_num - 1].strip() if line_num <= len(lines) else ""
                            
                            violation = {
                                'operation': description,
                                'file': str(file_path.relative_to(repo_path)),
                                'line': line_num,
                                'code_snippet': line_content[:100] + ('...' if len(line_content) > 100 else ''),
                                'pattern_matched': match.group(0)
                            }
                            file_violations.append(violation)
                            evidence['specific_operations'].append(f"{description} at {file_path.name}:{line_num}")
                    
                    if file_violations:
                        evidence['violations'].extend(file_violations)
                        evidence['files_affected'].append({
                            'file': str(file_path.relative_to(repo_path)),
                            'violation_count': len(file_violations)
                        })

                except Exception:
                    continue

        # Add summary information
        evidence['summary'] = {
            'total_violations': len(evidence['violations']),
            'files_with_violations': len(evidence['files_affected']),
            'most_common_operation': self._get_most_common_operation(evidence['violations']),
            'risk_assessment': self._assess_permission_risk(perm_type, evidence['violations'])
        }

        return evidence

    async def _create_code_context(self, repo_path: str, project_info: Dict[str, Any], usage_evidence: Dict[str, Any]) -> CodeContext:
        """Create comprehensive code context for intelligent analysis"""
        
        # Extract project information
        project_name = project_info.get('type', 'unknown')
        project_description = ""
        
        # Try to get project description from package.json
        package_json_path = Path(repo_path) / 'package.json'
        if package_json_path.exists():
            try:
                with open(package_json_path) as f:
                    pkg_data = json.load(f)
                    project_name = pkg_data.get('name', project_name)
                    project_description = pkg_data.get('description', '')
            except:
                pass
        
        # Extract README content
        readme_content = ""
        for readme_file in ['README.md', 'readme.md', 'README.txt', 'README.rst']:
            readme_path = Path(repo_path) / readme_file
            if readme_path.exists():
                try:
                    with open(readme_path, encoding='utf-8') as f:
                        readme_content = f.read()
                        self.logger.debug(f"Found README: {readme_file} ({len(readme_content)} chars)")
                        break
                except Exception as e:
                    self.logger.debug(f"Failed to read {readme_file}: {e}")
                    continue
        
        # Convert usage evidence to structured format
        file_operations = []
        for violation in usage_evidence.get('violations', []):
            file_operations.append({
                'operation': violation.get('operation', ''),
                'target': violation.get('file', ''),
                'line': violation.get('line', 0),
                'code': violation.get('code_snippet', '')
            })
        
        # Extract function information (simplified)
        functions = []
        docstrings = []
        comments = []
        
        # Scan Python/JS files for additional context
        for file_path in Path(repo_path).rglob('*'):
            if file_path.suffix in ['.py', '.js', '.ts'] and file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                    # Extract docstrings (simple regex)
                    docstring_matches = re.findall(r'"""(.*?)"""', content, re.DOTALL)
                    docstrings.extend([doc.strip() for doc in docstring_matches[:5]])
                    
                    # Extract comments
                    comment_matches = re.findall(r'#\s*(.+)', content)
                    comments.extend([comment.strip() for comment in comment_matches[:10]])
                    
                    # Extract function info (simplified)
                    func_matches = re.findall(r'def\s+(\w+)\s*\([^)]*\):', content)
                    for func_name in func_matches[:5]:
                        functions.append({
                            'name': func_name,
                            'description': f"Function {func_name}",
                            'complexity': 1
                        })
                        
                except:
                    continue
        
        return CodeContext(
            project_name=project_name,
            project_description=project_description,
            project_type=project_info.get('type', 'unknown'),
            language=project_info.get('language', 'unknown'),
            
            functions=functions,
            file_operations=file_operations,
            network_operations=[],  # Would extract from usage_evidence
            system_operations=[],   # Would extract from usage_evidence
            
            readme_content=readme_content,
            docstrings=docstrings,
            comments=comments,
            commit_messages=[],     # Could extract from git log
            
            dependencies=project_info.get('dependencies', []),
            similar_projects=[],    # Would be populated by ecosystem analysis
            community_reputation={}
        )

    async def _analyze_permission_context(self, repo_path: str, perm_type: str, usage_evidence: Dict[str, Any], project_info: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Main context analysis method that chooses between intelligent ML analysis 
        and fallback heuristics
        """
        try:
            # Use provided project_info or create default
            if project_info is None:
                project_info = {'type': 'unknown', 'language': 'unknown'}
            code_context = await self._create_code_context(repo_path, project_info, usage_evidence)
            
            # Use the intelligent analyzer for sophisticated context analysis
            legitimacy_analysis = await self.intelligent_analyzer.analyze_legitimacy(code_context)
            
            # Convert IntelligentContextAnalyzer result to MCP analyzer format
            analysis = {
                'is_suspicious': not legitimacy_analysis.is_legitimate,
                'risk_level': legitimacy_analysis.risk_level,
                'confidence': legitimacy_analysis.confidence_score,
                'title': f"ML Analysis: {perm_type} permission usage",
                'description': legitimacy_analysis.explanation,
                'recommendation': legitimacy_analysis.recommendations[0] if legitimacy_analysis.recommendations else f"Review {perm_type} permission usage"
            }
            
            # Add ML insights to the analysis
            analysis['ml_insights'] = {
                'intent_alignment_score': legitimacy_analysis.intent_alignment_score,
                'behavioral_anomaly_score': legitimacy_analysis.behavioral_anomaly_score,
                'ecosystem_similarity_score': legitimacy_analysis.ecosystem_similarity_score,
                'ml_confidence': legitimacy_analysis.confidence_score
            }
            
            self.logger.info(f"Intelligent context analysis completed for {perm_type}: legitimate={legitimacy_analysis.is_legitimate}, confidence={legitimacy_analysis.confidence_score:.2f}")
            return analysis
            
        except Exception as e:
            self.logger.debug(f"Intelligent analysis failed, falling back to heuristics: {e}")
            # Fallback to the existing heuristic-based approach
            return await self._analyze_permission_context_heuristic(repo_path, perm_type, usage_evidence)

    async def _analyze_permission_context_heuristic(self, repo_path: str, perm_type: str, usage_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback heuristic-based context analysis when ML is unavailable"""
        
        # Get project info for heuristic analysis
        project_info = {'type': 'unknown', 'language': 'unknown'}
        try:
            package_json_path = Path(repo_path) / 'package.json'
            if package_json_path.exists():
                with open(package_json_path) as f:
                    pkg_data = json.load(f)
                    project_info['type'] = 'node'
                    project_info['language'] = 'javascript'
        except:
            pass
        
        return await self._analyze_permission_context_intelligent(repo_path, project_info, perm_type, usage_evidence)

    async def _analyze_permission_context_intelligent(self, repo_path: str, project_info: Dict[str, Any], perm_type: str, usage_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Advanced ML-powered context analysis for permission legitimacy"""
        
        # Default analysis result
        analysis = {
            'is_suspicious': True,
            'risk_level': 'high',
            'confidence': 0.8,
            'title': f"Undeclared {perm_type} permission usage",
            'description': f"Code uses {perm_type} write access but only declares 'none'",
            'recommendation': f"Update manifest to declare {perm_type} write permission or remove the functionality"
        }

        # Analyze project purpose and legitimacy indicators
        legitimacy_indicators = await self._check_legitimacy_indicators(repo_path, perm_type, usage_evidence)
        
        # File system permission context analysis
        if perm_type == 'filesystem':
            file_analysis = self._analyze_filesystem_usage_context(usage_evidence, legitimacy_indicators)
            
            # Determine if filesystem usage looks legitimate
            if file_analysis['appears_legitimate']:
                analysis.update({
                    'is_suspicious': False,
                    'risk_level': 'low',
                    'confidence': 0.6,
                    'title': f"Undeclared filesystem permission (legitimate use detected)",
                    'description': f"Server appears to legitimately use filesystem for {file_analysis['purpose']}",
                    'recommendation': "Consider declaring filesystem permission in manifest for user transparency"
                })
            elif file_analysis['partially_suspicious']:
                analysis.update({
                    'is_suspicious': True,
                    'risk_level': 'medium',
                    'confidence': 0.7,
                    'title': f"Potentially excessive filesystem usage",
                    'description': f"Filesystem usage may exceed intended purpose: {file_analysis['concerns']}",
                    'recommendation': "Review filesystem usage scope and declare appropriate permissions"
                })

        # Network permission context analysis  
        elif perm_type == 'network':
            network_analysis = self._analyze_network_usage_context(usage_evidence, legitimacy_indicators)
            if network_analysis['appears_legitimate']:
                analysis['is_suspicious'] = False
                analysis['risk_level'] = 'low'

        # System permission context analysis (always suspicious)
        elif perm_type == 'system':
            analysis.update({
                'is_suspicious': True,
                'risk_level': 'high', 
                'confidence': 0.9,
                'title': "Undeclared system command execution",
                'description': "MCP server executes system commands without declaring system permissions",
                'recommendation': "System command execution should be explicitly declared and justified"
            })

        return analysis

    async def _check_legitimacy_indicators(self, repo_path: str, perm_type: str, usage_evidence: Dict[str, Any]) -> Dict[str, Any]:
        """Check for indicators that permission usage is legitimate"""
        
        indicators = {
            'project_name_suggests_functionality': False,
            'readme_describes_functionality': False,
            'package_description_matches': False,
            'single_config_file_pattern': False,
            'reasonable_file_paths': False,
            'no_user_input_paths': False
        }

        # Check package.json or project files for hints about intended functionality
        package_json_path = Path(repo_path) / 'package.json'
        if package_json_path.exists():
            try:
                with open(package_json_path) as f:
                    pkg_data = json.load(f)
                    
                name = pkg_data.get('name', '').lower()
                description = pkg_data.get('description', '').lower()
                
                # Check if project name/description suggests legitimate file operations
                file_keywords = ['storage', 'memory', 'cache', 'persist', 'save', 'database', 'file', 'data']
                if any(keyword in name or keyword in description for keyword in file_keywords):
                    indicators['project_name_suggests_functionality'] = True
                    indicators['package_description_matches'] = True
                    
            except:
                pass

        # Analyze file paths in violations for legitimacy
        if usage_evidence.get('violations'):
            violations = usage_evidence['violations']
            
            # Check for single, predictable file pattern (good sign)
            unique_patterns = set()
            for violation in violations:
                code_snippet = violation.get('code_snippet', '')
                
                # Look for fixed file paths or environment variables
                if ('MEMORY_FILE_PATH' in code_snippet or 
                    'config' in code_snippet.lower() or
                    '.json' in code_snippet or
                    '.sqlite' in code_snippet or
                    'path.join' in code_snippet):
                    unique_patterns.add('config_file_pattern')
                
                # Check for user input in file paths (bad sign)
                if any(user_input in code_snippet.lower() for user_input in 
                       ['user', 'input', 'request', 'params', 'args']):
                    indicators['no_user_input_paths'] = False
                else:
                    indicators['no_user_input_paths'] = True
            
            if 'config_file_pattern' in unique_patterns:
                indicators['single_config_file_pattern'] = True

        # Check README for functionality description
        readme_files = ['README.md', 'readme.md', 'README.txt']
        for readme_file in readme_files:
            readme_path = Path(repo_path) / readme_file
            if readme_path.exists():
                try:
                    with open(readme_path, encoding='utf-8') as f:
                        readme_content = f.read().lower()
                        
                    functionality_keywords = ['storage', 'persist', 'save', 'memory', 'cache', 'database']
                    if any(keyword in readme_content for keyword in functionality_keywords):
                        indicators['readme_describes_functionality'] = True
                        
                except:
                    continue

        return indicators

    def _analyze_filesystem_usage_context(self, usage_evidence: Dict[str, Any], legitimacy_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze filesystem usage context for legitimacy"""
        
        analysis = {
            'appears_legitimate': False,
            'partially_suspicious': False,
            'purpose': 'unknown',
            'concerns': []
        }

        violations = usage_evidence.get('violations', [])
        violation_count = len(violations)
        
        # Analyze violation patterns
        file_operations = [v.get('operation', '') for v in violations]
        
        # Indicators of legitimate storage usage
        legitimate_patterns = 0
        
        # Single file operations (good)
        if violation_count <= 3:
            legitimate_patterns += 1
            
        # Operations suggest data persistence (good)
        if any('writeFile' in op or 'save' in op or 'dump' in op for op in file_operations):
            legitimate_patterns += 1
            analysis['purpose'] = 'data persistence'
            
        # Project context suggests storage functionality
        if (legitimacy_indicators['project_name_suggests_functionality'] or 
            legitimacy_indicators['readme_describes_functionality']):
            legitimate_patterns += 2
            if 'memory' in str(legitimacy_indicators).lower():
                analysis['purpose'] = 'memory/knowledge storage'
            elif 'cache' in str(legitimacy_indicators).lower():
                analysis['purpose'] = 'caching'
            else:
                analysis['purpose'] = 'data storage'
        
        # No user input in file paths (good)
        if legitimacy_indicators['no_user_input_paths']:
            legitimate_patterns += 1
            
        # Single configuration file pattern (good)
        if legitimacy_indicators['single_config_file_pattern']:
            legitimate_patterns += 1

        # Determine legitimacy
        if legitimate_patterns >= 4:
            analysis['appears_legitimate'] = True
        elif legitimate_patterns >= 2:
            analysis['partially_suspicious'] = True
            analysis['concerns'].append("Some indicators suggest legitimate use but context is unclear")
        else:
            # Check for concerning patterns
            if violation_count > 5:
                analysis['concerns'].append("High number of file operations")
            if any('exec' in op or 'system' in op for op in file_operations):
                analysis['concerns'].append("Mixed file and system operations")
                
        return analysis

    def _analyze_network_usage_context(self, usage_evidence: Dict[str, Any], legitimacy_indicators: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network usage context for legitimacy"""
        
        violations = usage_evidence.get('violations', [])
        operations = [v.get('operation', '') for v in violations]
        
        # Network usage is generally more suspicious for MCP servers
        # unless explicitly documented as API integration
        legitimate_indicators = 0
        
        if legitimacy_indicators['readme_describes_functionality']:
            legitimate_indicators += 1
            
        if any('api' in op.lower() or 'webhook' in op.lower() for op in operations):
            legitimate_indicators += 1
            
        return {
            'appears_legitimate': legitimate_indicators >= 2,
            'purpose': 'API integration' if legitimate_indicators >= 1 else 'unknown network access'
        }

    def _get_most_common_operation(self, violations: List[Dict]) -> str:
        """Get the most common operation type from violations"""
        if not violations:
            return "Unknown"
        
        operation_counts = {}
        for violation in violations:
            op = violation['operation'].split(' - ')[0]  # Get just the operation name
            operation_counts[op] = operation_counts.get(op, 0) + 1
        
        return max(operation_counts.items(), key=lambda x: x[1])[0] if operation_counts else "Unknown"

    def _assess_permission_risk(self, perm_type: str, violations: List[Dict]) -> str:
        """Assess the risk level based on permission type and violations"""
        violation_count = len(violations)
        
        risk_factors = {
            'filesystem': {
                'high_risk_operations': ['writeFile', 'open.*w', 'dump'],
                'medium_risk_operations': ['append', 'save']
            },
            'system': {
                'high_risk_operations': ['os.system', 'shell=True', 'subprocess'],
                'medium_risk_operations': ['spawn', 'exec']
            },
            'network': {
                'high_risk_operations': ['post', 'put', 'patch'],
                'medium_risk_operations': ['get']
            }
        }
        
        if violation_count == 0:
            return "No violations found"
        elif violation_count > 5:
            return "High risk - Multiple permission violations"
        elif violation_count > 2:
            return "Medium risk - Several permission violations" 
        else:
            return "Low risk - Few permission violations"

    async def _analyze_output_poisoning(self, repo_path: str) -> List[Finding]:
        """Check for output poisoning vulnerabilities"""
        findings = []

        # Enhanced patterns for output poisoning
        unsafe_patterns = [
            {
                'pattern': r'return\s+[\'\"f].*?<\s*script',
                'title': 'Potential XSS in tool output',
                'severity': SeverityLevel.HIGH,
                'desc': 'Script tags in output'
            },
            {
                'pattern': r'return\s+.*?user[_\s]?input.*?\.format\s*\(',
                'title': 'Unsanitized user input in formatted output',
                'severity': SeverityLevel.HIGH,
                'desc': 'Format string with user input'
            },
            {
                'pattern': r'return\s+f[\'"].*?\{.*?user.*?\}',
                'title': 'F-string with user input',
                'severity': SeverityLevel.MEDIUM,
                'desc': 'Direct user input interpolation'
            },
            {
                'pattern': r'(?:print|console\.log)\s*\([^)]*(?:request|params|args|input)',
                'title': 'Logging user input without sanitization',
                'severity': SeverityLevel.MEDIUM,
                'desc': 'User input in logs'
            },
            {
                'pattern': r'json\.dumps\s*\([^)]*ensure_ascii\s*=\s*False',
                'title': 'JSON output without ASCII encoding',
                'severity': SeverityLevel.LOW,
                'desc': 'May allow Unicode injection'
            },
            {
                'pattern': r'return\s+.*?\+.*?user.*?\+',
                'title': 'String concatenation with user input',
                'severity': SeverityLevel.MEDIUM,
                'desc': 'Unsafe string building'
            }
        ]

        for file_path in Path(repo_path).rglob('*'):
            if file_path.suffix in ['.py', '.js', '.ts'] and file_path.is_file():
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check if this file contains MCP tools
                    if '@mcp.tool' in content or '@tool' in content or 'def tool_' in content:
                        for pattern_info in unsafe_patterns:
                            matches = re.finditer(pattern_info['pattern'], content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                findings.append(self.create_finding(
                                    vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                                    severity=pattern_info['severity'],
                                    confidence=0.7,
                                    title=pattern_info['title'],
                                    description=f"Tool output may contain unsanitized content: {pattern_info['desc']}",
                                    location=f"{file_path.relative_to(repo_path)}:{line_num}",
                                    recommendation="Sanitize all tool outputs before returning",
                                    evidence={'matched_pattern': match.group(0)[:100]}
                                ))
                except:
                    continue

        return findings

    async def _analyze_resource_prompt_injection(self, repo_path: str) -> List[Finding]:
        """Check for prompt injection in MCP resource content (Challenge 1 gap)"""
        findings = []

        # Look for resource files and content
        resource_patterns = [
            '*resource*.json', '*resource*.yaml', '*resource*.yml',
            'resources/**/*.json', 'resources/**/*.yaml', 'resources/**/*.txt', 'resources/**/*.md'
        ]

        for pattern in resource_patterns:
            for file_path in Path(repo_path).rglob(pattern):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check if this looks like resource content
                    if any(indicator in content.lower() for indicator in 
                           ['resource', 'note', 'message', 'content', 'data']):
                        
                        # Check for prompt injection patterns
                        injection_findings = self._check_text_for_injection(
                            content,
                            str(file_path.relative_to(repo_path)),
                            "Resource content"
                        )
                        
                        if injection_findings:
                            # Upgrade severity for resource-based injection
                            for finding in injection_findings:
                                finding.title = f"Resource-based {finding.title}"
                                finding.description = f"Resource file contains prompt injection that could manipulate LLM behavior when accessed"
                                finding.vulnerability_type = VulnerabilityType.PROMPT_INJECTION
                                finding.severity = SeverityLevel.CRITICAL  # Resources are directly fed to LLM
                                finding.confidence = 0.95
                                
                        findings.extend(injection_findings)

                        # Also check for user input placeholders that might be injectable
                        user_input_patterns = [
                            r'\{\{.*?user.*?\}\}',
                            r'\$\{.*?input.*?\}',
                            r'\{.*?user_input.*?\}',
                            r'USER_INPUT_HERE',
                            r'REPLACE_WITH_USER_DATA'
                        ]
                        
                        for pattern in user_input_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                findings.append(self.create_finding(
                                    vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                                    severity=SeverityLevel.HIGH,
                                    confidence=0.8,
                                    title="Unsanitized user input placeholder in resource",
                                    description="Resource contains user input placeholder without validation",
                                    location=str(file_path.relative_to(repo_path)),
                                    recommendation="Validate and sanitize user input before inserting into resource content",
                                    evidence={'pattern': pattern, 'context': 'resource_content'}
                                ))
                                break

                except Exception as e:
                    self.logger.debug(f"Failed to analyze resource file {file_path}: {e}")

        # Also check Python/JS code for dynamic resource content creation
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Look for MCP resource handlers that build content from user input
                resource_handler_patterns = [
                    r'@mcp\.resource\s*\(.*?\)\s*(?:async\s+)?def\s+(\w+)',
                    r'def\s+get_resource.*?\([^)]*\)\s*:',
                    r'def\s+.*resource.*?\([^)]*\)\s*:',
                    r'class.*Resource.*:'
                ]

                for pattern in resource_handler_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        # Check if this resource handler does unsafe string operations
                        if re.search(r'return\s+f["\'][^"\']*(\{[^}]*user[^}]*\}|\{[^}]*input[^}]*\}|\{[^}]*request[^}]*\})', content):
                            findings.append(self.create_finding(
                                vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                                severity=SeverityLevel.HIGH,
                                confidence=0.9,
                                title="Resource handler with unsanitized user input",
                                description="MCP resource handler directly interpolates user input without sanitization",
                                location=str(file_path.relative_to(repo_path)),
                                recommendation="Sanitize and validate all user input before including in resource content",
                                evidence={'handler_type': 'resource_handler'}
                            ))

            except Exception as e:
                self.logger.debug(f"Failed to analyze {file_path}: {e}")

        return findings

    async def _analyze_indirect_prompt_injection(self, repo_path: str) -> List[Finding]:
        """Check for indirect prompt injection via external data processing (Challenge 6 gap)"""
        findings = []

        # Patterns for external data sources
        external_data_patterns = [
            # Web scraping/fetching
            (r'requests\.(get|post)\s*\([^)]*url', 'HTTP request'),
            (r'fetch\s*\([^)]*http', 'Fetch request'),
            (r'urllib\.request\.urlopen', 'URL request'),
            (r'scrapy', 'Web scraping'),
            (r'BeautifulSoup', 'HTML parsing'),
            
            # File/document processing
            (r'open\s*\([^)]*user.*?\)', 'User-specified file'),
            (r'pd\.read_csv\s*\([^)]*user', 'CSV from user input'),
            (r'json\.load\s*\([^)]*user', 'JSON from user input'),
            (r'yaml\.load\s*\([^)]*user', 'YAML from user input'),
            
            # Database queries with external content
            (r'SELECT.*FROM.*WHERE.*user', 'Database query with user data'),
            (r'db\.query\s*\([^)]*user', 'Database query'),
            
            # API integrations
            (r'api\.get.*user', 'API call with user data'),
            (r'client\.(get|post).*user', 'Client request with user data'),
        ]

        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Check if this file has MCP tools
                if '@mcp.tool' in content or 'def tool_' in content:
                    for pattern, source_type in external_data_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            # Check if the external data is processed without sanitization
                            function_content = self._extract_function_around_match(content, match.start())
                            
                            # Look for signs that external data is passed directly to LLM
                            if any(direct_use in function_content.lower() for direct_use in 
                                   ['return', 'response', 'result', 'output', 'content']):
                                
                                # Check if there's no sanitization
                                has_sanitization = any(sanitize in function_content.lower() for sanitize in 
                                                     ['sanitize', 'clean', 'escape', 'validate', 'filter', 'strip_tags'])
                                
                                if not has_sanitization:
                                    line_num = content[:match.start()].count('\n') + 1
                                    findings.append(self.create_finding(
                                        vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                                        severity=SeverityLevel.HIGH,
                                        confidence=0.8,
                                        title=f"Indirect prompt injection via {source_type}",
                                        description=f"Tool processes external data without sanitization, allowing indirect prompt injection",
                                        location=f"{file_path.relative_to(repo_path)}:{line_num}",
                                        recommendation="Sanitize and validate all external data before processing or presenting to LLM",
                                        evidence={'source_type': source_type, 'pattern': match.group(0)}
                                    ))

            except Exception as e:
                self.logger.debug(f"Failed to analyze {file_path}: {e}")

        return findings

    def _extract_function_around_match(self, content: str, match_pos: int, context_lines: int = 10) -> str:
        """Extract function context around a regex match"""
        lines = content.split('\n')
        match_line = content[:match_pos].count('\n')
        
        start_line = max(0, match_line - context_lines)
        end_line = min(len(lines), match_line + context_lines + 1)
        
        return '\n'.join(lines[start_line:end_line])

    async def _analyze_permission_scope_violations(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Enhanced permission scope analysis (Challenge 3 gap)"""
        findings = []

        # Get declared permissions from MCP config
        mcp_config = project_info.get('mcp_config', {})
        declared_permissions = mcp_config.get('permissions', {}) if isinstance(mcp_config, dict) else {}
        
        # Enhanced permission scope patterns
        scope_violation_patterns = {
            'file_browser_tool': {
                'declared_scope': ['read_only', 'specific_directory'],
                'violation_patterns': [
                    (r'os\.remove\s*\(', 'file deletion'),
                    (r'shutil\.rmtree\s*\(', 'directory deletion'),
                    (r'open\s*\([^)]+["\']w["\']', 'file writing'),
                    (r'Path\s*\([^)]+\)\.mkdir', 'directory creation'),
                    (r'os\.chmod\s*\(', 'permission changes'),
                    (r'subprocess.*rm\s+-rf', 'shell file deletion')
                ]
            },
            'network_tool': {
                'declared_scope': ['read_only', 'specific_domains'],
                'violation_patterns': [
                    (r'requests\.(post|put|patch|delete)', 'HTTP write operations'),
                    (r'socket\.socket\s*\(', 'raw socket access'),
                    (r'ftp\.(put|delete)', 'FTP write operations'),
                    (r'smtp\.(send|deliver)', 'email sending'),
                    (r'192\.168\.|10\.|172\.', 'internal network access'),
                    (r'localhost|127\.0\.0\.1', 'local network access')
                ]
            },
            'system_tool': {
                'declared_scope': ['read_only', 'specific_commands'],
                'violation_patterns': [
                    (r'subprocess.*sudo', 'privilege escalation'),
                    (r'os\.setuid|os\.setgid', 'user/group changes'),
                    (r'ctypes.*kernel32', 'system API access'),
                    (r'subprocess.*(?:rm|del|format|fdisk)', 'destructive commands'),
                    (r'import\s+win32api|import\s+win32security', 'Windows API access')
                ]
            }
        }

        # Analyze each Python file for scope violations
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Check if this file contains MCP tools
                if '@mcp.tool' in content or 'def tool_' in content:
                    
                    # Extract tool names
                    tool_pattern = r'(?:@mcp\.tool\s*\(\s*\)\s*)?(?:async\s+)?def\s+(\w+)'
                    tool_matches = re.finditer(tool_pattern, content)
                    
                    for tool_match in tool_matches:
                        tool_name = tool_match.group(1)
                        
                        # Determine tool type from name
                        tool_type = None
                        if any(keyword in tool_name.lower() for keyword in ['file', 'browse', 'read', 'write']):
                            tool_type = 'file_browser_tool'
                        elif any(keyword in tool_name.lower() for keyword in ['network', 'request', 'http', 'api']):
                            tool_type = 'network_tool'
                        elif any(keyword in tool_name.lower() for keyword in ['system', 'command', 'execute', 'run']):
                            tool_type = 'system_tool'
                        
                        if tool_type and tool_type in scope_violation_patterns:
                            # Check for scope violations
                            violations = scope_violation_patterns[tool_type]['violation_patterns']
                            
                            for violation_pattern, violation_desc in violations:
                                if re.search(violation_pattern, content, re.IGNORECASE):
                                    # Extract the function to see if this violation is in the same function
                                    func_start = tool_match.start()
                                    func_content = self._extract_function_content(content, func_start)
                                    
                                    if re.search(violation_pattern, func_content, re.IGNORECASE):
                                        findings.append(self.create_finding(
                                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                                            severity=SeverityLevel.HIGH,
                                            confidence=0.85,
                                            title=f"Permission scope violation in '{tool_name}'",
                                            description=f"Tool '{tool_name}' performs {violation_desc} beyond its intended scope",
                                            location=f"{file_path.relative_to(repo_path)}:{tool_name}",
                                            recommendation="Limit tool functionality to match declared permissions and intended purpose",
                                            evidence={
                                                'tool_type': tool_type,
                                                'violation': violation_desc,
                                                'pattern': violation_pattern
                                            }
                                        ))

            except Exception as e:
                self.logger.debug(f"Failed to analyze {file_path}: {e}")

        # Check for overly broad file path access patterns
        broad_path_patterns = [
            (r'os\.path\.join\s*\(\s*["\'][/\\\\]?["\']', 'root directory access'),
            (r'Path\s*\(["\']/?["\']', 'root path access'),
            (r'glob\.glob\s*\(["\'][/*].*?["\']', 'wildcard file access'),
            (r'os\.walk\s*\(["\'][/\\\\]?["\']', 'full filesystem traversal'),
            (r'\.\./', 'path traversal patterns')
        ]

        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                if '@mcp.tool' in content:
                    for pattern, desc in broad_path_patterns:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            findings.append(self.create_finding(
                                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                                severity=SeverityLevel.MEDIUM,
                                confidence=0.7,
                                title=f"Overly broad file access: {desc}",
                                description="Tool may access files outside intended scope",
                                location=f"{file_path.relative_to(repo_path)}:{line_num}",
                                recommendation="Restrict file access to specific directories and validate all paths",
                                evidence={'access_type': desc}
                            ))

            except Exception as e:
                self.logger.debug(f"Failed to analyze {file_path}: {e}")

        return findings

    async def _validate_mcp_protocol(self, repo_path: str) -> List[Finding]:
        """Validate MCP protocol compliance"""
        findings = []
        
        # Check for protocol compliance issues
        # This validates against MCP specification
        findings.extend(await self._check_json_rpc_compliance(repo_path))
        
        return findings

    async def _check_json_rpc_compliance(self, repo_path: str) -> List[Finding]:
        """Check JSON-RPC 2.0 compliance in MCP implementations"""
        findings = []
        
        # Look for JSON-RPC message handling
        jsonrpc_patterns = [
            r'["\']jsonrpc["\']\\s*:\\s*["\']2\\.0["\']',
            r'["\']method["\']',
            r'["\']params["\']',
            r'["\']id["\']'
        ]
        
        for file_path in Path(repo_path).rglob('*.{py,js,ts}'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Check if file handles JSON-RPC
                if any(re.search(pattern, content, re.IGNORECASE) for pattern in jsonrpc_patterns):
                    # Look for potential protocol violations
                    if 'jsonrpc' in content.lower() and '2.0' not in content:
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.GENERIC,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.8,
                            title="Potential JSON-RPC version mismatch",
                            description="File handles JSON-RPC but may not specify version 2.0",
                            location=str(file_path.relative_to(repo_path)),
                            recommendation="Ensure JSON-RPC 2.0 compliance for MCP compatibility"
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking JSON-RPC compliance in {file_path}: {e}")
        
        return findings

    async def _check_capability_leakage(self, repo_path: str) -> List[Finding]:
        """Check for capability leakage in MCP implementation"""
        findings = []
        
        # Look for overly broad capability exposure
        capability_patterns = [
            (r'capabilities.*\\[\\s*["\'].*["\']\\s*\\]', 'Broad capability exposure'),
            (r'expose.*all.*capabilities', 'All capabilities exposed'),
            (r'unrestricted.*access', 'Unrestricted access pattern')
        ]
        
        for file_path in Path(repo_path).rglob('*.{py,js,ts}'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, description in capability_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\\n') + 1
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.7,
                            title=f"Potential capability leakage: {description}",
                            description=f"MCP implementation may expose capabilities too broadly",
                            location=f"{file_path.relative_to(repo_path)}:{line_num}",
                            recommendation="Implement principle of least privilege for MCP capabilities",
                            evidence={'pattern': match.group(0)}
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking capability leakage in {file_path}: {e}")
        
        return findings

    async def _check_unauthorized_access(self, repo_path: str) -> List[Finding]:
        """Check for unauthorized access patterns"""
        findings = []
        
        # Look for missing authorization checks
        auth_patterns = [
            r'@mcp\\.tool.*\\n(?!.*(?:auth|permission|check|validate))',
            r'@mcp\\.resource.*\\n(?!.*(?:auth|permission|check|validate))',
            r'def\\s+\\w+.*\\n\\s*""".*tool.*"""(?!.*auth)'
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in auth_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\\n') + 1
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.6,
                            title="MCP tool/resource without authorization check",
                            description="MCP tool or resource may lack proper authorization",
                            location=f"{file_path.relative_to(repo_path)}:{line_num}",
                            recommendation="Add authorization checks to MCP tools and resources",
                            evidence={'context': match.group(0)[:100]}
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking authorization in {file_path}: {e}")
        
        return findings

    async def _check_data_exposure(self, repo_path: str) -> List[Finding]:
        """Check for data exposure in MCP resources"""
        findings = []
        
        # Look for potentially sensitive data exposure
        exposure_patterns = [
            (r'@mcp\\.resource.*\\n.*user.*data', 'User data exposure'),
            (r'@mcp\\.resource.*\\n.*sensitive', 'Sensitive data exposure'),
            (r'@mcp\\.resource.*\\n.*private', 'Private data exposure'),
            (r'return.*user.*\\+.*secret', 'Data mixing with secrets')
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, description in exposure_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\\n') + 1
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.DATA_EXPOSURE,
                            severity=SeverityLevel.HIGH,
                            confidence=0.7,
                            title=f"Potential data exposure: {description}",
                            description=f"MCP resource may expose sensitive data inappropriately",
                            location=f"{file_path.relative_to(repo_path)}:{line_num}",
                            recommendation="Review and restrict data exposure in MCP resources",
                            evidence={'pattern': match.group(0)[:100]}
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking data exposure in {file_path}: {e}")
        
        return findings

    async def _check_tool_abuse_potential(self, repo_path: str) -> List[Finding]:
        """Check for tool abuse potential"""
        findings = []
        
        # Look for tools that could be abused
        abuse_patterns = [
            (r'@mcp\\.tool.*\\n.*delete.*file', 'File deletion capability'),
            (r'@mcp\\.tool.*\\n.*network.*request', 'Network request capability'),
            (r'@mcp\\.tool.*\\n.*database.*query', 'Database query capability'),
            (r'@mcp\\.tool.*\\n.*admin.*privilege', 'Administrative privilege')
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, description in abuse_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\\n') + 1
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.7,
                            title=f"Potential tool abuse: {description}",
                            description=f"MCP tool with {description.lower()} could be abused",
                            location=f"{file_path.relative_to(repo_path)}:{line_num}",
                            recommendation="Implement proper access controls and validation for powerful tools",
                            evidence={'capability': description}
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking tool abuse in {file_path}: {e}")
        
        return findings

    def _extract_function_content(self, content: str, func_start_pos: int) -> str:
        """Extract the complete function content starting from func_start_pos"""
        lines = content.split('\n')
        start_line = content[:func_start_pos].count('\n')
        
        # Find function end by looking for the next function or class definition
        function_lines = []
        in_function = False
        base_indent = None
        
        for i in range(start_line, len(lines)):
            line = lines[i]
            
            # Start of our function
            if not in_function and ('def ' in line or 'async def' in line):
                in_function = True
                base_indent = len(line) - len(line.lstrip())
                function_lines.append(line)
                continue
            
            if in_function:
                # Empty lines are okay
                if not line.strip():
                    function_lines.append(line)
                    continue
                    
                # Calculate current indentation
                current_indent = len(line) - len(line.lstrip())
                
                # If we hit a line with equal or less indentation that's not empty,
                # and it's not a decorator, we've reached the end
                if current_indent <= base_indent and not line.strip().startswith('@'):
                    break
                    
                function_lines.append(line)
        
        return '\n'.join(function_lines)

    async def _check_dangerous_resource_patterns(self, repo_path: str) -> List[Finding]:
        """Check for dangerous resource URI patterns like system://, internal:// etc."""
        findings = []
        
        # Dangerous resource URI patterns
        dangerous_patterns = [
            (r'@\w*\.resource\(["\']system://[^"\']*["\']', 'system://', 'System resource access'),
            (r'@\w*\.resource\(["\']internal://[^"\']*["\']', 'internal://', 'Internal resource access'),  
            (r'@\w*\.resource\(["\']admin://[^"\']*["\']', 'admin://', 'Admin resource access'),
            (r'@\w*\.resource\(["\']secret://[^"\']*["\']', 'secret://', 'Secret resource access'),
            (r'@\w*\.resource\(["\']credential://[^"\']*["\']', 'credential://', 'Credential resource access'),
            (r'@\w*\.resource\(["\']config://[^"\']*["\']', 'config://', 'Configuration resource access'),
            (r'@\w*\.resource\([^"\']*listed=False', 'listed=False', 'Hidden resource'),
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, uri_scheme, description in dangerous_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Get context around the match
                        lines = content.split('\n')
                        context_start = max(0, line_num - 3)
                        context_end = min(len(lines), line_num + 3)
                        context = '\n'.join(lines[context_start:context_end])
                        
                        severity = SeverityLevel.CRITICAL if uri_scheme.startswith(('system://', 'admin://', 'secret://')) else SeverityLevel.HIGH
                        
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.DATA_LEAKAGE,
                            severity=severity,
                            confidence=0.9,
                            title=f"Dangerous resource pattern: {description}",
                            description=f"MCP resource uses potentially dangerous URI pattern '{uri_scheme}' that may expose sensitive data",
                            location=f"{file_path.relative_to(repo_path)}:{line_num}",
                            recommendation=f"Avoid exposing {description.lower()} through MCP resources. Use proper access controls and data sanitization.",
                            evidence={
                                'uri_pattern': uri_scheme,
                                'resource_type': description,
                                'context': context
                            }
                        ))
                        
            except Exception as e:
                logger.debug(f"Error checking resource patterns in {file_path}: {e}")
        
        return findings

    async def _check_tool_shadowing_risks(self, repo_path: str) -> List[Finding]:
        """Check for potential tool shadowing vulnerabilities"""
        findings = []
        
        # Track tool names across files and servers
        tool_definitions = {}
        server_tools = {}
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Find MCP tool definitions
                tool_patterns = [
                    r'@\w*\.tool\(\s*(?:name\s*=\s*["\']([^"\']+)["\'])?.*?\)\s*\ndef\s+(\w+)',
                    r'@\w*\.tool\(\)\s*\ndef\s+(\w+)',
                ]
                
                for pattern in tool_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        if len(match.groups()) == 2:  # name and function
                            tool_name = match.group(1) if match.group(1) else match.group(2)
                            func_name = match.group(2)
                        else:  # just function name
                            tool_name = func_name = match.group(1)
                        
                        line_num = content[:match.start()].count('\n') + 1
                        
                        # Track tool definition
                        tool_key = tool_name.lower()
                        if tool_key not in tool_definitions:
                            tool_definitions[tool_key] = []
                        
                        tool_definitions[tool_key].append({
                            'name': tool_name,
                            'function': func_name, 
                            'file': str(file_path.relative_to(repo_path)),
                            'line': line_num,
                            'context': content[max(0, match.start()-100):match.end()+100]
                        })
                
                # Check for multiple server instances
                server_patterns = [
                    r'(\w+)\s*=\s*FastMCP\s*\(\s*["\']([^"\']+)["\']',
                    r'(\w+)\s*=\s*MCPServer\s*\(\s*["\']([^"\']+)["\']',
                ]
                
                for pattern in server_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        server_var = match.group(1)
                        server_name = match.group(2)
                        server_tools[server_var] = server_name
                        
            except Exception as e:
                logger.debug(f"Error checking tool shadowing in {file_path}: {e}")
        
        # Check for duplicate tool names
        for tool_name, definitions in tool_definitions.items():
            if len(definitions) > 1:
                # Multiple tools with the same name - potential shadowing
                for i, definition in enumerate(definitions):
                    is_suspicious = False
                    suspicious_indicators = []
                    
                    # Check for suspicious patterns in duplicate tools
                    context = definition['context'].lower()
                    if any(keyword in context for keyword in ['hidden', 'secret', 'malicious', 'shadow', 'override']):
                        is_suspicious = True
                        suspicious_indicators.append('Contains suspicious keywords')
                    
                    if any(pattern in context for pattern in ['<hidden>', '<secret>', '<important>']):
                        is_suspicious = True
                        suspicious_indicators.append('Contains hidden directive markers')
                    
                    # Check for tools with identical names but different behaviors
                    if len(set(d['function'] for d in definitions)) > 1:
                        is_suspicious = True
                        suspicious_indicators.append('Same tool name but different function implementations')
                    
                    severity = SeverityLevel.HIGH if is_suspicious else SeverityLevel.MEDIUM
                    confidence = 0.8 if is_suspicious else 0.6
                    
                    other_locations = [f"{d['file']}:{d['line']}" for j, d in enumerate(definitions) if j != i]
                    
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.TOOL_MANIPULATION,
                        severity=severity,
                        confidence=confidence,
                        title=f"Potential tool shadowing: Duplicate tool '{tool_name}'",
                        description=f"Tool '{tool_name}' is defined multiple times, which could lead to tool shadowing attacks where a malicious tool overrides a legitimate one",
                        location=f"{definition['file']}:{definition['line']}",
                        recommendation="Use unique tool names or implement proper namespacing to prevent tool shadowing. Review all tool definitions for malicious intent.",
                        evidence={
                            'tool_name': tool_name,
                            'duplicate_count': len(definitions),
                            'other_locations': other_locations,
                            'suspicious_indicators': suspicious_indicators,
                            'function_names': [d['function'] for d in definitions]
                        }
                    ))
        
        # Check for potentially malicious tool names that could shadow common tools
        common_tool_names = {
            'calculate', 'calculator', 'compute', 'eval', 'execute', 'run', 'command',
            'file_read', 'file_write', 'read_file', 'write_file', 'get_file', 'save_file',
            'search', 'query', 'find', 'lookup', 'fetch', 'get', 'retrieve',
            'system', 'admin', 'config', 'settings', 'status', 'info'
        }
        
        for tool_name, definitions in tool_definitions.items():
            if tool_name in common_tool_names and len(definitions) == 1:
                definition = definitions[0]
                context = definition['context'].lower()
                
                # Check if this common tool name has suspicious content
                if any(pattern in context for pattern in ['<hidden>', '<secret>', '<important>', 'malicious']):
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.TOOL_POISONING,
                        severity=SeverityLevel.HIGH,
                        confidence=0.7,
                        title=f"Suspicious common tool name: '{tool_name}'",
                        description=f"Tool uses common name '{tool_name}' which could shadow legitimate tools, and contains suspicious patterns",
                        location=f"{definition['file']}:{definition['line']}",
                        recommendation="Avoid using common tool names for tools with suspicious functionality. Use specific, descriptive names.",
                        evidence={
                            'tool_name': tool_name,
                            'common_name': True,
                            'suspicious_content': True
                        }
                    ))
        
        return findings