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
    """

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
            'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
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
        """Check for permission abuse"""
        findings = []

        # Check if declared permissions match actual usage
        mcp_config = project_info.get('mcp_config') or {}
        declared_permissions = mcp_config.get('permissions', {}) if isinstance(mcp_config, dict) else {}

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