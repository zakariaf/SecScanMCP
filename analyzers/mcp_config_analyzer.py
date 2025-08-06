"""
MCP Configuration Analyzer - Native MCP Protocol Understanding
"""

import json
import yaml
import re
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import logging

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class MCPConfigAnalyzer(BaseAnalyzer):
    """
    Analyzes MCP configurations with native protocol understanding
    
    Features:
    - MCP client configuration discovery (Claude, Cursor, Windsurf, etc.)
    - Protocol-specific validation
    - Tool, Resource, and Prompt analysis
    - Server capability assessment
    - Security policy validation
    """

    # MCP Client Configuration Paths
    MCP_CLIENT_CONFIGS = {
        'claude': [
            '~/.config/Claude/claude_desktop_config.json',
            '~/Library/Application Support/Claude/claude_desktop_config.json',
            '%APPDATA%/Claude/claude_desktop_config.json'
        ],
        'cursor': [
            '~/.config/Cursor/User/globalStorage/cursor.mcp/cursor_mcp_config.json',
            '~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/cursor_mcp_config.json'
        ],
        'windsurf': [
            '~/.config/Windsurf/User/globalStorage/windsurf.mcp/windsurf_mcp_config.json'
        ]
    }

    # MCP Protocol Specification Patterns
    MCP_SERVER_TYPES = ['stdio', 'sse', 'http']
    MCP_CAPABILITIES = ['tools', 'resources', 'prompts', 'sampling']
    
    # Security-relevant MCP patterns
    SECURITY_PATTERNS = {
        'dangerous_commands': [
            r'rm\s+-rf',
            r'sudo\s+',
            r'chmod\s+777',
            r'exec\s*\(',
            r'eval\s*\(',
            r'subprocess\.call',
            r'os\.system'
        ],
        'credential_exposure': [
            r'["\']?api[_-]?key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'["\']?token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'["\']?password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'Bearer\s+[A-Za-z0-9\-._~+/]+'
        ],
        'network_access': [
            r'https?://[^\s"\']+',
            r'ftp://[^\s"\']+',
            r'localhost:\d+',
            r'127\.0\.0\.1:\d+',
            r'0\.0\.0\.0:\d+'
        ]
    }

    def __init__(self):
        super().__init__()
        self.discovered_configs = {}
        self.mcp_servers = {}

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze repository with MCP-native understanding"""
        findings = []

        # 1. Discover MCP configurations
        config_findings = await self._discover_mcp_configurations(repo_path)
        findings.extend(config_findings)

        # 2. Parse and validate MCP server implementations  
        server_findings = await self._analyze_mcp_servers(repo_path)
        findings.extend(server_findings)

        # 3. Analyze tool interactions and capabilities
        interaction_findings = await self._analyze_tool_interactions(repo_path)
        findings.extend(interaction_findings)

        # 4. Validate MCP protocol compliance
        protocol_findings = await self._validate_mcp_protocol(repo_path)
        findings.extend(protocol_findings)

        # 5. Assess MCP-specific security risks
        security_findings = await self._assess_mcp_security_risks(repo_path)
        findings.extend(security_findings)

        logger.info(f"MCP Config analyzer found {len(findings)} issues")
        return findings

    async def _discover_mcp_configurations(self, repo_path: str) -> List[Finding]:
        """Discover MCP client and server configurations"""
        findings = []
        
        # Look for MCP configuration files
        config_patterns = [
            '**/mcp*.json',
            '**/mcp*.yaml', 
            '**/*mcp*.json',
            '**/claude_desktop_config.json',
            '**/cursor_mcp_config.json',
            '**/.config/mcp/*.json'
        ]

        for pattern in config_patterns:
            for config_file in Path(repo_path).rglob(pattern):
                try:
                    findings.extend(await self._analyze_config_file(config_file, repo_path))
                except Exception as e:
                    logger.debug(f"Failed to analyze config {config_file}: {e}")

        # Check for embedded MCP servers (Python/JS)
        findings.extend(await self._find_embedded_mcp_servers(repo_path))

        return findings

    async def _analyze_config_file(self, config_file: Path, repo_path: str) -> List[Finding]:
        """Analyze individual MCP configuration file"""
        findings = []
        
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                if config_file.suffix == '.json':
                    config = json.load(f)
                else:
                    config = yaml.safe_load(f)

            # Validate MCP configuration structure
            findings.extend(self._validate_config_structure(config, config_file, repo_path))
            
            # Check for security issues in configuration
            findings.extend(self._check_config_security(config, config_file, repo_path))
            
            # Analyze server definitions
            if 'mcpServers' in config:
                findings.extend(self._analyze_server_definitions(
                    config['mcpServers'], config_file, repo_path
                ))

        except json.JSONDecodeError as e:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.MEDIUM,
                confidence=0.9,
                title="Invalid JSON in MCP configuration",
                description=f"MCP configuration file contains invalid JSON: {str(e)}",
                location=str(config_file.relative_to(repo_path)),
                recommendation="Fix JSON syntax errors in MCP configuration"
            ))
        except Exception as e:
            logger.debug(f"Error analyzing config {config_file}: {e}")

        return findings

    def _validate_config_structure(self, config: Dict, config_file: Path, repo_path: str) -> List[Finding]:
        """Validate MCP configuration against protocol specification"""
        findings = []
        
        # Check for required MCP structure
        if not isinstance(config, dict):
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                title="Invalid MCP configuration structure",
                description="MCP configuration must be a JSON object",
                location=str(config_file.relative_to(repo_path)),
                recommendation="Ensure MCP configuration follows protocol specification"
            ))
            return findings

        # Check for MCP-specific fields
        mcp_fields = ['mcpServers', 'servers', 'tools', 'resources', 'prompts']
        has_mcp_field = any(field in config for field in mcp_fields)
        
        if not has_mcp_field:
            # This might not be an MCP config file
            return findings

        # Validate server configurations
        servers = config.get('mcpServers', config.get('servers', {}))
        if servers:
            for server_name, server_config in servers.items():
                findings.extend(self._validate_server_config(
                    server_name, server_config, config_file, repo_path
                ))

        return findings

    def _validate_server_config(self, name: str, server_config: Dict, config_file: Path, repo_path: str) -> List[Finding]:
        """Validate individual server configuration"""
        findings = []
        
        # Check for required fields
        if 'command' not in server_config and 'url' not in server_config:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.HIGH,
                confidence=0.9,
                title=f"Invalid MCP server configuration: {name}",
                description="MCP server must specify either 'command' or 'url'",
                location=f"{config_file.relative_to(repo_path)}:servers.{name}",
                recommendation="Add required 'command' or 'url' field to server configuration"
            ))

        # Check transport type
        transport_type = server_config.get('type', 'stdio')
        if transport_type not in self.MCP_SERVER_TYPES:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                title=f"Unknown MCP transport type: {transport_type}",
                description=f"Server '{name}' uses unknown transport type '{transport_type}'",
                location=f"{config_file.relative_to(repo_path)}:servers.{name}.type",
                recommendation=f"Use standard MCP transport types: {', '.join(self.MCP_SERVER_TYPES)}"
            ))

        # Check for security issues in server configuration
        findings.extend(self._check_server_security(name, server_config, config_file, repo_path))

        return findings

    def _check_config_security(self, config: Dict, config_file: Path, repo_path: str) -> List[Finding]:
        """Check MCP configuration for security issues"""
        findings = []
        
        config_str = json.dumps(config)
        
        # Check for credential exposure
        for pattern in self.SECURITY_PATTERNS['credential_exposure']:
            matches = re.finditer(pattern, config_str, re.IGNORECASE)
            for match in matches:
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                    severity=SeverityLevel.CRITICAL,
                    confidence=0.9,
                    title="Hardcoded credentials in MCP configuration",
                    description="MCP configuration contains hardcoded credentials",
                    location=str(config_file.relative_to(repo_path)),
                    recommendation="Use environment variables or secure credential storage",
                    evidence={'credential_pattern': match.group(0)[:50] + '...'}
                ))

        return findings

    def _check_server_security(self, name: str, server_config: Dict, config_file: Path, repo_path: str) -> List[Finding]:
        """Check individual server configuration for security issues"""
        findings = []
        
        # Check command execution security
        command = server_config.get('command', '')
        if command:
            for pattern in self.SECURITY_PATTERNS['dangerous_commands']:
                if re.search(pattern, command, re.IGNORECASE):
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                        severity=SeverityLevel.HIGH,
                        confidence=0.8,
                        title=f"Dangerous command in MCP server '{name}'",
                        description=f"Server '{name}' uses potentially dangerous command: {command}",
                        location=f"{config_file.relative_to(repo_path)}:servers.{name}.command",
                        recommendation="Review and restrict server command execution"
                    ))

        # Check network access
        url = server_config.get('url', '')
        if url:
            for pattern in self.SECURITY_PATTERNS['network_access']:
                if re.search(pattern, url, re.IGNORECASE):
                    # Check for localhost/internal access
                    if 'localhost' in url.lower() or '127.0.0.1' in url:
                        findings.append(self.create_finding(
                            vulnerability_type=VulnerabilityType.SSRF,
                            severity=SeverityLevel.MEDIUM,
                            confidence=0.7,
                            title=f"Local network access in MCP server '{name}'",
                            description=f"Server '{name}' accesses local network: {url}",
                            location=f"{config_file.relative_to(repo_path)}:servers.{name}.url",
                            recommendation="Ensure local network access is intentional and secure"
                        ))

        # Check environment variable exposure
        env_vars = server_config.get('env', {})
        if env_vars:
            for var_name, var_value in env_vars.items():
                if not var_value.startswith('${') and any(secret in var_name.lower() 
                                                         for secret in ['token', 'key', 'password', 'secret']):
                    findings.append(self.create_finding(
                        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
                        severity=SeverityLevel.HIGH,
                        confidence=0.8,
                        title=f"Hardcoded secret in MCP server '{name}' environment",
                        description=f"Environment variable '{var_name}' may contain hardcoded secret",
                        location=f"{config_file.relative_to(repo_path)}:servers.{name}.env.{var_name}",
                        recommendation="Use environment variable references like ${VAR_NAME}"
                    ))

        return findings

    async def _find_embedded_mcp_servers(self, repo_path: str) -> List[Finding]:
        """Find MCP servers embedded in code"""
        findings = []
        
        # Python MCP server patterns
        python_patterns = [
            r'from\s+mcp\s+import',
            r'import\s+mcp',
            r'@mcp\.tool',
            r'@mcp\.resource',
            r'@mcp\.prompt',
            r'FastMCP\s*\(',
            r'MCPServer\s*\('
        ]
        
        # JavaScript/TypeScript MCP patterns
        js_patterns = [
            r'from\s+["\']@modelcontextprotocol',
            r'require\s*\(\s*["\']@modelcontextprotocol',
            r'createServer\s*\(',
            r'\.tool\s*\(',
            r'\.resource\s*\(',
            r'\.prompt\s*\('
        ]

        # Scan Python files
        for py_file in Path(repo_path).rglob('*.py'):
            findings.extend(await self._analyze_embedded_server(py_file, python_patterns, repo_path))

        # Scan JavaScript/TypeScript files  
        for js_file in Path(repo_path).rglob('*.{js,ts}'):
            findings.extend(await self._analyze_embedded_server(js_file, js_patterns, repo_path))

        return findings

    async def _analyze_embedded_server(self, file_path: Path, patterns: List[str], repo_path: str) -> List[Finding]:
        """Analyze embedded MCP server implementation"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Check if this file contains MCP server code
            is_mcp_server = any(re.search(pattern, content, re.IGNORECASE) for pattern in patterns)
            
            if is_mcp_server:
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.GENERIC,
                    severity=SeverityLevel.INFO,
                    confidence=0.9,
                    title="MCP server implementation detected",
                    description=f"File implements an MCP server: {file_path.name}",
                    location=str(file_path.relative_to(repo_path)),
                    recommendation="Ensure MCP server follows security best practices",
                    evidence={'server_type': 'embedded', 'language': file_path.suffix[1:]}
                ))
                
                # Analyze the MCP server for security issues
                findings.extend(await self._analyze_server_implementation(file_path, content, repo_path))

        except Exception as e:
            logger.debug(f"Error analyzing embedded server {file_path}: {e}")

        return findings

    async def _analyze_server_implementation(self, file_path: Path, content: str, repo_path: str) -> List[Finding]:
        """Analyze MCP server implementation for security issues"""
        findings = []
        
        # Check for dangerous patterns in MCP server code
        dangerous_patterns = [
            (r'@mcp\.tool.*\n.*exec\s*\(', 'Tool with exec() usage', SeverityLevel.CRITICAL),
            (r'@mcp\.tool.*\n.*eval\s*\(', 'Tool with eval() usage', SeverityLevel.CRITICAL),
            (r'@mcp\.tool.*\n.*os\.system', 'Tool with os.system() usage', SeverityLevel.HIGH),
            (r'@mcp\.tool.*\n.*subprocess.*shell\s*=\s*True', 'Tool with shell injection risk', SeverityLevel.HIGH),
            (r'@mcp\.resource.*\n.*open\s*\([^)]*user', 'Resource with user-controlled file access', SeverityLevel.HIGH),
            (r'@mcp\.prompt.*\n.*f["\'][^"\']*\{.*user', 'Prompt with unsanitized user input', SeverityLevel.MEDIUM)
        ]
        
        for pattern, description, severity in dangerous_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    severity=severity,
                    confidence=0.8,
                    title=f"Dangerous MCP server pattern: {description}",
                    description=f"MCP server contains potentially dangerous implementation: {description}",
                    location=f"{file_path.relative_to(repo_path)}:{line_num}",
                    recommendation="Review and secure MCP server implementation",
                    evidence={'pattern': match.group(0)[:100]}
                ))

        return findings

    async def _analyze_tool_interactions(self, repo_path: str) -> List[Finding]:
        """Analyze tool interactions and capability mappings"""
        findings = []
        
        # This would analyze how tools interact with each other
        # and identify potential "toxic flows" between tools
        
        # For now, we'll implement basic tool discovery and analysis
        tool_definitions = await self._discover_tool_definitions(repo_path)
        
        # Check for tool interaction security issues
        findings.extend(self._analyze_tool_security_interactions(tool_definitions, repo_path))
        
        return findings

    async def _discover_tool_definitions(self, repo_path: str) -> List[Dict]:
        """Discover MCP tool definitions in the codebase"""
        tools = []
        
        # Pattern to find tool definitions
        tool_patterns = [
            r'@mcp\.tool\s*(?:\([^)]*\))?\s*(?:async\s+)?def\s+(\w+)',
            r'\.tool\s*\(\s*["\']([^"\']+)["\']',
            r'createTool\s*\(\s*["\']([^"\']+)["\']'
        ]
        
        for py_file in Path(repo_path).rglob('*.py'):
            try:
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in tool_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in matches:
                        tools.append({
                            'name': match.group(1),
                            'file': str(py_file.relative_to(repo_path)),
                            'pattern': pattern,
                            'context': content[max(0, match.start()-100):match.end()+100]
                        })
                        
            except Exception as e:
                logger.debug(f"Error discovering tools in {py_file}: {e}")
        
        return tools

    def _analyze_tool_security_interactions(self, tools: List[Dict], repo_path: str) -> List[Finding]:
        """Analyze security implications of tool interactions"""
        findings = []
        
        # Check for potentially dangerous tool combinations
        dangerous_combinations = [
            (['file_read', 'file_write'], 'File manipulation combination'),
            (['network_request', 'file_write'], 'Network to file flow'),
            (['user_input', 'system_exec'], 'User input to execution flow'),
            (['database_query', 'file_write'], 'Database to file flow')
        ]
        
        tool_names = [tool['name'].lower() for tool in tools]
        
        for combination, description in dangerous_combinations:
            if all(any(pattern in name for name in tool_names) for pattern in combination):
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.GENERIC,
                    severity=SeverityLevel.MEDIUM,
                    confidence=0.7,
                    title=f"Potentially dangerous tool combination: {description}",
                    description=f"MCP server implements tools that could create security risks when combined",
                    location="multiple tools",
                    recommendation="Review tool interactions and implement proper authorization",
                    evidence={'tool_combination': combination, 'detected_tools': tool_names}
                ))
        
        return findings

    async def _validate_mcp_protocol(self, repo_path: str) -> List[Finding]:
        """Validate MCP protocol compliance"""
        findings = []
        
        # Check for protocol compliance issues
        # This would validate against MCP specification
        
        # For now, implement basic validation
        findings.extend(await self._check_json_rpc_compliance(repo_path))
        
        return findings

    async def _check_json_rpc_compliance(self, repo_path: str) -> List[Finding]:
        """Check JSON-RPC 2.0 compliance in MCP implementations"""
        findings = []
        
        # Look for JSON-RPC message handling
        jsonrpc_patterns = [
            r'["\']jsonrpc["\']\s*:\s*["\']2\.0["\']',
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

    async def _assess_mcp_security_risks(self, repo_path: str) -> List[Finding]:
        """Assess MCP-specific security risks"""
        findings = []
        
        # MCP-specific security checks
        security_checks = [
            self._check_capability_leakage,
            self._check_unauthorized_access,
            self._check_data_exposure,
            self._check_tool_abuse_potential
        ]
        
        for check in security_checks:
            try:
                check_findings = await check(repo_path)
                findings.extend(check_findings)
            except Exception as e:
                logger.debug(f"Error in security check {check.__name__}: {e}")
        
        return findings

    async def _check_capability_leakage(self, repo_path: str) -> List[Finding]:
        """Check for capability leakage in MCP implementation"""
        findings = []
        
        # Look for overly broad capability exposure
        capability_patterns = [
            (r'capabilities.*\[\s*["\'].*["\']\s*\]', 'Broad capability exposure'),
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
                        line_num = content[:match.start()].count('\n') + 1
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
            r'@mcp\.tool.*\n(?!.*(?:auth|permission|check|validate))',
            r'@mcp\.resource.*\n(?!.*(?:auth|permission|check|validate))',
            r'def\s+\w+.*\n\s*""".*tool.*"""(?!.*auth)'
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern in auth_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
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
            (r'@mcp\.resource.*\n.*user.*data', 'User data exposure'),
            (r'@mcp\.resource.*\n.*sensitive', 'Sensitive data exposure'),
            (r'@mcp\.resource.*\n.*private', 'Private data exposure'),
            (r'return.*user.*\+.*secret', 'Data mixing with secrets')
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, description in exposure_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
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
            (r'@mcp\.tool.*\n.*delete.*file', 'File deletion capability'),
            (r'@mcp\.tool.*\n.*network.*request', 'Network request capability'),
            (r'@mcp\.tool.*\n.*database.*query', 'Database query capability'),
            (r'@mcp\.tool.*\n.*admin.*privilege', 'Administrative privilege')
        ]
        
        for file_path in Path(repo_path).rglob('*.py'):
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for pattern, description in abuse_patterns:
                    matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
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