"""Capability and tool abuse detection service."""

import re
import ast
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Set

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class CapabilityAbuseService:
    """Detects capability leakage and tool abuse vulnerabilities."""
    
    def __init__(self):
        self.capability_patterns = self._build_capability_patterns()
        self.abuse_indicators = self._build_abuse_indicators()
        self.dangerous_operations = self._build_dangerous_operations()
    
    def _build_capability_patterns(self) -> List[Dict[str, Any]]:
        """Build capability exposure patterns."""
        return [
            {
                'pattern': r'(?i)capability\s*[=:]\s*[\'"].*admin.*[\'"]',
                'severity': SeverityLevel.HIGH,
                'title': 'Admin Capability Exposure'
            },
            {
                'pattern': r'(?i)(grant|give|allow)\s+.*\s+(all|full|admin|root)\s+(access|permissions?)',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Full Access Grant'
            },
            {
                'pattern': r'(?i)(bypass|skip|ignore)\s+(permission|auth|security)\s+check',
                'severity': SeverityLevel.HIGH,
                'title': 'Security Bypass'
            }
        ]
    
    def _build_abuse_indicators(self) -> Dict[str, Dict[str, Any]]:
        """Build tool abuse indicators by category."""
        return {
            'file_system_abuse': {
                'patterns': [
                    r'(?i)(delete|remove|rm)\s+.*\*',
                    r'(?i)rmdir\s+.*-r',
                    r'(?i)(chmod|chown)\s+.*777'
                ],
                'severity': SeverityLevel.HIGH,
                'description': 'File system abuse patterns'
            },
            'network_abuse': {
                'patterns': [
                    r'(?i)(curl|wget|requests)\s+.*attack',
                    r'(?i)nmap\s+.*scan',
                    r'(?i)socket.*connect.*brute'
                ],
                'severity': SeverityLevel.MEDIUM,
                'description': 'Network abuse patterns'
            },
            'data_exfiltration': {
                'patterns': [
                    r'(?i)(send|post|upload)\s+.*\.(passwd|shadow|key)',
                    r'(?i)(exfil|extract|steal)\s+.*data',
                    r'(?i)base64.*encode.*secret'
                ],
                'severity': SeverityLevel.CRITICAL,
                'description': 'Data exfiltration patterns'
            }
        }
    
    def _build_dangerous_operations(self) -> Set[str]:
        """Build set of dangerous operations."""
        return {
            'eval', 'exec', 'compile', '__import__',
            'os.system', 'subprocess.call', 'subprocess.run',
            'open', 'file', 'input', 'raw_input'
        }
    
    async def check_capability_leakage(self, repo_path: str) -> List[Finding]:
        """
        Check for capability leakage vulnerabilities.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of capability leakage findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Check configuration files
        findings.extend(self._check_config_capabilities(repo))
        
        # Check source code for capability exposure
        findings.extend(self._check_code_capabilities(repo))
        
        # Check for unauthorized access patterns
        findings.extend(self._check_unauthorized_access(repo))
        
        return findings
    
    async def check_tool_abuse_potential(self, repo_path: str) -> List[Finding]:
        """
        Check for tool abuse potential.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of tool abuse findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Analyze tool implementations
        findings.extend(self._analyze_tool_implementations(repo))
        
        # Check for dangerous resource patterns
        findings.extend(self._check_dangerous_resource_patterns(repo))
        
        # Check for tool shadowing risks
        findings.extend(self._check_tool_shadowing_risks(repo))
        
        return findings
    
    def _check_config_capabilities(self, repo: Path) -> List[Finding]:
        """Check configuration files for capability issues."""
        findings = []
        
        config_patterns = ['mcp.json', 'mcp.yaml', 'mcp.yml', '.mcp/**']
        
        for pattern in config_patterns:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._analyze_config_capabilities(config_file))
        
        return findings
    
    def _analyze_config_capabilities(self, config_file: Path) -> List[Finding]:
        """Analyze configuration file for capability issues."""
        findings = []
        
        try:
            content = config_file.read_text()
            
            # Check for capability patterns
            for pattern_info in self.capability_patterns:
                matches = re.finditer(pattern_info['pattern'], content)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Capability Issue: {pattern_info['title']}",
                        description="Potentially dangerous capability configuration",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        location=str(config_file),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.8
                    ))
            
            # Parse and check structured data
            try:
                if config_file.suffix == '.json':
                    config_data = json.loads(content)
                elif config_file.suffix in ['.yaml', '.yml']:
                    import yaml
                    config_data = yaml.safe_load(content)
                else:
                    config_data = None
                
                if config_data:
                    findings.extend(
                        self._check_structured_capabilities(config_data, str(config_file))
                    )
            except:
                pass  # Continue with text-based analysis
        
        except Exception as e:
            logger.warning(f"Error analyzing capabilities in {config_file}: {e}")
        
        return findings
    
    def _check_structured_capabilities(self, config_data: Dict[str, Any], 
                                     location: str) -> List[Finding]:
        """Check structured configuration data for capability issues."""
        findings = []
        
        if isinstance(config_data, dict):
            # Check for tools with excessive permissions
            if 'tools' in config_data and isinstance(config_data['tools'], list):
                for i, tool in enumerate(config_data['tools']):
                    if isinstance(tool, dict):
                        findings.extend(
                            self._check_tool_permissions(tool, f"{location}:tools[{i}]")
                        )
            
            # Check server configurations
            if 'mcpServers' in config_data:
                servers = config_data['mcpServers']
                if isinstance(servers, dict):
                    for server_name, server_config in servers.items():
                        findings.extend(
                            self._check_server_permissions(
                                server_config, f"{location}:mcpServers.{server_name}"
                            )
                        )
        
        return findings
    
    def _check_tool_permissions(self, tool: Dict[str, Any], location: str) -> List[Finding]:
        """Check individual tool permissions."""
        findings = []
        
        # Check for overly broad permissions
        if 'permissions' in tool:
            perms = tool['permissions']
            if isinstance(perms, list):
                if 'all' in perms or '*' in perms:
                    findings.append(Finding(
                        title="Overly Broad Tool Permissions",
                        description="Tool granted 'all' or wildcard permissions",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        location=location,
                        confidence=0.9
                    ))
        
        return findings
    
    def _check_server_permissions(self, server_config: Dict[str, Any], 
                                location: str) -> List[Finding]:
        """Check server permissions configuration."""
        findings = []
        
        # Check for dangerous environment variables
        if 'env' in server_config and isinstance(server_config['env'], dict):
            env_vars = server_config['env']
            dangerous_env = ['DEBUG=1', 'DEV_MODE=true', 'DISABLE_AUTH=true']
            
            for var_name, var_value in env_vars.items():
                if f"{var_name}={var_value}" in dangerous_env:
                    findings.append(Finding(
                        title="Dangerous Environment Variable",
                        description=f"Dangerous env var: {var_name}={var_value}",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                        location=location,
                        confidence=0.7
                    ))
        
        return findings
    
    def _check_code_capabilities(self, repo: Path) -> List[Finding]:
        """Check source code for capability exposure."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._analyze_code_capabilities(py_file))
        
        return findings
    
    def _analyze_code_capabilities(self, file_path: Path) -> List[Finding]:
        """Analyze code file for capability issues."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for capability patterns
            for pattern_info in self.capability_patterns:
                matches = re.finditer(pattern_info['pattern'], content)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Code Capability Issue: {pattern_info['title']}",
                        description="Capability exposure in source code",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.7
                    ))
        
        except Exception as e:
            logger.warning(f"Error analyzing code capabilities in {file_path}: {e}")
        
        return findings
    
    def _check_unauthorized_access(self, repo: Path) -> List[Finding]:
        """Check for unauthorized access patterns."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_access_patterns(py_file))
        
        return findings
    
    def _check_access_patterns(self, file_path: Path) -> List[Finding]:
        """Check file for unauthorized access patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for authentication bypasses
            bypass_patterns = [
                r'(?i)if.*auth.*==.*false',
                r'(?i)(skip|bypass|ignore).*auth',
                r'(?i)auth.*disabled?',
                r'(?i)no.*auth.*required?'
            ]
            
            for pattern in bypass_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    findings.append(Finding(
                        title="Authentication Bypass Detected",
                        description="Code may bypass authentication checks",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.6
                    ))
        
        except Exception as e:
            logger.warning(f"Error checking access patterns in {file_path}: {e}")
        
        return findings
    
    def _analyze_tool_implementations(self, repo: Path) -> List[Finding]:
        """Analyze tool implementations for abuse potential."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_tool_implementation(py_file))
        
        return findings
    
    def _check_tool_implementation(self, file_path: Path) -> List[Finding]:
        """Check tool implementation for abuse patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Skip if not a tool file
            if not any(indicator in content for indicator in ['@mcp.tool', '@tool', 'def tool_']):
                return findings
            
            # Check for abuse patterns by category
            for abuse_type, abuse_info in self.abuse_indicators.items():
                for pattern in abuse_info['patterns']:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        findings.append(Finding(
                            title=f"Tool Abuse Risk: {abuse_type.replace('_', ' ').title()}",
                            description=abuse_info['description'],
                            severity=abuse_info['severity'],
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            location=str(file_path),
                            code_snippet=self._extract_context(content, match.start()),
                            confidence=0.7
                        ))
        
        except Exception as e:
            logger.warning(f"Error checking tool implementation in {file_path}: {e}")
        
        return findings
    
    def _check_dangerous_resource_patterns(self, repo: Path) -> List[Finding]:
        """Check for dangerous resource patterns."""
        findings = []
        
        dangerous_patterns = [
            r'(?i)(file|path)\s*:\s*[\'"][^\'\"]*\.\./.*[\'"]',  # Path traversal
            r'(?i)(url|uri)\s*:\s*[\'"]file://',  # File URI
            r'(?i)(command|exec)\s*:\s*[\'"][^\'\"]*\|',  # Command chaining
        ]
        
        for pattern in dangerous_patterns:
            for py_file in repo.glob('**/*.py'):
                if self._should_analyze_file(py_file):
                    try:
                        content = py_file.read_text(encoding='utf-8', errors='ignore')
                        matches = re.finditer(pattern, content)
                        
                        for match in matches:
                            findings.append(Finding(
                                title="Dangerous Resource Pattern",
                                description="Resource configuration may be exploitable",
                                severity=SeverityLevel.MEDIUM,
                                vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                                location=str(py_file),
                                code_snippet=self._extract_context(content, match.start()),
                                confidence=0.6
                            ))
                    except:
                        continue
        
        return findings
    
    def _check_tool_shadowing_risks(self, repo: Path) -> List[Finding]:
        """Check for tool shadowing risks."""
        findings = []
        
        # Find all tool definitions
        tool_names = set()
        tool_files = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                try:
                    content = py_file.read_text(encoding='utf-8', errors='ignore')
                    
                    # Extract tool names
                    tool_patterns = [
                        r'@mcp\.tool\([\'"]([^\'"]+)[\'"]',
                        r'def\s+tool_([a-zA-Z_][a-zA-Z0-9_]*)',
                        r'register_tool\([\'"]([^\'"]+)[\'"]'
                    ]
                    
                    for pattern in tool_patterns:
                        matches = re.finditer(pattern, content)
                        for match in matches:
                            tool_name = match.group(1)
                            if tool_name in tool_names:
                                findings.append(Finding(
                                    title="Tool Name Collision",
                                    description=f"Tool name '{tool_name}' defined multiple times",
                                    severity=SeverityLevel.MEDIUM,
                                    vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                                    location=str(py_file),
                                    confidence=0.8
                                ))
                            tool_names.add(tool_name)
                    
                    tool_files.append(py_file)
                
                except:
                    continue
        
        return findings
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        exclude_patterns = [
            'test_', 'tests/', '__pycache__/',
            'node_modules/', '.git/', 'venv/'
        ]
        
        file_str = str(file_path)
        return not any(pattern in file_str for pattern in exclude_patterns)
    
    def _extract_context(self, content: str, position: int, 
                        context_chars: int = 150) -> str:
        """Extract context around match position."""
        start = max(0, position - context_chars // 2)
        end = min(len(content), position + context_chars // 2)
        return content[start:end].strip()