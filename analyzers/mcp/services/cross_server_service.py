"""Cross-server contamination risk analysis service."""

import json
import yaml
import logging
from pathlib import Path
from typing import List, Dict, Any, Set

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class CrossServerService:
    """Detects cross-server contamination risks in MCP configurations."""
    
    def __init__(self):
        self.risk_indicators = self._build_risk_indicators()
    
    def _build_risk_indicators(self) -> Dict[str, Any]:
        """Build cross-server contamination risk indicators."""
        return {
            'shared_environments': {
                'patterns': ['shared_env', 'global_env', 'common_env'],
                'severity': SeverityLevel.HIGH,
                'description': 'Shared environment variables between servers'
            },
            'shared_credentials': {
                'patterns': ['shared_creds', 'common_auth', 'global_token'],
                'severity': SeverityLevel.CRITICAL,
                'description': 'Shared authentication credentials'
            },
            'shared_storage': {
                'patterns': ['shared_db', 'common_storage', 'global_cache'],
                'severity': SeverityLevel.MEDIUM,
                'description': 'Shared storage resources'
            },
            'cross_server_communication': {
                'patterns': ['server_to_server', 'cross_call', 'peer_server'],
                'severity': SeverityLevel.HIGH,
                'description': 'Direct server-to-server communication'
            }
        }
    
    async def analyze_cross_server_risks(self, repo_path: str) -> List[Finding]:
        """
        Analyze repository for cross-server contamination risks.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of cross-server contamination findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Analyze MCP configuration files
        findings.extend(self._analyze_mcp_configs(repo))
        
        # Analyze server definitions
        findings.extend(self._analyze_server_definitions(repo))
        
        # Check for shared resources
        findings.extend(self._check_shared_resources(repo))
        
        # Check communication patterns
        findings.extend(self._check_communication_patterns(repo))
        
        return findings
    
    def _analyze_mcp_configs(self, repo: Path) -> List[Finding]:
        """Analyze MCP configuration files for cross-server risks."""
        findings = []
        
        config_patterns = ['mcp.json', 'mcp.yaml', 'mcp.yml', '.mcp/**']
        
        for pattern in config_patterns:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(
                        self._analyze_config_file(config_file)
                    )
        
        return findings
    
    def _analyze_config_file(self, config_file: Path) -> List[Finding]:
        """Analyze individual configuration file."""
        findings = []
        
        try:
            content = config_file.read_text()
            
            # Parse configuration
            if config_file.suffix == '.json':
                config = json.loads(content)
            elif config_file.suffix in ['.yaml', '.yml']:
                config = yaml.safe_load(content)
            else:
                return findings
            
            # Check for cross-server risks in config
            findings.extend(self._check_config_risks(config, str(config_file)))
            
        except Exception as e:
            logger.warning(f"Error analyzing {config_file}: {e}")
        
        return findings
    
    def _check_config_risks(self, config: Dict[str, Any], 
                          location: str) -> List[Finding]:
        """Check configuration for cross-server risks."""
        findings = []
        
        if isinstance(config, dict):
            # Check for multiple servers configuration
            if 'mcpServers' in config or 'servers' in config:
                servers = config.get('mcpServers', config.get('servers', {}))
                findings.extend(self._analyze_multi_server_setup(servers, location))
            
            # Check for shared resources
            findings.extend(self._check_shared_config_resources(config, location))
        
        return findings
    
    def _analyze_multi_server_setup(self, servers: Dict[str, Any], 
                                   location: str) -> List[Finding]:
        """Analyze multi-server setup for contamination risks."""
        findings = []
        
        if len(servers) < 2:
            return findings
        
        server_names = list(servers.keys())
        
        # Check for shared environment variables
        shared_env = self._find_shared_environments(servers)
        if shared_env:
            findings.append(Finding(
                title="Cross-Server Environment Sharing",
                description=f"Servers share environment variables: {', '.join(shared_env)}",
                severity=SeverityLevel.HIGH,
                vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                location=location,
                recommendation="Isolate server environments to prevent cross-contamination.",
                tool="mcp_cross_server",
                confidence=0.8
            ))
        
        # Check for identical configurations
        identical_configs = self._find_identical_configurations(servers)
        if identical_configs:
            findings.append(Finding(
                title="Identical Server Configurations",
                description=f"Servers have identical configs: {', '.join(identical_configs)}",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                location=location,
                recommendation="Ensure each server has unique configuration to prevent shared vulnerabilities.",
                tool="mcp_cross_server",
                confidence=0.7
            ))
        
        return findings
    
    def _find_shared_environments(self, servers: Dict[str, Any]) -> List[str]:
        """Find shared environment variables between servers."""
        env_vars = {}
        shared = []
        
        for server_name, server_config in servers.items():
            if isinstance(server_config, dict) and 'env' in server_config:
                env_config = server_config['env']
                if isinstance(env_config, dict):
                    for env_key in env_config.keys():
                        if env_key not in env_vars:
                            env_vars[env_key] = []
                        env_vars[env_key].append(server_name)
        
        # Find variables shared by multiple servers
        for env_key, server_list in env_vars.items():
            if len(server_list) > 1:
                shared.append(env_key)
        
        return shared
    
    def _find_identical_configurations(self, servers: Dict[str, Any]) -> List[str]:
        """Find servers with identical configurations."""
        config_signatures = {}
        identical = []
        
        for server_name, server_config in servers.items():
            # Create a signature of the configuration
            signature = str(sorted(server_config.items())) if isinstance(server_config, dict) else str(server_config)
            
            if signature not in config_signatures:
                config_signatures[signature] = []
            config_signatures[signature].append(server_name)
        
        # Find signatures with multiple servers
        for signature, server_list in config_signatures.items():
            if len(server_list) > 1:
                identical.extend(server_list)
        
        return identical
    
    def _check_shared_config_resources(self, config: Dict[str, Any], 
                                     location: str) -> List[Finding]:
        """Check for shared resources in configuration."""
        findings = []
        
        for risk_type, risk_info in self.risk_indicators.items():
            for pattern in risk_info['patterns']:
                if self._contains_pattern_recursive(config, pattern):
                    findings.append(Finding(
                        title=f"Cross-Server Risk: {risk_type.replace('_', ' ').title()}",
                        description=risk_info['description'],
                        severity=risk_info['severity'],
                        vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                        location=location,
                        recommendation="Isolate server resources to prevent cross-contamination.",
                        tool="mcp_cross_server",
                        confidence=0.6
                    ))
        
        return findings
    
    def _analyze_server_definitions(self, repo: Path) -> List[Finding]:
        """Analyze server definitions for cross-contamination risks."""
        findings = []
        
        # Look for server definition files
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_server_code(py_file))
        
        return findings
    
    def _check_server_code(self, file_path: Path) -> List[Finding]:
        """Check server code for cross-contamination patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for server-to-server communication
            if 'server' in content.lower() and ('call' in content or 'request' in content):
                server_comm_patterns = [
                    r'(?i)server.*\.call\(',
                    r'(?i)requests\..*server',
                    r'(?i)connect.*server'
                ]
                
                for pattern in server_comm_patterns:
                    import re
                    if re.search(pattern, content):
                        findings.append(Finding(
                            title="Server-to-Server Communication Detected",
                            description="Direct server communication may enable contamination",
                            severity=SeverityLevel.MEDIUM,
                            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                            location=str(file_path),
                            recommendation="Implement proper isolation between servers to prevent cross-contamination.",
                            tool="mcp_cross_server",
                            confidence=0.5
                        ))
                        break
        
        except Exception as e:
            logger.warning(f"Error checking server code in {file_path}: {e}")
        
        return findings
    
    def _check_shared_resources(self, repo: Path) -> List[Finding]:
        """Check for shared resources between servers."""
        findings = []
        
        # Check for shared database/storage files
        shared_files = ['shared.db', 'common.sqlite', 'global.json']
        
        for shared_file in shared_files:
            if (repo / shared_file).exists():
                findings.append(Finding(
                    title="Shared Resource File Detected",
                    description=f"Shared resource file {shared_file} may enable contamination",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                    location=str(repo / shared_file),
                    recommendation="Isolate server resources to prevent shared file vulnerabilities.",
                    tool="mcp_cross_server",
                    confidence=0.6
                ))
        
        return findings
    
    def _check_communication_patterns(self, repo: Path) -> List[Finding]:
        """Check for problematic communication patterns."""
        findings = []
        
        # This would involve more complex analysis of network calls,
        # IPC mechanisms, shared memory, etc.
        # Simplified version for now
        
        return findings
    
    def _contains_pattern_recursive(self, obj: Any, pattern: str) -> bool:
        """Recursively check if object contains pattern."""
        if isinstance(obj, str):
            return pattern.lower() in obj.lower()
        elif isinstance(obj, dict):
            return any(
                pattern.lower() in str(k).lower() or self._contains_pattern_recursive(v, pattern)
                for k, v in obj.items()
            )
        elif isinstance(obj, list):
            return any(self._contains_pattern_recursive(item, pattern) for item in obj)
        return False
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        exclude_patterns = [
            'test_', 'tests/', '__pycache__/',
            'node_modules/', '.git/', 'venv/'
        ]
        
        file_str = str(file_path)
        return not any(pattern in file_str for pattern in exclude_patterns)