"""Permission abuse detection for MCP servers."""

import re
import ast
import logging
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType
from ..models.patterns import MCPPatterns

logger = logging.getLogger(__name__)


class PermissionDetector:
    """Detects permission abuse and dangerous operations."""
    
    def __init__(self):
        self.patterns = MCPPatterns()
        self.permission_patterns = self.patterns.get_permission_patterns()
    
    def analyze_code_permissions(self, code: str, location: str) -> List[Finding]:
        """
        Analyze code for dangerous permission usage.
        
        Args:
            code: Python code to analyze
            location: Location identifier
            
        Returns:
            List of findings
        """
        findings = []
        
        # Check filesystem operations
        fs_findings = self._check_filesystem_ops(code, location)
        findings.extend(fs_findings)
        
        # Check network operations
        net_findings = self._check_network_ops(code, location)
        findings.extend(net_findings)
        
        # Check system operations
        sys_findings = self._check_system_ops(code, location)
        findings.extend(sys_findings)
        
        return findings
    
    def _check_filesystem_ops(self, code: str, location: str) -> List[Finding]:
        """Check for dangerous filesystem operations."""
        findings = []
        
        for pattern in self.permission_patterns['filesystem']:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(self._create_permission_finding(
                    "Filesystem", pattern, code, location
                ))
        
        return findings
    
    def _check_network_ops(self, code: str, location: str) -> List[Finding]:
        """Check for unauthorized network operations."""
        findings = []
        
        for pattern in self.permission_patterns['network']:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(self._create_permission_finding(
                    "Network", pattern, code, location
                ))
        
        return findings
    
    def _check_system_ops(self, code: str, location: str) -> List[Finding]:
        """Check for dangerous system operations."""
        findings = []
        
        for pattern in self.permission_patterns['system']:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(self._create_permission_finding(
                    "System", pattern, code, location,
                    severity=SeverityLevel.CRITICAL
                ))
        
        return findings
    
    def analyze_ast_permissions(self, tree: ast.AST, location: str) -> List[Finding]:
        """
        Analyze AST for permission issues.
        
        Args:
            tree: Python AST to analyze
            location: Location identifier
            
        Returns:
            List of findings
        """
        findings = []
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                finding = self._check_dangerous_call(node, location)
                if finding:
                    findings.append(finding)
        
        return findings
    
    def _check_dangerous_call(self, node: ast.Call,
                             location: str) -> Optional[Finding]:
        """Check if AST call node is dangerous."""
        dangerous_funcs = {
            'eval': SeverityLevel.CRITICAL,
            'exec': SeverityLevel.CRITICAL,
            'compile': SeverityLevel.HIGH,
            '__import__': SeverityLevel.HIGH,
            'open': SeverityLevel.MEDIUM
        }
        
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in dangerous_funcs:
                return Finding(
                    vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                    severity=dangerous_funcs[func_name],
                    confidence=0.9,
                    title=f"Dangerous function: {func_name}",
                    description=f"Use of {func_name} can lead to security issues",
                    location=f"{location}:line_{node.lineno}",
                    recommendation=f"Avoid using {func_name}, use safer alternatives",
                    references=[],
                    evidence={"function": func_name, "line": node.lineno},
                    tool="mcp_specific"
                )
        
        return None
    
    def _create_permission_finding(self, perm_type: str, pattern: str,
                                  code: str, location: str,
                                  severity: SeverityLevel = SeverityLevel.HIGH) -> Finding:
        """Create finding for permission violation."""
        snippet = self._extract_code_snippet(code, pattern)
        
        return Finding(
            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
            severity=severity,
            confidence=0.85,
            title=f"{perm_type} permission abuse detected",
            description=f"Potentially dangerous {perm_type.lower()} operation",
            location=location,
            recommendation=f"Review {perm_type.lower()} operations for necessity",
            references=[],
            evidence={
                "permission_type": perm_type,
                "pattern": pattern,
                "snippet": snippet
            },
            tool="mcp_specific"
        )
    
    def _extract_code_snippet(self, code: str, pattern: str,
                             lines_context: int = 2) -> str:
        """Extract code snippet around pattern match."""
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if re.search(pattern, line, re.IGNORECASE):
                start = max(0, i - lines_context)
                end = min(len(lines), i + lines_context + 1)
                return '\n'.join(lines[start:end])
        return ""