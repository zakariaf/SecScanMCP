"""Python code analysis service for MCP servers."""

import ast
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType
from ..detectors.permission_detector import PermissionDetector
from ..detectors.injection_detector import InjectionDetector

logger = logging.getLogger(__name__)


class CodeAnalyzer:
    """Analyzes Python code in MCP servers for security issues."""
    
    def __init__(self):
        self.permission_detector = PermissionDetector()
        self.injection_detector = InjectionDetector()
    
    def analyze_python_file(self, file_path: Path) -> List[Finding]:
        """
        Analyze a Python file for security issues.
        
        Args:
            file_path: Path to Python file
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            content = file_path.read_text()
            findings.extend(self._analyze_code_content(content, str(file_path)))
        except Exception as e:
            logger.error(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _analyze_code_content(self, content: str, location: str) -> List[Finding]:
        """Analyze Python code content."""
        findings = []
        
        # Check for injection patterns in strings
        findings.extend(self._check_string_literals(content, location))
        
        # Analyze with AST
        try:
            tree = ast.parse(content)
            findings.extend(self._analyze_ast(tree, content, location))
        except SyntaxError as e:
            logger.debug(f"Syntax error in {location}: {e}")
        
        # Check permissions
        findings.extend(
            self.permission_detector.analyze_code_permissions(content, location)
        )
        
        return findings
    
    def _check_string_literals(self, content: str, location: str) -> List[Finding]:
        """Check string literals for injection patterns."""
        findings = []
        
        # Find all string literals
        string_pattern = r'["\']([^"\']+)["\']'
        matches = re.finditer(string_pattern, content)
        
        for match in matches:
            string_content = match.group(1)
            line_no = content[:match.start()].count('\n') + 1
            
            string_findings = self.injection_detector.check_text_for_injection(
                string_content,
                f"{location}:line_{line_no}",
                "string_literal"
            )
            findings.extend(string_findings)
        
        return findings
    
    def _analyze_ast(self, tree: ast.AST, content: str,
                    location: str) -> List[Finding]:
        """Analyze AST for security issues."""
        findings = []
        
        # Analyze each function
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                findings.extend(
                    self._analyze_function(node, content, location)
                )
        
        # Check for dangerous calls
        findings.extend(
            self.permission_detector.analyze_ast_permissions(tree, location)
        )
        
        return findings
    
    def _analyze_function(self, func_node: ast.FunctionDef,
                         content: str, location: str) -> List[Finding]:
        """Analyze a function for security issues."""
        findings = []
        func_name = func_node.name
        
        # Check if it's a tool function
        if func_name.startswith('handle_') or func_name.endswith('_tool'):
            findings.extend(
                self._analyze_tool_function(func_node, content, location)
            )
        
        # Check for dangerous patterns
        findings.extend(
            self._check_function_patterns(func_node, location)
        )
        
        return findings
    
    def _analyze_tool_function(self, func_node: ast.FunctionDef,
                              content: str, location: str) -> List[Finding]:
        """Analyze MCP tool function."""
        findings = []
        func_name = func_node.name
        
        # Check for unsanitized input usage
        has_validation = self._check_input_validation(func_node)
        
        if not has_validation:
            findings.append(Finding(
                vulnerability_type=VulnerabilityType.INPUT_VALIDATION,
                severity=SeverityLevel.HIGH,
                confidence=0.75,
                title=f"Missing input validation in {func_name}",
                description="Tool function doesn't validate input",
                location=f"{location}:{func_name}",
                recommendation="Add input validation before processing",
                references=[],
                evidence={"function": func_name},
                tool="mcp_specific"
            ))
        
        return findings
    
    def _check_input_validation(self, func_node: ast.FunctionDef) -> bool:
        """Check if function has input validation."""
        validation_patterns = [
            'validate', 'sanitize', 'check', 'verify',
            'isinstance', 'type', 'schema'
        ]
        
        for node in ast.walk(func_node):
            if isinstance(node, ast.Name):
                if any(pattern in node.id.lower() for pattern in validation_patterns):
                    return True
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if any(pattern in node.func.id.lower() for pattern in validation_patterns):
                        return True
        
        return False
    
    def _check_function_patterns(self, func_node: ast.FunctionDef,
                                location: str) -> List[Finding]:
        """Check for dangerous patterns in function."""
        findings = []
        
        # Check for eval/exec in function
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        findings.append(Finding(
                            vulnerability_type=VulnerabilityType.CODE_INJECTION,
                            severity=SeverityLevel.CRITICAL,
                            confidence=0.95,
                            title=f"Use of {node.func.id} in {func_node.name}",
                            description="Dynamic code execution is dangerous",
                            location=f"{location}:{func_node.name}:line_{node.lineno}",
                            recommendation="Remove dynamic code execution",
                            references=[],
                            evidence={
                                "function": func_node.name,
                                "dangerous_call": node.func.id
                            },
                            tool="mcp_specific"
                        ))
        
        return findings