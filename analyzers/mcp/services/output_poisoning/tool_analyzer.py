"""Tool function output poisoning analyzer."""

import re
import ast
import logging
from pathlib import Path
from typing import List

from models import Finding, SeverityLevel, VulnerabilityType
from .patterns import POISONING_PATTERNS
from .utils import (
    should_analyze_file, is_mcp_tool_file,
    is_in_output_context, extract_context
)

logger = logging.getLogger(__name__)


class ToolOutputAnalyzer:
    """Analyzes MCP tool functions for output poisoning."""

    def analyze(self, repo: Path) -> List[Finding]:
        """Analyze tool functions for output poisoning."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_file(py_file))
        return findings

    def _check_file(self, file_path: Path) -> List[Finding]:
        """Check Python file for tool output poisoning."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not is_mcp_tool_file(content):
                return findings
            findings.extend(self._check_string_patterns(content, file_path))
            findings.extend(self._analyze_ast(content, file_path))
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
        return findings

    def _check_string_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Check string literals for poisoning patterns."""
        findings = []
        for pattern_info in POISONING_PATTERNS:
            for match in re.finditer(pattern_info['pattern'], content, re.MULTILINE):
                line_content = self._get_line_content(content, match.start())
                if is_in_output_context(line_content, match.start() - content.rfind('\n', 0, match.start()) - 1):
                    findings.append(self._create_finding(pattern_info, file_path, content, match.start()))
        return findings

    def _get_line_content(self, content: str, pos: int) -> str:
        """Get the line containing the position."""
        line_start = content.rfind('\n', 0, pos) + 1
        line_end = content.find('\n', pos)
        return content[line_start:line_end if line_end != -1 else len(content)]

    def _create_finding(self, pattern_info: dict, file_path: Path, content: str, pos: int) -> Finding:
        """Create a poisoning finding."""
        return Finding(
            title=f"Output Poisoning: {pattern_info['title']}",
            description="Potential output poisoning pattern in tool response",
            severity=pattern_info['severity'],
            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
            location=str(file_path),
            recommendation="Sanitize and validate all tool outputs before returning.",
            evidence={'code_snippet': extract_context(content, pos)},
            tool="mcp_output_poisoning",
            confidence=0.8
        )

    def _analyze_ast(self, content: str, file_path: Path) -> List[Finding]:
        """Analyze AST for dynamic output poisoning."""
        try:
            tree = ast.parse(content)
            return ASTOutputVisitor(file_path).analyze(tree)
        except SyntaxError:
            logger.warning(f"Syntax error in {file_path}, skipping AST analysis")
            return []


class ASTOutputVisitor(ast.NodeVisitor):
    """AST visitor for detecting output poisoning in tool functions."""

    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings: List[Finding] = []

    def analyze(self, tree: ast.AST) -> List[Finding]:
        """Analyze AST and return findings."""
        self.visit(tree)
        return self.findings

    def visit_FunctionDef(self, node):
        """Check tool function definitions."""
        if self._is_tool_function(node):
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value:
                    self._check_return_value(child, node.name)
        self.generic_visit(node)

    def _is_tool_function(self, func_node) -> bool:
        """Check if function is an MCP tool."""
        for decorator in func_node.decorator_list:
            if isinstance(decorator, ast.Name) and 'tool' in decorator.id.lower():
                return True
            if isinstance(decorator, ast.Attribute) and 'tool' in decorator.attr.lower():
                return True
        return 'tool' in func_node.name.lower()

    def _check_return_value(self, return_node, func_name: str):
        """Check return value for poisoning patterns."""
        line_no = getattr(return_node, 'lineno', 0)
        if isinstance(return_node.value, ast.Constant) and isinstance(return_node.value.value, str):
            if self._contains_poisoning(return_node.value.value):
                self._add_string_finding(func_name, line_no)
        elif isinstance(return_node.value, ast.JoinedStr):
            self._add_fstring_finding(func_name, line_no)

    def _contains_poisoning(self, text: str) -> bool:
        """Check if text contains poisoning patterns."""
        return any(re.search(p['pattern'], text, re.IGNORECASE) for p in POISONING_PATTERNS)

    def _add_string_finding(self, func_name: str, line_no: int):
        """Add finding for poisoned string literal."""
        self.findings.append(Finding(
            title="Dynamic Output Poisoning in Tool Response",
            description=f"Tool function {func_name} returns potentially poisoned output",
            severity=SeverityLevel.HIGH,
            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
            location=f"{self.file_path}:{line_no}",
            recommendation="Sanitize and validate all tool outputs before returning.",
            tool="mcp_output_poisoning",
            confidence=0.85
        ))

    def _add_fstring_finding(self, func_name: str, line_no: int):
        """Add finding for dynamic string construction."""
        self.findings.append(Finding(
            title="Dynamic String Construction in Tool Output",
            description=f"Tool function {func_name} uses dynamic string construction",
            severity=SeverityLevel.MEDIUM,
            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
            location=f"{self.file_path}:{line_no}",
            recommendation="Use templating with proper escaping for dynamic strings.",
            tool="mcp_output_poisoning",
            confidence=0.6
        ))
