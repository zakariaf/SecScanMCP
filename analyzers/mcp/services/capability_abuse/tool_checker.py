"""Tool implementation and abuse checking service."""

import re
import logging
from pathlib import Path
from typing import List, Set

from models import Finding, SeverityLevel, VulnerabilityType
from .patterns import CapabilityPatterns
from .utils import should_analyze_file, extract_context

logger = logging.getLogger(__name__)


class ToolChecker:
    """Checks tool implementations for abuse patterns."""

    TOOL_INDICATORS = ['@mcp.tool', '@tool', 'def tool_']

    def check_implementations(self, repo: Path) -> List[Finding]:
        """Check tool implementations for abuse potential."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_tool_file(py_file))
        return findings

    def check_resource_patterns(self, repo: Path) -> List[Finding]:
        """Check for dangerous resource patterns."""
        findings = []
        for pattern in CapabilityPatterns.DANGEROUS_RESOURCE_PATTERNS:
            for py_file in repo.glob('**/*.py'):
                if should_analyze_file(py_file):
                    findings.extend(self._check_resource_pattern(py_file, pattern))
        return findings

    def check_shadowing(self, repo: Path) -> List[Finding]:
        """Check for tool shadowing risks."""
        findings = []
        tool_names: Set[str] = set()
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_shadowing(py_file, tool_names))
        return findings

    def _check_tool_file(self, file_path: Path) -> List[Finding]:
        """Check tool implementation file."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not any(ind in content for ind in self.TOOL_INDICATORS):
                return findings
            for abuse_type, info in CapabilityPatterns.ABUSE_INDICATORS.items():
                for pattern in info['patterns']:
                    for match in re.finditer(pattern, content):
                        findings.append(Finding(
                            title=f"Tool Abuse Risk: {abuse_type.replace('_', ' ').title()}",
                            description=info['description'],
                            severity=info['severity'],
                            vulnerability_type=VulnerabilityType.PERMISSION_ABUSE,
                            location=str(file_path),
                            code_snippet=extract_context(content, match.start()),
                            confidence=0.7,
                            tool="capability_abuse_checker",
                            recommendation="Review tool implementation for potential abuse"
                        ))
        except Exception as e:
            logger.warning(f"Error checking tool in {file_path}: {e}")
        return findings

    def _check_resource_pattern(self, py_file: Path, pattern: str) -> List[Finding]:
        """Check for a specific dangerous resource pattern."""
        findings = []
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
            for match in re.finditer(pattern, content):
                findings.append(Finding(
                    title="Dangerous Resource Pattern",
                    description="Resource configuration may be exploitable",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
                    location=str(py_file),
                    code_snippet=extract_context(content, match.start()),
                    confidence=0.6,
                    tool="capability_abuse_checker",
                    recommendation="Validate and sanitize resource paths"
                ))
        except:
            pass
        return findings

    def _check_shadowing(self, py_file: Path, tool_names: Set[str]) -> List[Finding]:
        """Check for tool name collisions."""
        findings = []
        try:
            content = py_file.read_text(encoding='utf-8', errors='ignore')
            for pattern in CapabilityPatterns.TOOL_NAME_PATTERNS:
                for match in re.finditer(pattern, content):
                    tool_name = match.group(1)
                    if tool_name in tool_names:
                        findings.append(Finding(
                            title="Tool Name Collision",
                            description=f"Tool name '{tool_name}' defined multiple times",
                            severity=SeverityLevel.MEDIUM,
                            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                            location=str(py_file), confidence=0.8,
                            tool="capability_abuse_checker",
                            recommendation="Ensure tool names are unique across the codebase"
                        ))
                    tool_names.add(tool_name)
        except:
            pass
        return findings
