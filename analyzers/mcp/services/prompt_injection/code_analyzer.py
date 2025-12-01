"""Code-based prompt injection analyzer."""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, SeverityLevel, VulnerabilityType
from .patterns import PromptInjectionPatterns
from .utils import should_analyze_file, check_text_for_patterns, extract_context

logger = logging.getLogger(__name__)


class CodePromptAnalyzer:
    """Analyzes code for prompt injection patterns."""

    TOOL_INDICATORS = ['@mcp.tool', '@tool', 'def tool_']
    RESOURCE_KEYWORDS = ['resource', 'mcp.resource', '@resource']
    PROCESSING_INDICATORS = [
        'process_data', 'parse_input', 'handle_request',
        'process_response', 'format_output'
    ]

    def analyze_resources(self, repo: Path) -> List[Finding]:
        """Analyze resource definitions for injection."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_python_resources(py_file))
        return findings

    def analyze_tools(self, repo: Path) -> List[Finding]:
        """Analyze tool functions for indirect injection."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_tool_injection(py_file))
        return findings

    def analyze_data_processors(self, repo: Path) -> List[Finding]:
        """Analyze data processing for injection risks."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_data_processing(py_file))
        return findings

    def _check_python_resources(self, file_path: Path) -> List[Finding]:
        """Check Python file for resource injection."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not any(kw in content for kw in self.RESOURCE_KEYWORDS):
                return []
            return check_text_for_patterns(
                content, str(file_path), PromptInjectionPatterns.get_all_patterns()
            )
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
            return []

    def _check_tool_injection(self, file_path: Path) -> List[Finding]:
        """Check tool functions for indirect injection."""
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not any(ind in content for ind in self.TOOL_INDICATORS):
                return []
            return check_text_for_patterns(
                content, str(file_path), PromptInjectionPatterns.INDIRECT_PATTERNS
            )
        except Exception as e:
            logger.warning(f"Error checking indirect injection in {file_path}: {e}")
            return []

    def _check_data_processing(self, file_path: Path) -> List[Finding]:
        """Check data processing for injection risks."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            if not any(ind in content for ind in self.PROCESSING_INDICATORS):
                return []

            for pattern in PromptInjectionPatterns.DATA_PROCESSING_PATTERNS:
                for match in re.finditer(pattern, content):
                    findings.append(Finding(
                        title="Data Processing Injection Risk",
                        description="Unsanitized user input in data processing",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                        location=str(file_path),
                        recommendation="Sanitize and validate user input before processing.",
                        evidence={'code_snippet': extract_context(content, match.start())},
                        tool="mcp_prompt_injection",
                        confidence=0.6
                    ))
        except Exception as e:
            logger.warning(f"Error checking data processing in {file_path}: {e}")
        return findings
