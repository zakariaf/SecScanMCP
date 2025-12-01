"""Utility functions for prompt injection detection."""

import re
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, VulnerabilityType


EXCLUDE_PATTERNS = [
    'test_', 'tests/', '__pycache__/',
    'node_modules/', '.git/', 'venv/'
]


def should_analyze_file(file_path: Path) -> bool:
    """Check if file should be analyzed."""
    file_str = str(file_path)
    return not any(pattern in file_str for pattern in EXCLUDE_PATTERNS)


def extract_context(content: str, position: int, context_chars: int = 150) -> str:
    """Extract context around match position."""
    start = max(0, position - context_chars // 2)
    end = min(len(content), position + context_chars // 2)
    return content[start:end].strip()


def check_text_for_patterns(
    text: str, location: str, patterns: List[Dict[str, Any]]
) -> List[Finding]:
    """Check text for specific patterns."""
    findings = []
    for pattern_info in patterns:
        for match in re.finditer(pattern_info['pattern'], text, re.MULTILINE):
            findings.append(Finding(
                title=f"Prompt Injection: {pattern_info['title']}",
                description="Advanced prompt injection pattern detected",
                severity=pattern_info['severity'],
                vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                location=location,
                recommendation="Implement input validation and sanitization.",
                evidence={'code_snippet': extract_context(text, match.start())},
                tool="mcp_prompt_injection",
                confidence=0.8
            ))
    return findings
