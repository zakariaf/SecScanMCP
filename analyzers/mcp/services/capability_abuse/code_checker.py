"""Code capability checking service."""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, VulnerabilityType
from .patterns import CapabilityPatterns
from .utils import should_analyze_file, extract_context

logger = logging.getLogger(__name__)


class CodeCapabilityChecker:
    """Checks source code for capability exposure."""

    def check(self, repo: Path) -> List[Finding]:
        """Check all code files for capability issues."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._analyze_file(py_file))
        return findings

    def _analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze code file for capability issues."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            for pattern_info in CapabilityPatterns.CAPABILITY_PATTERNS:
                for match in re.finditer(pattern_info['pattern'], content):
                    findings.append(Finding(
                        title=f"Code Capability Issue: {pattern_info['title']}",
                        description="Capability exposure in source code",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                        location=str(file_path),
                        code_snippet=extract_context(content, match.start()),
                        confidence=0.7,
                        tool="capability_abuse_checker",
                        recommendation="Review and restrict capability exposure in code"
                    ))
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
        return findings
