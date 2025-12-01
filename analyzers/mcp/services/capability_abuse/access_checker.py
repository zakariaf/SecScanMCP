"""Access pattern checking service."""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, SeverityLevel, VulnerabilityType
from .patterns import CapabilityPatterns
from .utils import should_analyze_file, extract_context

logger = logging.getLogger(__name__)


class AccessPatternChecker:
    """Checks for unauthorized access patterns."""

    def check(self, repo: Path) -> List[Finding]:
        """Check all code files for access pattern issues."""
        findings = []
        for py_file in repo.glob('**/*.py'):
            if should_analyze_file(py_file):
                findings.extend(self._check_file(py_file))
        return findings

    def _check_file(self, file_path: Path) -> List[Finding]:
        """Check file for unauthorized access patterns."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            for pattern in CapabilityPatterns.BYPASS_PATTERNS:
                for match in re.finditer(pattern, content):
                    findings.append(Finding(
                        title="Authentication Bypass Detected",
                        description="Code may bypass authentication checks",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
                        location=str(file_path),
                        code_snippet=extract_context(content, match.start()),
                        confidence=0.6,
                        tool="capability_abuse_checker",
                        recommendation="Implement proper authentication checks"
                    ))
        except Exception as e:
            logger.warning(f"Error checking access patterns in {file_path}: {e}")
        return findings
