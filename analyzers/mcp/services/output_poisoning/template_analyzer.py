"""Template file output poisoning analyzer."""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, VulnerabilityType
from .patterns import POISONING_PATTERNS, TEMPLATE_FILE_PATTERNS
from .utils import extract_context

logger = logging.getLogger(__name__)


class TemplateAnalyzer:
    """Analyzes response template files for output poisoning."""

    def analyze(self, repo: Path) -> List[Finding]:
        """Analyze template files for poisoning patterns."""
        findings = []
        for pattern in TEMPLATE_FILE_PATTERNS:
            for template_file in repo.glob(pattern):
                if template_file.is_file():
                    findings.extend(self._check_file(template_file))
        return findings

    def _check_file(self, file_path: Path) -> List[Finding]:
        """Check template file for poisoning patterns."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            findings.extend(self._scan_patterns(content, file_path))
        except Exception as e:
            logger.warning(f"Error checking template {file_path}: {e}")
        return findings

    def _scan_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Scan content for poisoning patterns."""
        findings = []
        for pattern_info in POISONING_PATTERNS:
            for match in re.finditer(pattern_info['pattern'], content, re.MULTILINE):
                findings.append(self._create_finding(pattern_info, file_path, content, match.start()))
        return findings

    def _create_finding(self, pattern_info: dict, file_path: Path, content: str, pos: int) -> Finding:
        """Create a template poisoning finding."""
        return Finding(
            title=f"Template Output Poisoning: {pattern_info['title']}",
            description="Poisoning pattern found in response template",
            severity=pattern_info['severity'],
            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
            location=str(file_path),
            recommendation="Sanitize template outputs and use proper escaping mechanisms.",
            evidence={'code_snippet': extract_context(content, pos)},
            tool="mcp_output_poisoning",
            confidence=0.9
        )
