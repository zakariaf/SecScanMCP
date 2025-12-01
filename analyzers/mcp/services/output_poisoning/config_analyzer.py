"""Configuration file output poisoning analyzer."""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, VulnerabilityType
from .patterns import POISONING_PATTERNS, CONFIG_FILE_PATTERNS
from .utils import extract_context, should_analyze_file

logger = logging.getLogger(__name__)


class ConfigAnalyzer:
    """Analyzes configuration files for output poisoning patterns."""

    def analyze(self, repo: Path) -> List[Finding]:
        """Analyze config files for malicious response patterns."""
        findings = []
        for pattern in CONFIG_FILE_PATTERNS:
            for config_file in repo.glob(f'**/{pattern}'):
                if config_file.is_file() and should_analyze_file(config_file):
                    findings.extend(self._check_file(config_file))
        return findings

    def _check_file(self, file_path: Path) -> List[Finding]:
        """Check configuration file for response poisoning."""
        findings = []
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            findings.extend(self._scan_patterns(content, file_path))
        except Exception as e:
            logger.warning(f"Error checking config {file_path}: {e}")
        return findings

    def _scan_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Scan content for poisoning patterns."""
        findings = []
        for pattern_info in POISONING_PATTERNS:
            for match in re.finditer(pattern_info['pattern'], content, re.MULTILINE):
                findings.append(self._create_finding(pattern_info, file_path, content, match.start()))
        return findings

    def _create_finding(self, pattern_info: dict, file_path: Path, content: str, pos: int) -> Finding:
        """Create a config poisoning finding."""
        return Finding(
            title=f"Config Response Poisoning: {pattern_info['title']}",
            description="Poisoning pattern in configuration file",
            severity=pattern_info['severity'],
            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
            location=str(file_path),
            recommendation="Review configuration for potentially malicious output patterns.",
            evidence={'code_snippet': extract_context(content, pos)},
            tool="mcp_output_poisoning",
            confidence=0.7
        )
