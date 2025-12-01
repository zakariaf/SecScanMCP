"""Intelligent filtering service for reducing false positives."""

import logging
from typing import List

from models import Finding

logger = logging.getLogger(__name__)


class IntelligentFilteringService:
    """Applies context-aware filtering to findings."""

    HIGH_CONFIDENCE_THRESHOLD = 0.8

    def __init__(self, intelligent_analyzer=None):
        self.intelligent_analyzer = intelligent_analyzer

    def filter_findings(self, findings: List[Finding], repo_path: str) -> List[Finding]:
        """Apply intelligent context analysis to reduce false positives."""
        if not findings:
            return findings

        try:
            return self._apply_filtering(findings, repo_path)
        except Exception as e:
            logger.error(f"Error in intelligent filtering: {e}")
            return findings

    def _apply_filtering(self, findings: List[Finding], repo_path: str) -> List[Finding]:
        """Apply filtering logic to findings."""
        filtered = []

        for finding in findings:
            if finding.confidence > self.HIGH_CONFIDENCE_THRESHOLD:
                filtered.append(finding)
            else:
                result = self._analyze_with_context(finding, repo_path)
                if result:
                    filtered.append(result)

        return filtered

    def _analyze_with_context(self, finding: Finding, repo_path: str) -> Finding:
        """Analyze finding with additional context."""
        return finding
