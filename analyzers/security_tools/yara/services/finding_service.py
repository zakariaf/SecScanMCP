"""
YARA Finding Service

Converts YARA matches to findings by orchestrating specialized services
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from models import Finding

from .string_matcher import StringMatcherService
from .vulnerability_mapper import VulnerabilityMapperService

logger = logging.getLogger(__name__)


class FindingService:
    """Converts YARA matches to findings"""

    def __init__(self, string_matcher: Optional[StringMatcherService] = None,
                 vuln_mapper: Optional[VulnerabilityMapperService] = None):
        self.string_matcher = string_matcher or StringMatcherService()
        self.vuln_mapper = vuln_mapper or VulnerabilityMapperService()

    def convert_match_to_finding(self, match: Any, file_path: Path,
                                 repo_root: Path) -> Optional[Finding]:
        """Convert YARA match to Finding"""
        try:
            relative_path = self._get_relative_path(file_path, repo_root)
            meta = match.meta
            matched_strings = self.string_matcher.extract_matched_strings(
                match, file_path
            )

            return self._create_finding(match, meta, relative_path, matched_strings)

        except Exception as e:
            logger.error(f"Failed to convert YARA match: {e}")
            return None

    def _create_finding(self, match: Any, meta: Dict,
                       relative_path: Path, matched_strings: List[Dict]) -> Finding:
        """Create Finding object from match data"""
        return Finding(
            vulnerability_type=self.vuln_mapper.determine_vuln_type(meta),
            severity=self.vuln_mapper.determine_severity(meta),
            confidence=self.vuln_mapper.get_confidence(meta),
            title=f"YARA Detection: {match.rule}",
            description=self._build_description(match, meta),
            location=self._build_location(relative_path, matched_strings),
            recommendation=self.vuln_mapper.get_recommendation(meta),
            references=self.vuln_mapper.extract_references(meta),
            evidence=self._build_evidence(match, meta, matched_strings),
            tool="yara"
        )

    def _get_relative_path(self, file_path: Path, repo_root: Path) -> Path:
        """Get relative path from repo root"""
        try:
            return file_path.relative_to(repo_root)
        except ValueError:
            return file_path

    def _build_location(self, relative_path: Path,
                       matched_strings: List[Dict]) -> str:
        """Build location string with line number if available"""
        if matched_strings and matched_strings[0].get('line'):
            return f"{relative_path}:{matched_strings[0]['line']}"
        return str(relative_path)

    def _build_description(self, match: Any, meta: Dict) -> str:
        """Build finding description"""
        description = meta.get('description', f'YARA rule {match.rule} matched')

        if 'details' in meta:
            description += f"\n\nDetails: {meta['details']}"

        return description

    def _build_evidence(self, match: Any, meta: Dict,
                       matched_strings: List[Dict]) -> Dict:
        """Build evidence dictionary"""
        return {
            'rule': match.rule,
            'namespace': match.namespace,
            'tags': match.tags,
            'meta': dict(meta),
            'matched_strings': matched_strings
        }
