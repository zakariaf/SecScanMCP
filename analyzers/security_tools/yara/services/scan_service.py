"""
YARA Scan Service

Handles file scanning with YARA rules
Following clean architecture with single responsibility
"""

import yara
import logging
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from models import Finding

if TYPE_CHECKING:
    from .finding_service import FindingService
    from .rule_service import RuleService

logger = logging.getLogger(__name__)

# Constants
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
SCAN_TIMEOUT = 30  # seconds per file


class ScanService:
    """Handles YARA file scanning operations"""

    def __init__(self, rule_service: "RuleService",
                 finding_service: Optional["FindingService"] = None):
        """
        Initialize scan service with dependencies.

        Args:
            rule_service: Service for loading YARA rules
            finding_service: Service for converting matches to findings
        """
        self.rule_service = rule_service
        self._finding_service = finding_service

    @property
    def finding_service(self) -> "FindingService":
        """Lazy load finding service to avoid circular import"""
        if self._finding_service is None:
            from .finding_service import FindingService
            self._finding_service = FindingService()
        return self._finding_service

    def scan_file(self, file_path: Path, repo_root: Path) -> List[Finding]:
        """Scan a single file with YARA rules"""
        if not self._should_scan(file_path):
            return []

        try:
            matches = self._execute_scan(file_path)
            return self._process_matches(matches, file_path, repo_root)

        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path}")
        except yara.Error as e:
            logger.warning(f"YARA error scanning {file_path}: {e}")
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")

        return []

    def _should_scan(self, file_path: Path) -> bool:
        """Check if file should be scanned"""
        if not self.rule_service.rules:
            return False

        try:
            return file_path.stat().st_size <= MAX_FILE_SIZE
        except OSError:
            return False

    def _execute_scan(self, file_path: Path) -> List:
        """Execute YARA scan on file"""
        return self.rule_service.rules.match(
            str(file_path),
            timeout=SCAN_TIMEOUT
        )

    def _process_matches(self, matches: List, file_path: Path,
                        repo_root: Path) -> List[Finding]:
        """Process YARA matches into findings"""
        findings = []

        for match in matches:
            finding = self.finding_service.convert_match_to_finding(
                match, file_path, repo_root
            )
            if finding:
                findings.append(finding)

        return findings
