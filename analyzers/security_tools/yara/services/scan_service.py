"""
YARA Scan Service

Handles file scanning with YARA rules
Following clean architecture with single responsibility
"""

import yara
import logging
from pathlib import Path
from typing import List, Optional

from models import Finding

logger = logging.getLogger(__name__)


class ScanService:
    """Handles YARA file scanning operations"""
    
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
    SCAN_TIMEOUT = 30  # seconds per file
    
    def __init__(self, rule_service):
        self.rule_service = rule_service
        # Import finding service here to avoid circular dependency
        from .finding_service import FindingService
        self.finding_service = FindingService()
    
    def scan_file(self, file_path: Path, repo_root: Path) -> List[Finding]:
        """Scan a single file with YARA rules"""
        findings = []
        
        try:
            # Check file size
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return findings
            
            # Scan file with rules
            if not self.rule_service.rules:
                return findings
            
            matches = self.rule_service.rules.match(
                str(file_path),
                timeout=self.SCAN_TIMEOUT
            )
            
            # Convert matches to findings
            findings = self._process_matches(matches, file_path, repo_root)
            
        except yara.TimeoutError:
            logger.warning(f"YARA scan timeout for {file_path}")
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
        
        return findings
    
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