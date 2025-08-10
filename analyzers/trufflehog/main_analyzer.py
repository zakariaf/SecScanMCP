"""
Main TruffleHog Analyzer

Orchestrates TruffleHog secret scanning
Following clean architecture principles with ≤100 lines per file
"""

import logging
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.scan_service import ScanService
from .services.finding_service import FindingService

logger = logging.getLogger(__name__)


class TruffleHogAnalyzer(BaseAnalyzer):
    """Clean orchestrator for TruffleHog secret detection"""
    
    def __init__(self):
        super().__init__()
        self.scan_service = ScanService()
        self.finding_service = FindingService()
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run TruffleHog to find secrets"""
        findings = []
        
        try:
            # Run TruffleHog scan
            scan_results = await self.scan_service.run_scan(repo_path)
            if not scan_results:
                return findings
            
            # Convert results to findings
            for result in scan_results:
                finding = self.finding_service.convert_to_finding(result, repo_path)
                if finding:
                    findings.append(finding)
            
            logger.info(f"TruffleHog found {len(findings)} secrets")
            
        except Exception as e:
            logger.error(f"TruffleHog analysis failed: {e}")
        
        return findings