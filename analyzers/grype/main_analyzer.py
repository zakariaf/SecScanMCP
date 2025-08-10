"""
Main Grype Analyzer

Orchestrates Grype vulnerability scanning with SBOM optimization
Following clean architecture principles with ≤100 lines per file
"""

import json
import logging
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.scan_service import ScanService
from .services.sbom_service import SBOMService
from .services.finding_service import FindingService

logger = logging.getLogger(__name__)


class GrypeAnalyzer(BaseAnalyzer):
    """Clean orchestrator for Grype vulnerability scanning"""
    
    def __init__(self):
        super().__init__()
        self.scan_service = ScanService()
        self.sbom_service = SBOMService()
        self.finding_service = FindingService()
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Grype vulnerability scan"""
        findings = []
        
        try:
            # Get scan results from Grype
            results = await self._run_scan(repo_path)
            if not results:
                logger.warning("No scan results from Grype")
                return findings
            
            # Convert matches to findings
            for match in results.get('matches', []):
                finding = self.finding_service.convert_match(match, repo_path)
                if finding:
                    findings.append(finding)
            
            logger.info(f"Grype found {len(findings)} vulnerabilities")
            
        except FileNotFoundError:
            logger.warning("Grype not found, skipping Grype analysis")
        except Exception as e:
            logger.error(f"Grype analysis failed: {e}")
        
        return findings
    
    async def _run_scan(self, repo_path: str) -> Dict[str, Any]:
        """Run Grype scan with SBOM optimization"""
        # Try to use SBOM for faster scanning
        sbom_path = await self.sbom_service.get_or_create_sbom(repo_path)
        
        try:
            # Execute scan
            results = await self.scan_service.run_scan(repo_path, sbom_path)
            return results
            
        finally:
            # Cleanup temporary SBOM if created
            if sbom_path:
                self.sbom_service.cleanup_temp_sbom(sbom_path)