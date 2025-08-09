"""
Main Trivy Vulnerability Scanner

Orchestrates Trivy-based comprehensive security scanning
Following clean architecture principles with ≤100 lines per file
"""

import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.scanning_service import ScanningService
from .services.result_parser import ResultParser

logger = logging.getLogger(__name__)


class TrivyAnalyzer(BaseAnalyzer):
    """Clean orchestrator for Trivy comprehensive security scanning"""
    
    def __init__(self):
        super().__init__()
        self.scanning_service = ScanningService()
        self.result_parser = ResultParser(self)
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Trivy comprehensive security scan"""
        findings: List[Finding] = []
        
        try:
            self.log_scan_summary(repo_path)
            
            # Perform comprehensive scan in temporary directory
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                results = await self.scanning_service.scan_repository(repo_path, temp_file.name)
                
                if results:
                    # Parse scan results into findings
                    findings = self.result_parser.parse_results(results, repo_path)
                
        except Exception as e:
            logger.error(f"Trivy analysis failed: {e}")
        
        logger.info(f"Trivy found {len(findings)} issues")
        return findings