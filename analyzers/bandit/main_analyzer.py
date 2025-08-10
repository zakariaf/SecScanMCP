"""
Main Bandit Analyzer

Orchestrates Bandit Python security scanning
Following clean architecture principles with ≤100 lines per file
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.scan_service import ScanService
from .services.finding_service import FindingService

logger = logging.getLogger(__name__)


class BanditAnalyzer(BaseAnalyzer):
    """Clean orchestrator for Bandit Python security analysis"""
    
    def __init__(self):
        super().__init__()
        self.scan_service = ScanService()
        self.finding_service = FindingService()
    
    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to Python projects"""
        return project_info.get('language') == 'python'
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Bandit security analysis"""
        if not self.is_applicable(project_info):
            return []
        
        findings = []
        ignore_file = None
        
        try:
            self.log_scan_summary(repo_path)
            
            # Create ignore file for Bandit
            ignore_file = self.create_ignore_file(repo_path)
            
            # Run Bandit scan
            results = await self.scan_service.run_scan(repo_path, ignore_file)
            if not results:
                return findings
            
            # Convert results to findings
            for result in results.get('results', []):
                finding = self.finding_service.convert_to_finding(result)
                if finding:
                    findings.append(finding)
            
            logger.info(f"Bandit found {len(findings)} issues")
            
        except Exception as e:
            logger.error(f"Bandit analysis failed: {e}")
            
        finally:
            # Clean up ignore file
            if ignore_file and Path(ignore_file).exists():
                Path(ignore_file).unlink()
        
        return findings