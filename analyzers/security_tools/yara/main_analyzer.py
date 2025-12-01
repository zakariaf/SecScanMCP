"""
Main YARA Analyzer

Orchestrates YARA-based pattern matching for threat detection
Following clean architecture principles with ≤100 lines per file
"""

import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.rule_service import RuleService
from .services.scan_service import ScanService
from .services.finding_service import FindingService

logger = logging.getLogger(__name__)


class YARAAnalyzer(BaseAnalyzer):
    """Clean orchestrator for YARA analysis"""
    
    def __init__(self):
        super().__init__()
        self.rule_service = RuleService()
        self.scan_service = ScanService(self.rule_service)
        self.finding_service = FindingService()
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze repository with YARA rules"""
        if not self.rule_service.rules:
            self.logger.warning("No YARA rules loaded, skipping analysis")
            return []
        
        findings = []
        repo_path = Path(repo_path)
        
        try:
            self.log_scan_summary(str(repo_path))
            
            # Get filtered files
            filtered_files = self.get_filtered_files(str(repo_path))
            
            # Scan files in parallel
            findings = await self._parallel_scan(filtered_files, repo_path)
            
            self.logger.info(f"YARA analysis found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"YARA analysis failed: {e}")
        
        return findings
    
    async def _parallel_scan(self, files: List[str], repo_path: Path) -> List[Finding]:
        """Scan files in parallel using thread pool"""
        findings = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            tasks = [
                executor.submit(self.scan_service.scan_file, Path(f), repo_path)
                for f in files
            ]

            for future in asyncio.as_completed(
                [asyncio.wrap_future(f) for f in tasks],
                timeout=300
            ):
                try:
                    result = await future
                    if result:
                        findings.extend(result)
                except asyncio.TimeoutError:
                    self.logger.warning("YARA scan timeout reached")
                    break
                except Exception as e:
                    self.logger.error(f"Error in YARA scan: {e}")

        return findings