"""
Main ClamAV Malware Detection Analyzer

Orchestrates ClamAV-based malware scanning with enterprise-grade detection
Following clean architecture principles with ≤100 lines per file
"""

import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.connection_service import ConnectionService
from .services.scanning_service import ScanningService
from .services.pattern_service import PatternService

logger = logging.getLogger(__name__)


class ClamAVAnalyzer(BaseAnalyzer):
    """Clean orchestrator for ClamAV malware detection"""
    
    def __init__(self):
        super().__init__()
        self.connection_service = ConnectionService()
        self.scanning_service = ScanningService(self.connection_service)
        self.pattern_service = PatternService(self)
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run ClamAV malware analysis on the repository"""
        findings: List[Finding] = []
        
        try:
            self.log_scan_summary(repo_path)
            
            # Connect to ClamAV daemon
            if not await self.connection_service.connect():
                logger.warning("ClamAV daemon not available, skipping malware scan")
                return findings
            
            # Perform file scanning
            scan_findings = await self.scanning_service.scan_repository(repo_path)
            findings.extend(scan_findings)
            
            # Additional pattern matching for MCP-specific threats  
            pattern_findings = await self.pattern_service.scan_for_patterns(repo_path)
            findings.extend(pattern_findings)
            
        except Exception as e:
            logger.error(f"ClamAV analysis failed: {e}")
        
        finally:
            await self.connection_service.disconnect()
        
        logger.info(f"ClamAV found {len(findings)} malware/suspicious files")
        return findings