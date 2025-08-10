"""
Main Syft Analyzer

Orchestrates SBOM generation and analysis for package and license issues
Following clean architecture principles with ≤100 lines per file
"""

import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.sbom_service import SBOMService
from .services.license_service import LicenseService
from .services.component_service import ComponentService
from .services.metadata_service import MetadataService

logger = logging.getLogger(__name__)


class SyftAnalyzer(BaseAnalyzer):
    """Clean orchestrator for Syft SBOM analysis"""
    
    def __init__(self):
        super().__init__()
        self.sbom_service = SBOMService()
        self.license_service = LicenseService()
        self.component_service = ComponentService()
        self.metadata_service = MetadataService()
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Generate SBOM and analyze for licensing and component issues"""
        findings = []
        
        try:
            # Generate SBOM
            sbom_data = await self.sbom_service.generate_sbom(repo_path)
            if not sbom_data:
                logger.warning("Failed to generate SBOM, skipping analysis")
                return findings
            
            # Analyze different aspects
            findings.extend(self._analyze_licenses(sbom_data, repo_path))
            findings.extend(self._analyze_components(sbom_data, repo_path))
            findings.extend(self._analyze_metadata(sbom_data, repo_path))
            
            # Store SBOM summary for other analyzers
            self._store_sbom_summary(sbom_data, project_info)
            
            logger.info(f"Syft analysis found {len(findings)} issues")
            
        except Exception as e:
            logger.error(f"Syft analysis failed: {e}")
        
        return findings
    
    def _analyze_licenses(self, sbom_data: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze licenses using license service"""
        return self.license_service.analyze_licenses(sbom_data, repo_path)
    
    def _analyze_components(self, sbom_data: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze components using component service"""
        return self.component_service.analyze_components(sbom_data, repo_path)
    
    def _analyze_metadata(self, sbom_data: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze metadata using metadata service"""
        return self.metadata_service.analyze_metadata(sbom_data, repo_path)
    
    def _store_sbom_summary(self, sbom_data: Dict[str, Any], project_info: Dict[str, Any]):
        """Store SBOM summary for other analyzers"""
        if 'sbom_summary' not in project_info:
            project_info['sbom_summary'] = self.metadata_service.create_sbom_summary(sbom_data)