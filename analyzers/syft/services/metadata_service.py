"""
Metadata Service

Analyzes SBOM metadata and creates summaries for other analyzers
Following clean architecture with single responsibility
"""

import logging
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class MetadataService:
    """Analyzes SBOM metadata and creates summaries"""
    
    # Threshold for considering SBOM incomplete (10% missing info)
    INCOMPLETENESS_THRESHOLD = 0.1
    
    def __init__(self):
        pass  # BaseAnalyzer removed - services create Finding objects directly
    
    def analyze_metadata(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze SBOM metadata for completeness and issues"""
        findings = []
        
        artifacts = sbom.get('artifacts', [])
        total_packages = len(artifacts)
        
        if total_packages == 0:
            return findings
        
        # Analyze completeness
        completeness_stats = self._analyze_completeness(artifacts)
        
        # Create finding if many packages have incomplete info
        if self._is_significantly_incomplete(completeness_stats, total_packages):
            findings.append(self._create_incompleteness_finding(
                completeness_stats, total_packages
            ))
        
        return findings
    
    def _analyze_completeness(self, artifacts: List[Dict]) -> Dict[str, int]:
        """Analyze completeness of package information"""
        stats = {
            'incomplete_count': 0,
            'missing_versions': 0,
            'missing_licenses': 0
        }
        
        for artifact in artifacts:
            version_missing = self._is_version_missing(artifact)
            license_missing = self._is_license_missing(artifact)
            
            if version_missing:
                stats['missing_versions'] += 1
                stats['incomplete_count'] += 1
            
            if license_missing:
                stats['missing_licenses'] += 1
        
        return stats
    
    def _is_version_missing(self, artifact: Dict) -> bool:
        """Check if artifact has missing version"""
        version = artifact.get('version')
        return not version or version == 'unknown'
    
    def _is_license_missing(self, artifact: Dict) -> bool:
        """Check if artifact has missing license"""
        licenses = artifact.get('licenses', [])
        return not licenses
    
    def _is_significantly_incomplete(self, stats: Dict[str, int], total: int) -> bool:
        """Check if incompleteness is significant"""
        return stats['incomplete_count'] > total * self.INCOMPLETENESS_THRESHOLD
    
    def _create_incompleteness_finding(self, stats: Dict[str, int],
                                     total_packages: int) -> Finding:
        """Create finding for incomplete package information"""
        return Finding(
            vulnerability_type=VulnerabilityType.GENERIC,
            severity=SeverityLevel.LOW,
            confidence=1.0,
            title="Incomplete Package Information",
            description=self._build_incompleteness_description(stats, total_packages),
            location="sbom",
            recommendation=self._get_incompleteness_recommendation(),
            evidence={
                'total_packages': total_packages,
                'incomplete_count': stats['incomplete_count'],
                'missing_versions': stats['missing_versions'],
                'missing_licenses': stats['missing_licenses']
            },
            tool="syft"
        )
    
    def _build_incompleteness_description(self, stats: Dict[str, int], 
                                        total: int) -> str:
        """Build description for incompleteness finding"""
        return (f"{stats['incomplete_count']} out of {total} packages "
                f"have incomplete information.")
    
    def _get_incompleteness_recommendation(self) -> str:
        """Get recommendation for incomplete information"""
        return ("Improve package detection by using proper package managers "
                "and maintaining metadata.")
    
    def create_sbom_summary(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of SBOM contents for other analyzers"""
        artifacts = sbom.get('artifacts', [])
        
        # Count by type and infer languages
        type_counts = {}
        language_counts = {}
        
        for artifact in artifacts:
            pkg_type = artifact.get('type', 'unknown')
            type_counts[pkg_type] = type_counts.get(pkg_type, 0) + 1
            
            # Infer language from package type
            language = self._infer_language_from_type(pkg_type)
            if language:
                language_counts[language] = language_counts.get(language, 0) + 1
        
        return {
            'total_packages': len(artifacts),
            'package_types': type_counts,
            'languages': language_counts,
            'has_binaries': self._has_binaries(artifacts),
            'source': sbom.get('source', {})
        }
    
    def _infer_language_from_type(self, pkg_type: str) -> str:
        """Infer programming language from package type"""
        language_map = {
            'python': 'python',
            'wheel': 'python',
            'egg': 'python',
            'npm': 'javascript',
            'yarn': 'javascript',
            'gem': 'ruby',
            'go-module': 'go',
            'cargo': 'rust',
            'rust': 'rust',
            'jar': 'java',
            'maven': 'java'
        }
        
        return language_map.get(pkg_type)
    
    def _has_binaries(self, artifacts: List[Dict]) -> bool:
        """Check if SBOM contains binary artifacts"""
        binary_types = {'binary', 'executable'}
        return any(a.get('type') in binary_types for a in artifacts)