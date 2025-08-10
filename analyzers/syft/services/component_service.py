"""
Component Service

Analyzes SBOM components for security and maintenance issues
Following clean architecture with single responsibility
"""

import logging
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class ComponentService:
    """Analyzes components for potential issues"""
    
    # Package types that are binaries/executables
    BINARY_TYPES = {'binary', 'executable', 'archive'}
    
    def __init__(self):
        self.base_analyzer = BaseAnalyzer()
    
    def analyze_components(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze components for potential issues"""
        findings = []
        
        # Track different types of issues
        duplicate_packages = {}
        binary_packages = []
        unknown_packages = []
        
        # Process all artifacts
        for artifact in sbom.get('artifacts', []):
            self._process_artifact(
                artifact, duplicate_packages, binary_packages, unknown_packages
            )
        
        # Create findings for different issue types
        findings.extend(self._create_binary_findings(binary_packages))
        findings.extend(self._create_duplicate_findings(duplicate_packages))
        findings.extend(self._create_unknown_findings(unknown_packages))
        
        return findings
    
    def _process_artifact(self, artifact: Dict[str, Any], 
                         duplicate_packages: Dict, 
                         binary_packages: List[Dict], 
                         unknown_packages: List[str]):
        """Process a single artifact for issues"""
        pkg_name = artifact.get('name', 'unknown')
        pkg_version = artifact.get('version', 'unknown')
        pkg_type = artifact.get('type', 'unknown')
        
        # Check for binaries
        if pkg_type in self.BINARY_TYPES:
            binary_packages.append({
                'name': pkg_name,
                'type': pkg_type,
                'locations': self._extract_locations(artifact)
            })
        
        # Check for unknown/unidentified packages
        if pkg_version == 'unknown' or not pkg_version:
            unknown_packages.append(pkg_name)
        
        # Track duplicates (different versions of same package)
        if pkg_name in duplicate_packages:
            duplicate_packages[pkg_name].append(pkg_version)
        else:
            duplicate_packages[pkg_name] = [pkg_version]
    
    def _extract_locations(self, artifact: Dict[str, Any]) -> List[str]:
        """Extract file locations from artifact"""
        locations = []
        for location in artifact.get('locations', []):
            path = location.get('path', '')
            if path:
                locations.append(path)
        return locations
    
    def _create_binary_findings(self, binary_packages: List[Dict]) -> List[Finding]:
        """Create findings for binary packages"""
        findings = []
        
        for binary in binary_packages:
            findings.append(self.base_analyzer.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                title=f"Binary Package Detected: {binary['name']}",
                description=self._build_binary_description(binary),
                location=self._get_binary_location(binary),
                recommendation=self._get_binary_recommendation(),
                evidence={
                    'package': binary['name'],
                    'type': binary['type'],
                    'locations': binary['locations']
                }
            ))
        
        return findings
    
    def _create_duplicate_findings(self, duplicate_packages: Dict) -> List[Finding]:
        """Create findings for duplicate packages"""
        findings = []
        
        for pkg_name, versions in duplicate_packages.items():
            unique_versions = set(versions)
            if len(unique_versions) > 1:  # Multiple different versions
                findings.append(self.base_analyzer.create_finding(
                    vulnerability_type=VulnerabilityType.GENERIC,
                    severity=SeverityLevel.LOW,
                    confidence=1.0,
                    title=f"Multiple Versions: {pkg_name}",
                    description=self._build_duplicate_description(pkg_name, unique_versions),
                    location="dependencies",
                    recommendation=self._get_duplicate_recommendation(),
                    evidence={
                        'package': pkg_name,
                        'versions': list(unique_versions)
                    }
                ))
        
        return findings
    
    def _create_unknown_findings(self, unknown_packages: List[str]) -> List[Finding]:
        """Create findings for packages with unknown versions (if significant)"""
        # Only create finding if there are many unknown packages
        if len(unknown_packages) > 5:
            return [self.base_analyzer.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.LOW,
                confidence=0.8,
                title="Many Packages with Unknown Versions",
                description=f"{len(unknown_packages)} packages have unknown or missing version information.",
                location="dependencies",
                recommendation="Improve package management to track versions properly.",
                evidence={
                    'unknown_count': len(unknown_packages),
                    'examples': unknown_packages[:10]  # First 10 examples
                }
            )]
        return []
    
    def _build_binary_description(self, binary: Dict) -> str:
        """Build description for binary package finding"""
        return (f"Binary or executable package '{binary['name']}' found. "
                f"Binary packages are harder to audit for vulnerabilities.")
    
    def _get_binary_location(self, binary: Dict) -> str:
        """Get location for binary package finding"""
        return binary['locations'][0] if binary['locations'] else 'unknown'
    
    def _get_binary_recommendation(self) -> str:
        """Get recommendation for binary packages"""
        return "Consider building from source or using package manager versions when possible."
    
    def _build_duplicate_description(self, pkg_name: str, versions: set) -> str:
        """Build description for duplicate package finding"""
        version_list = ', '.join(sorted(versions))
        return f"Package '{pkg_name}' has multiple versions in the project: {version_list}"
    
    def _get_duplicate_recommendation(self) -> str:
        """Get recommendation for duplicate packages"""
        return "Consolidate to a single version to avoid conflicts and reduce attack surface."