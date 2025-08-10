"""
License Service

Analyzes SBOM for license compliance and compatibility issues
Following clean architecture with single responsibility
"""

import logging
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class LicenseService:
    """Analyzes licenses for compliance issues"""
    
    # Define problematic licenses for different use cases
    RESTRICTIVE_LICENSES = {
        'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'GPL-2.0+', 'GPL-3.0+',
        'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only'
    }
    
    # Weak copyleft that might cause issues
    WEAK_COPYLEFT_LICENSES = {
        'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0'
    }
    
    def __init__(self):
        self.base_analyzer = BaseAnalyzer()
    
    def analyze_licenses(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze licenses in SBOM for potential issues"""
        findings = []
        
        license_summary = {}
        problematic_packages = []
        
        # Process all artifacts
        for artifact in sbom.get('artifacts', []):
            self._process_artifact_licenses(
                artifact, license_summary, problematic_packages
            )
        
        # Create findings for problematic licenses
        findings.extend(self._create_license_findings(problematic_packages))
        
        # Create summary finding if complex license landscape
        if len(license_summary) > 5:
            findings.append(self._create_complexity_finding(license_summary))
        
        return findings
    
    def _process_artifact_licenses(self, artifact: Dict[str, Any], 
                                   license_summary: Dict, 
                                   problematic_packages: List[Dict]):
        """Process licenses for a single artifact"""
        licenses = artifact.get('licenses', [])
        if not licenses:
            return
        
        pkg_name = artifact.get('name', 'unknown')
        pkg_version = artifact.get('version', 'unknown')
        
        for license_info in licenses:
            license_name = license_info.get('value', 'unknown')
            if not license_name or license_name == 'unknown':
                continue
            
            # Track license usage
            if license_name not in license_summary:
                license_summary[license_name] = []
            license_summary[license_name].append(f"{pkg_name}@{pkg_version}")
            
            # Check for problematic licenses
            license_type = self._classify_license(license_name)
            if license_type:
                problematic_packages.append({
                    'package': pkg_name,
                    'version': pkg_version,
                    'license': license_name,
                    'type': license_type
                })
    
    def _classify_license(self, license_name: str) -> str:
        """Classify license by restrictiveness"""
        if license_name in self.RESTRICTIVE_LICENSES:
            return 'restrictive'
        elif license_name in self.WEAK_COPYLEFT_LICENSES:
            return 'weak_copyleft'
        return None
    
    def _create_license_findings(self, problematic_packages: List[Dict]) -> List[Finding]:
        """Create findings for problematic licenses"""
        findings = []
        
        for pkg in problematic_packages:
            severity = (SeverityLevel.HIGH if pkg['type'] == 'restrictive' 
                       else SeverityLevel.MEDIUM)
            
            findings.append(self.base_analyzer.create_finding(
                vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
                severity=severity,
                confidence=0.95,
                title=f"Restrictive License: {pkg['package']} uses {pkg['license']}",
                description=self._build_license_description(pkg),
                location=f"dependency:{pkg['package']}",
                recommendation=self._get_license_recommendation(),
                references=self._get_license_references(pkg['license']),
                evidence={
                    'package': pkg['package'],
                    'version': pkg['version'],
                    'license': pkg['license'],
                    'license_type': pkg['type']
                }
            ))
        
        return findings
    
    def _build_license_description(self, pkg: Dict) -> str:
        """Build description for license finding"""
        return (f"Package {pkg['package']} is licensed under {pkg['license']}, "
                f"which may conflict with commercial use or require source code disclosure.")
    
    def _get_license_recommendation(self) -> str:
        """Get recommendation for license issues"""
        return ("Review license compatibility with your project. "
                "Consider finding alternatives with more permissive licenses.")
    
    def _get_license_references(self, license_name: str) -> List[str]:
        """Get reference URLs for license"""
        return [
            f"https://spdx.org/licenses/{license_name}.html",
            "https://choosealicense.com/licenses/"
        ]
    
    def _create_complexity_finding(self, license_summary: Dict) -> Finding:
        """Create finding for complex license landscape"""
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
            severity=SeverityLevel.LOW,
            confidence=1.0,
            title="Complex License Landscape",
            description=f"Project uses {len(license_summary)} different licenses across dependencies.",
            location="project",
            recommendation="Consider standardizing on compatible licenses and document license policy.",
            evidence={
                'license_count': len(license_summary),
                'licenses': list(license_summary.keys())[:10]  # Top 10
            }
        )