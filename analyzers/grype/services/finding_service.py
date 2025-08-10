"""
Finding Service for Grype

Converts Grype vulnerability matches to standardized findings
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import Dict, Any, List

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class FindingService:
    """Converts Grype matches to findings"""
    
    # Map Grype severity to our severity levels
    SEVERITY_MAP = {
        'Critical': SeverityLevel.CRITICAL,
        'High': SeverityLevel.HIGH,
        'Medium': SeverityLevel.MEDIUM,
        'Low': SeverityLevel.LOW,
        'Negligible': SeverityLevel.INFO,
        'Unknown': SeverityLevel.INFO
    }
    
    def __init__(self):
        self.base_analyzer = BaseAnalyzer()
    
    def convert_match(self, match: Dict[str, Any], repo_path: str) -> Finding:
        """Convert Grype match to Finding"""
        # Extract basic information
        vulnerability = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        # Get vulnerability details
        vuln_id = vulnerability.get('id', 'UNKNOWN')
        severity = self._get_severity(vulnerability)
        confidence = self._calculate_confidence(match)
        
        # Get package details
        pkg_name = artifact.get('name', 'unknown')
        pkg_version = artifact.get('version', 'unknown')
        pkg_type = artifact.get('type', 'unknown')
        
        # Build finding components
        title = f"{vuln_id}: {pkg_name} {pkg_version}"
        description = vulnerability.get('description', f'Vulnerability in {pkg_name}')
        location = self._get_location(artifact, repo_path, pkg_type)
        fix_versions = self._extract_fix_versions(vulnerability)
        recommendation = self._build_recommendation(pkg_name, fix_versions)
        references = self._extract_references(vulnerability)
        evidence = self._build_evidence(match, fix_versions, confidence)
        
        # Adjust severity for known exploited vulnerabilities
        severity = self._adjust_severity_for_kev(vulnerability, severity)
        
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence=evidence,
            cve_id=vuln_id if vuln_id.startswith('CVE-') else None
        )
    
    def _get_severity(self, vulnerability: Dict[str, Any]) -> SeverityLevel:
        """Get severity level from vulnerability data"""
        severity_str = vulnerability.get('severity', 'Unknown')
        return self.SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)
    
    def _calculate_confidence(self, match: Dict[str, Any]) -> float:
        """Calculate confidence based on match quality"""
        confidence = 0.9  # Base confidence
        
        match_details = match.get('matchDetails', [])
        if match_details:
            detail = match_details[0]
            match_type = detail.get('type', '')
            
            if match_type == 'exact-direct-match':
                confidence = 0.95
            elif match_type == 'exact-indirect-match':
                confidence = 0.85
        
        return confidence
    
    def _get_location(self, artifact: Dict[str, Any], repo_path: str, pkg_type: str) -> str:
        """Get location string for the finding"""
        locations = artifact.get('locations', [])
        
        if locations:
            location = locations[0].get('path', 'unknown')
            try:
                location = str(Path(location).relative_to(repo_path))
            except:
                pass
            return location
        else:
            return f"{pkg_type} package"
    
    def _extract_fix_versions(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Extract fix versions from vulnerability data"""
        fix_versions = []
        fix_field = vulnerability.get('fix', {})
        
        if isinstance(fix_field, dict):
            # old format: { "versions": [ ... ] }
            fix_versions = fix_field.get('versions', [])
        elif isinstance(fix_field, list):
            # new format: [ { "versions": [...] }, ... ] or just a list of version strings
            for entry in fix_field:
                if isinstance(entry, dict) and 'versions' in entry:
                    fix_versions.extend(entry.get('versions', []))
                elif isinstance(entry, str):
                    fix_versions.append(entry)
        
        return fix_versions
    
    def _build_recommendation(self, pkg_name: str, fix_versions: List[str]) -> str:
        """Build recommendation text"""
        if fix_versions:
            return f"Update {pkg_name} to one of: {', '.join(fix_versions)}"
        else:
            return f"No fix available for {pkg_name}. Monitor for updates or consider alternatives."
    
    def _extract_references(self, vulnerability: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from vulnerability"""
        return vulnerability.get('urls', [])
    
    def _build_evidence(self, match: Dict[str, Any], fix_versions: List[str], 
                       confidence: float) -> Dict[str, Any]:
        """Build evidence dictionary"""
        vulnerability = match.get('vulnerability', {})
        artifact = match.get('artifact', {})
        
        evidence = {
            'vulnerability_id': vulnerability.get('id', 'UNKNOWN'),
            'package': artifact.get('name', 'unknown'),
            'version': artifact.get('version', 'unknown'),
            'package_type': artifact.get('type', 'unknown'),
            'fixed_versions': fix_versions,
            'match_confidence': confidence
        }
        
        # Add CVSS scores
        cvss_scores = self._extract_cvss_scores(vulnerability)
        if cvss_scores:
            evidence['cvss_scores'] = cvss_scores
            evidence['cvss_max'] = max(data['score'] for data in cvss_scores.values())
        
        # Add related vulnerabilities
        related = [rel.get('id') for rel in vulnerability.get('relatedVulnerabilities', [])]
        if related:
            evidence['related_vulnerabilities'] = related
        
        # Add EPSS data
        epss_data = self._extract_epss_data(vulnerability)
        if epss_data:
            evidence.update(epss_data)
        
        # Add KEV data
        if self._has_kev_data(vulnerability):
            evidence['is_known_exploited'] = True
            evidence['kev_data'] = vulnerability.get('kev', {})
        
        return evidence
    
    def _extract_cvss_scores(self, vulnerability: Dict[str, Any]) -> Dict[str, Dict]:
        """Extract CVSS scores from vulnerability"""
        cvss_scores = {}
        
        for cvss in vulnerability.get('cvss', []):
            version = cvss.get('version', 'unknown')
            cvss_scores[version] = {
                'score': cvss.get('metrics', {}).get('baseScore', 0),
                'vector': cvss.get('vector', '')
            }
        
        return cvss_scores
    
    def _extract_epss_data(self, vulnerability: Dict[str, Any]) -> Dict[str, Any]:
        """Extract EPSS data from vulnerability"""
        epss_data = {}
        epss_field = vulnerability.get('epss')
        
        if isinstance(epss_field, dict):
            # older single-object format
            epss_score = epss_field.get('score') or epss_field.get('epss')
            epss_percentile = epss_field.get('percentile')
        elif isinstance(epss_field, list) and epss_field:
            # new array format: pick the first entry
            first = epss_field[0]
            if isinstance(first, dict):
                epss_score = first.get('epss', first.get('score'))
                epss_percentile = first.get('percentile')
            else:
                return {}
        else:
            return {}
        
        if epss_score is not None:
            epss_data['epss_score'] = epss_score
            if epss_percentile is not None:
                epss_data['epss_percentile'] = epss_percentile
        
        return epss_data
    
    def _has_kev_data(self, vulnerability: Dict[str, Any]) -> bool:
        """Check if vulnerability has KEV data"""
        return 'kev' in vulnerability
    
    def _adjust_severity_for_kev(self, vulnerability: Dict[str, Any], 
                                severity: SeverityLevel) -> SeverityLevel:
        """Adjust severity if vulnerability is known exploited"""
        if self._has_kev_data(vulnerability):
            # Increase severity for known exploited vulnerabilities
            if severity == SeverityLevel.MEDIUM:
                return SeverityLevel.HIGH
            elif severity == SeverityLevel.LOW:
                return SeverityLevel.MEDIUM
        
        return severity