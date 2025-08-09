"""
Trivy Result Parser Service

Converts Trivy scan results into Finding objects
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class ResultParser:
    """Parses Trivy scan results into Finding objects"""
    
    # Map Trivy severity to our severity levels
    SEVERITY_MAP = {
        'CRITICAL': SeverityLevel.CRITICAL,
        'HIGH': SeverityLevel.HIGH,
        'MEDIUM': SeverityLevel.MEDIUM,
        'LOW': SeverityLevel.LOW,
        'UNKNOWN': SeverityLevel.INFO
    }
    
    # Map Trivy vulnerability classes to our types
    VULN_CLASS_MAP = {
        'lang-pkgs': VulnerabilityType.VULNERABLE_DEPENDENCY,
        'os-pkgs': VulnerabilityType.VULNERABLE_DEPENDENCY,
        'config': VulnerabilityType.INSECURE_CONFIGURATION,
        'secret': VulnerabilityType.HARDCODED_SECRET,
        'license': VulnerabilityType.LICENSE_VIOLATION
    }
    
    def __init__(self, base_analyzer):
        self.base_analyzer = base_analyzer
    
    def parse_results(self, results: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Parse Trivy results into Finding objects"""
        findings = []
        
        # Handle new format with Results array
        if isinstance(results, dict) and 'Results' in results:
            for result in results.get('Results', []):
                findings.extend(self._process_result(result, repo_path))
        else:
            # Handle old format or single result
            findings.extend(self._process_result(results, repo_path))
        
        return findings
    
    def _process_result(self, result: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Process a single Trivy result object"""
        findings = []
        
        # Get target information
        target = result.get('Target', 'unknown')
        target_type = result.get('Type', 'unknown')
        
        # Process different types of findings
        findings.extend(self._process_vulnerabilities(result, target, repo_path))
        findings.extend(self._process_misconfigurations(result, target, repo_path))
        findings.extend(self._process_secrets(result, target, repo_path))
        findings.extend(self._process_licenses(result, target, repo_path))
        
        return findings
    
    def _process_vulnerabilities(self, result: Dict[str, Any], target: str, repo_path: str) -> List[Finding]:
        """Process vulnerability findings"""
        findings = []
        
        for vuln in result.get('Vulnerabilities', []):
            finding = self._convert_vulnerability(vuln, target, repo_path)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _process_misconfigurations(self, result: Dict[str, Any], target: str, repo_path: str) -> List[Finding]:
        """Process misconfiguration findings"""
        findings = []
        
        for misconfig in result.get('Misconfigurations', []):
            finding = self._convert_misconfiguration(misconfig, target, repo_path)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _process_secrets(self, result: Dict[str, Any], target: str, repo_path: str) -> List[Finding]:
        """Process secret findings"""
        findings = []
        
        for secret in result.get('Secrets', []):
            finding = self._convert_secret(secret, target, repo_path)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _process_licenses(self, result: Dict[str, Any], target: str, repo_path: str) -> List[Finding]:
        """Process license findings"""
        findings = []
        
        for license_finding in result.get('Licenses', []):
            finding = self._convert_license(license_finding, target, repo_path)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _convert_vulnerability(self, vuln: Dict[str, Any], target: str, repo_path: str) -> Optional[Finding]:
        """Convert Trivy vulnerability to Finding"""
        # Extract basic info
        vuln_id = vuln.get('VulnerabilityID', 'UNKNOWN')
        pkg_name = vuln.get('PkgName', 'unknown')
        installed_version = vuln.get('InstalledVersion', 'unknown')
        fixed_version = vuln.get('FixedVersion', '')
        
        # Get severity and build description
        severity = self.SEVERITY_MAP.get(vuln.get('Severity', 'UNKNOWN'), SeverityLevel.MEDIUM)
        description = self._build_vulnerability_description(vuln, pkg_name)
        
        # Get references and location
        references = self._extract_references(vuln)
        location = self._get_relative_location(target, repo_path)
        
        # Build recommendation
        recommendation = self._build_vulnerability_recommendation(pkg_name, fixed_version)
        
        # Get CVSS score for confidence
        cvss_score = self._extract_cvss_score(vuln)
        confidence = min(0.9, max(0.6, cvss_score / 10.0)) if cvss_score > 0 else 0.8
        
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=confidence,
            title=f"{vuln_id} in {pkg_name}",
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence={
                'vulnerability_id': vuln_id,
                'package_name': pkg_name,
                'installed_version': installed_version,
                'fixed_version': fixed_version,
                'cvss_score': cvss_score,
                'scanner': 'Trivy'
            }
        )
    
    def _convert_misconfiguration(self, misconfig: Dict[str, Any], target: str, repo_path: str) -> Optional[Finding]:
        """Convert Trivy misconfiguration to Finding"""
        rule_id = misconfig.get('ID', 'UNKNOWN')
        title = misconfig.get('Title', 'Configuration issue')
        description = misconfig.get('Description', 'Security misconfiguration detected')
        severity = self.SEVERITY_MAP.get(misconfig.get('Severity', 'MEDIUM'), SeverityLevel.MEDIUM)
        
        # Build location with line info if available
        location = self._get_relative_location(target, repo_path)
        if misconfig.get('CauseMetadata', {}).get('StartLine'):
            location += f":{misconfig['CauseMetadata']['StartLine']}"
        
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
            severity=severity,
            confidence=0.85,
            title=f"Configuration: {title}",
            description=description,
            location=location,
            recommendation=misconfig.get('Message', 'Fix the configuration issue'),
            references=misconfig.get('References', []),
            evidence={
                'rule_id': rule_id,
                'scanner': 'Trivy'
            }
        )
    
    def _convert_secret(self, secret: Dict[str, Any], target: str, repo_path: str) -> Optional[Finding]:
        """Convert Trivy secret to Finding"""
        rule_id = secret.get('RuleID', 'UNKNOWN')
        title = secret.get('Title', 'Secret detected')
        match = secret.get('Match', 'Sensitive data detected')
        
        location = self._get_relative_location(target, repo_path)
        if secret.get('StartLine'):
            location += f":{secret['StartLine']}"
        
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
            severity=SeverityLevel.HIGH,
            confidence=0.9,
            title=f"Secret: {title}",
            description=f"Potential secret or sensitive data found: {match}",
            location=location,
            recommendation="Remove the hardcoded secret and use environment variables or secure key management",
            references=[],
            evidence={
                'rule_id': rule_id,
                'match': match,
                'scanner': 'Trivy'
            }
        )
    
    def _convert_license(self, license_finding: Dict[str, Any], target: str, repo_path: str) -> Optional[Finding]:
        """Convert Trivy license finding to Finding"""
        name = license_finding.get('Name', 'Unknown')
        confidence = license_finding.get('Confidence', 0.0)
        
        # Map confidence to severity (lower confidence = higher concern)
        if confidence < 0.5:
            severity = SeverityLevel.HIGH
        elif confidence < 0.8:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW
        
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
            severity=severity,
            confidence=confidence,
            title=f"License: {name}",
            description=f"License detected: {name}",
            location=self._get_relative_location(target, repo_path),
            recommendation="Review license compatibility with your project",
            references=[],
            evidence={
                'license_name': name,
                'scanner': 'Trivy'
            }
        )
    
    def _build_vulnerability_description(self, vuln: Dict[str, Any], pkg_name: str) -> str:
        """Build comprehensive vulnerability description"""
        description = vuln.get('Description', f'Vulnerability in {pkg_name}')
        if vuln.get('Title'):
            description = f"{vuln['Title']}. {description}"
        return description
    
    def _extract_references(self, vuln: Dict[str, Any]) -> List[str]:
        """Extract reference URLs from vulnerability"""
        references = vuln.get('References', [])
        if vuln.get('PrimaryURL'):
            references.insert(0, vuln['PrimaryURL'])
        return references
    
    def _get_relative_location(self, target: str, repo_path: str) -> str:
        """Get relative path location"""
        try:
            return str(Path(target).relative_to(repo_path))
        except:
            return target
    
    def _build_vulnerability_recommendation(self, pkg_name: str, fixed_version: str) -> str:
        """Build vulnerability fix recommendation"""
        if fixed_version:
            return f"Update {pkg_name} to version {fixed_version} or later"
        else:
            return f"No fix available yet for {pkg_name}. Monitor for updates or consider alternatives."
    
    def _extract_cvss_score(self, vuln: Dict[str, Any]) -> float:
        """Extract CVSS score from vulnerability"""
        cvss_data = vuln.get('CVSS', {})
        for source, scores in cvss_data.items():
            if isinstance(scores, dict) and scores.get('V3Score'):
                return float(scores['V3Score'])
            elif isinstance(scores, dict) and scores.get('V2Score'):
                return float(scores['V2Score'])
        return 0.0