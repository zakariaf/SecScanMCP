"""
TruffleHog Finding Service

Converts TruffleHog results to standardized findings with secret masking
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class FindingService:
    """Converts TruffleHog results to findings with secret protection"""
    
    # Map detector types to our vulnerability types
    SECRET_TYPE_MAP = {
        'AWS': VulnerabilityType.API_KEY_EXPOSURE,
        'GitHub': VulnerabilityType.API_KEY_EXPOSURE,
        'GitLab': VulnerabilityType.API_KEY_EXPOSURE,
        'Slack': VulnerabilityType.API_KEY_EXPOSURE,
        'PrivateKey': VulnerabilityType.HARDCODED_SECRET,
        'JWT': VulnerabilityType.HARDCODED_SECRET,
        'Password': VulnerabilityType.HARDCODED_SECRET,
        'Generic': VulnerabilityType.HARDCODED_SECRET,
    }
    
    def __init__(self):
        self.base_analyzer = BaseAnalyzer()
    
    def convert_to_finding(self, trufflehog_result: Dict[str, Any], repo_path: str) -> Finding:
        """Convert TruffleHog result to our Finding model with secret masking"""
        # Extract detector information
        detector_name = trufflehog_result.get('DetectorName', 'Unknown')
        detector_type = trufflehog_result.get('DetectorType', 0)
        
        # Determine vulnerability type and severity
        vuln_type = self._determine_vulnerability_type(detector_name)
        severity = self._determine_severity(detector_name)
        confidence = self._calculate_confidence(trufflehog_result)
        
        # Extract location information
        location = self._extract_location(trufflehog_result, repo_path)
        
        # Build finding components
        title = f"{detector_name} Secret Detected"
        description = f"Found {detector_name} credentials in source code"
        recommendation = self._get_recommendation()
        references = self._get_references()
        evidence = self._build_evidence(trufflehog_result, detector_name, detector_type)
        
        return self.base_analyzer.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence=evidence
        )
    
    def _determine_vulnerability_type(self, detector_name: str) -> VulnerabilityType:
        """Determine vulnerability type from detector name"""
        for key, vtype in self.SECRET_TYPE_MAP.items():
            if key.lower() in detector_name.lower():
                return vtype
        
        return VulnerabilityType.HARDCODED_SECRET
    
    def _determine_severity(self, detector_name: str) -> SeverityLevel:
        """Determine severity based on detector name"""
        # Lower severity for test/example credentials
        if 'test' in detector_name.lower() or 'example' in detector_name.lower():
            return SeverityLevel.MEDIUM
        
        # All other secrets are high severity by default
        return SeverityLevel.HIGH
    
    def _calculate_confidence(self, trufflehog_result: Dict[str, Any]) -> float:
        """Calculate confidence based on verification status"""
        # Higher confidence if secret is verified as valid
        return 0.95 if trufflehog_result.get('VerifiedResult', False) else 0.7
    
    def _extract_location(self, trufflehog_result: Dict[str, Any], repo_path: str) -> str:
        """Extract file location and line number"""
        source_metadata = trufflehog_result.get('SourceMetadata', {})
        data = source_metadata.get('Data', {})
        
        # Build file location
        file_path = data.get('Filesystem', {}).get('file', 'unknown')
        try:
            file_path = Path(file_path).relative_to(repo_path)
        except (ValueError, TypeError):
            pass
        
        line_num = data.get('Filesystem', {}).get('line', 0)
        return f"{file_path}:{line_num}"
    
    def _get_recommendation(self) -> str:
        """Get standard recommendation for secret findings"""
        return ("Remove the secret immediately and rotate the credentials. "
                "Use environment variables or a secret management system instead.")
    
    def _get_references(self) -> list:
        """Get reference URLs for secret vulnerabilities"""
        return [
            "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"
        ]
    
    def _build_evidence(self, trufflehog_result: Dict[str, Any], 
                       detector_name: str, detector_type: int) -> Dict[str, Any]:
        """Build evidence dictionary with masked secret"""
        source_metadata = trufflehog_result.get('SourceMetadata', {})
        data = source_metadata.get('Data', {})
        
        # Mask the actual secret for security
        raw_secret = trufflehog_result.get('Raw', '')
        masked_secret = self._mask_secret(raw_secret)
        
        return {
            'detector': detector_name,
            'masked_secret': masked_secret,
            'verified': trufflehog_result.get('Verified', False),
            'secret_type': detector_type,
            'line_content': data.get('Filesystem', {}).get('line_content', '')
        }
    
    def _mask_secret(self, raw_secret: str) -> str:
        """Mask secret for evidence while preserving some characters for identification"""
        if not raw_secret:
            return ''
        
        if len(raw_secret) > 8:
            # Show first 4 and last 4 characters, mask the middle
            return raw_secret[:4] + '*' * (len(raw_secret) - 8) + raw_secret[-4:]
        else:
            # For shorter secrets, mask everything
            return '*' * len(raw_secret)