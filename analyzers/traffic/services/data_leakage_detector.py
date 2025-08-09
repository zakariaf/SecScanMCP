"""Data leakage detection service."""

import re
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class DataLeakageDetector:
    """Advanced detection of data leakage patterns."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.sensitive_patterns = self._initialize_sensitive_patterns()
        self.entropy_threshold = 4.5  # Minimum entropy for encrypted/encoded data
    
    def _initialize_sensitive_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize patterns for sensitive data detection."""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'api_key': re.compile(r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            'password_hash': re.compile(r'\$[a-z0-9]+\$[^$]*\$[A-Za-z0-9/.]{20,}'),
            'private_key': re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'github_token': re.compile(r'ghp_[A-Za-z0-9]{36}'),
        }
    
    def scan_for_sensitive_data(self, data: str) -> List[Dict[str, Any]]:
        """Scan data for sensitive information patterns."""
        findings = []
        
        try:
            for pattern_name, pattern in self.sensitive_patterns.items():
                matches = pattern.findall(data)
                
                for match in matches:
                    # Calculate entropy to detect encoded data
                    entropy = self._calculate_entropy(match)
                    
                    finding = {
                        'type': pattern_name,
                        'value': self._mask_sensitive_data(match),
                        'original_length': len(match),
                        'entropy': entropy,
                        'confidence': self._calculate_confidence(pattern_name, match, entropy),
                        'position': data.find(match),
                        'context': self._extract_context(data, data.find(match))
                    }
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Sensitive data scanning failed: {e}")
        
        return findings
    
    def detect_bulk_data_transfer(self, data: str, size_threshold: int = 10000) -> bool:
        """Detect potential bulk data transfer."""
        if len(data) < size_threshold:
            return False
        
        # Check for structured data patterns
        structured_indicators = [
            data.count('\n') > 100,  # Many lines
            data.count(',') > 200,   # CSV-like data
            data.count('{') > 50,    # JSON-like data
            data.count('<') > 50,    # XML-like data
        ]
        
        return any(structured_indicators)
    
    def analyze_data_encoding(self, data: str) -> Dict[str, Any]:
        """Analyze data encoding patterns."""
        analysis = {
            'base64_detected': False,
            'hex_encoded': False,
            'url_encoded': False,
            'entropy': 0.0,
            'likely_compressed': False,
            'likely_encrypted': False
        }
        
        try:
            # Check for Base64
            if re.search(r'[A-Za-z0-9+/]{40,}={0,2}', data):
                analysis['base64_detected'] = True
            
            # Check for hex encoding
            if re.search(r'[0-9a-fA-F]{64,}', data):
                analysis['hex_encoded'] = True
            
            # Check for URL encoding
            if '%' in data and re.search(r'%[0-9a-fA-F]{2}', data):
                analysis['url_encoded'] = True
            
            # Calculate entropy
            analysis['entropy'] = self._calculate_entropy(data)
            
            # High entropy analysis
            if analysis['entropy'] > 7.5:
                analysis['likely_compressed'] = True
            if analysis['entropy'] > 7.8:
                analysis['likely_encrypted'] = True
        
        except Exception as e:
            self.logger.error(f"Encoding analysis failed: {e}")
        
        return analysis
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data."""
        import math
        from collections import Counter
        
        if not data:
            return 0.0
        
        # Count character frequencies
        frequencies = Counter(data)
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        for count in frequencies.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _mask_sensitive_data(self, data: str) -> str:
        """Mask sensitive data for logging."""
        if len(data) <= 4:
            return '*' * len(data)
        
        # Show first 2 and last 2 characters
        return data[:2] + '*' * (len(data) - 4) + data[-2:]
    
    def _calculate_confidence(self, pattern_type: str, match: str, entropy: float) -> float:
        """Calculate confidence score for a match."""
        base_confidence = 0.7
        
        # Adjust based on pattern type
        high_confidence_patterns = ['ssn', 'credit_card', 'jwt_token']
        if pattern_type in high_confidence_patterns:
            base_confidence = 0.9
        
        # Adjust based on entropy (higher entropy = more likely real)
        if entropy > 4.0:
            base_confidence += 0.1
        
        # Adjust based on length (longer matches = more confidence)
        if len(match) > 20:
            base_confidence += 0.1
        
        return min(base_confidence, 1.0)
    
    def _extract_context(self, data: str, position: int, window: int = 50) -> str:
        """Extract context around a match."""
        start = max(0, position - window)
        end = min(len(data), position + window)
        
        context = data[start:end]
        # Mask the actual sensitive data in context
        return context.replace('\n', '\\n')[:100] + ('...' if len(context) > 100 else '')