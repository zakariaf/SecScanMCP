"""Pattern definitions for capability abuse detection."""

from typing import Dict, List, Any, Set
from models import SeverityLevel


class CapabilityPatterns:
    """Stores capability detection patterns."""

    CAPABILITY_PATTERNS = [
        {
            'pattern': r'(?i)capability\s*[=:]\s*[\'"].*admin.*[\'"]',
            'severity': SeverityLevel.HIGH,
            'title': 'Admin Capability Exposure'
        },
        {
            'pattern': r'(?i)(grant|give|allow)\s+.*\s+(all|full|admin|root)\s+(access|permissions?)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Full Access Grant'
        },
        {
            'pattern': r'(?i)(bypass|skip|ignore)\s+(permission|auth|security)\s+check',
            'severity': SeverityLevel.HIGH,
            'title': 'Security Bypass'
        }
    ]

    ABUSE_INDICATORS = {
        'file_system_abuse': {
            'patterns': [
                r'(?i)(delete|remove|rm)\s+.*\*',
                r'(?i)rmdir\s+.*-r',
                r'(?i)(chmod|chown)\s+.*777'
            ],
            'severity': SeverityLevel.HIGH,
            'description': 'File system abuse patterns'
        },
        'network_abuse': {
            'patterns': [
                r'(?i)(curl|wget|requests)\s+.*attack',
                r'(?i)nmap\s+.*scan',
                r'(?i)socket.*connect.*brute'
            ],
            'severity': SeverityLevel.MEDIUM,
            'description': 'Network abuse patterns'
        },
        'data_exfiltration': {
            'patterns': [
                r'(?i)(send|post|upload)\s+.*\.(passwd|shadow|key)',
                r'(?i)(exfil|extract|steal)\s+.*data',
                r'(?i)base64.*encode.*secret'
            ],
            'severity': SeverityLevel.CRITICAL,
            'description': 'Data exfiltration patterns'
        }
    }

    BYPASS_PATTERNS = [
        r'(?i)if.*auth.*==.*false',
        r'(?i)(skip|bypass|ignore).*auth',
        r'(?i)auth.*disabled?',
        r'(?i)no.*auth.*required?'
    ]

    DANGEROUS_RESOURCE_PATTERNS = [
        r'(?i)(file|path)\s*:\s*[\'"][^\'\"]*\.\./.*[\'"]',
        r'(?i)(url|uri)\s*:\s*[\'"]file://',
        r'(?i)(command|exec)\s*:\s*[\'"][^\'\"]*\|',
    ]

    TOOL_NAME_PATTERNS = [
        r'@mcp\.tool\([\'"]([^\'"]+)[\'"]',
        r'def\s+tool_([a-zA-Z_][a-zA-Z0-9_]*)',
        r'register_tool\([\'"]([^\'"]+)[\'"]'
    ]

    DANGEROUS_OPERATIONS: Set[str] = {
        'eval', 'exec', 'compile', '__import__',
        'os.system', 'subprocess.call', 'subprocess.run',
        'open', 'file', 'input', 'raw_input'
    }

    DANGEROUS_ENV_VALUES = ['DEBUG=1', 'DEV_MODE=true', 'DISABLE_AUTH=true']
