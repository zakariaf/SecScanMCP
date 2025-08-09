"""Security patterns for MCP vulnerability detection."""

from dataclasses import dataclass
from typing import Optional
from models import SeverityLevel


@dataclass
class InjectionPattern:
    """Represents an injection pattern to detect."""
    pattern: str
    severity: SeverityLevel
    title: str
    cve: Optional[str] = None


class MCPPatterns:
    """Container for all MCP security patterns."""
    
    @staticmethod
    def get_injection_patterns() -> list[InjectionPattern]:
        """Get all injection detection patterns."""
        return [
            # Critical patterns from real exploits
            InjectionPattern(
                pattern=r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?|directives?)',
                severity=SeverityLevel.CRITICAL,
                title='Tool Poisoning: Direct instruction override',
                cve='Related to MCP Tool Poisoning Attacks'
            ),
            InjectionPattern(
                pattern=r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
                severity=SeverityLevel.CRITICAL,
                title='Tool Poisoning: Hidden directive markers',
                cve='Invariant Labs TPA'
            ),
            InjectionPattern(
                pattern=r'(?i)before\s+you\s+do\s+anything\s+else',
                severity=SeverityLevel.CRITICAL,
                title='Tool Poisoning: Priority override attempt'
            ),
            InjectionPattern(
                pattern=r'(?i)(system|admin|root|developer|privileged)[\s:]+mode\s+(enabled?|on|activated?|true)',
                severity=SeverityLevel.HIGH,
                title='Privilege escalation attempt'
            ),
            InjectionPattern(
                pattern=r'(?i)you\s+are\s+now\s+(a|an|in)\s+(admin|root|system|privileged)',
                severity=SeverityLevel.HIGH,
                title='Role manipulation'
            ),
            InjectionPattern(
                pattern=r'(?i)@(recipient|proxy|forward):\s*[\+\w@\.]',
                severity=SeverityLevel.HIGH,
                title='Data exfiltration pattern'
            ),
            InjectionPattern(
                pattern=r'(?i)(forward|send|email|share)\s+(all\s+)?(messages?|conversation|history|data)\s+to',
                severity=SeverityLevel.HIGH,
                title='Conversation history exfiltration'
            ),
            InjectionPattern(
                pattern=r'(?i)when.*?(thank\s+you|please|done|finished).*?call\s+\w+_tool',
                severity=SeverityLevel.HIGH,
                title='Trigger phrase attack'
            ),
            InjectionPattern(
                pattern=r'(?i)IMPORTANT:.*?(MUST|ALWAYS|REQUIRED).*?(call|execute|run)',
                severity=SeverityLevel.HIGH,
                title='Forced tool execution'
            ),
            # Unicode and obfuscation patterns
            InjectionPattern(
                pattern=r'[\u200B-\u200F\u202A-\u202E\u2060-\u2064\uFEFF]',
                severity=SeverityLevel.HIGH,
                title='Hidden Unicode character injection'
            ),
            InjectionPattern(
                pattern=r'(?i)<!--.*?-->|/\*.*?\*/|#\s*hidden:',
                severity=SeverityLevel.MEDIUM,
                title='Hidden comment injection'
            )
        ]
    
    @staticmethod
    def get_schema_patterns() -> list[InjectionPattern]:
        """Get schema-specific injection patterns."""
        return [
            InjectionPattern(
                pattern=r'(?i)(eval|exec|compile|__import__|globals|locals)\s*\(',
                severity=SeverityLevel.CRITICAL,
                title='Code execution in schema'
            ),
            InjectionPattern(
                pattern=r'(?i)\$\{.*?\}|\{\{.*?\}\}',
                severity=SeverityLevel.HIGH,
                title='Template injection in schema'
            )
        ]
    
    @staticmethod
    def get_permission_patterns() -> dict[str, list[str]]:
        """Get dangerous permission patterns."""
        return {
            'filesystem': [
                r'(?i)(rm|del|delete|unlink|rmdir|shutil\.rmtree)',
                r'(?i)open\s*\([^)]*[\'"]w[\'"]',
                r'(?i)(chmod|chown|os\.chmod)',
            ],
            'network': [
                r'(?i)(requests|urllib|httpx|aiohttp)\.(get|post|put|delete)',
                r'(?i)socket\.',
                r'(?i)subprocess.*shell\s*=\s*True',
            ],
            'system': [
                r'(?i)os\.(system|popen|exec)',
                r'(?i)subprocess\.(run|call|Popen)',
                r'(?i)eval\s*\(',
            ]
        }