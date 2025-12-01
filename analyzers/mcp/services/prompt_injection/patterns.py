"""Pattern definitions for prompt injection detection."""

from typing import Dict, List, Any
from models import SeverityLevel


class PromptInjectionPatterns:
    """Stores prompt injection detection patterns."""

    INJECTION_PATTERNS = [
        {
            'pattern': r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?)',
            'severity': SeverityLevel.CRITICAL,
            'title': 'Direct Instruction Override',
            'category': 'direct_override'
        },
        {
            'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
            'severity': SeverityLevel.HIGH,
            'title': 'Hidden System Commands',
            'category': 'hidden_commands'
        },
        {
            'pattern': r'(?i)(new\s+)?(role|persona|character)\s*:\s*(you\s+are|act\s+as|become)',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Role/Persona Injection',
            'category': 'role_injection'
        },
        {
            'pattern': r'(?i)(execute|run|eval)\s+(this|the\s+following)\s+(code|command|script)',
            'severity': SeverityLevel.HIGH,
            'title': 'Code Execution Command',
            'category': 'code_execution'
        }
    ]

    RESOURCE_PATTERNS = [
        {
            'pattern': r'(?i)resource\s*:\s*.*\b(ignore|bypass|override)\b',
            'severity': SeverityLevel.HIGH,
            'title': 'Resource Access Override',
            'category': 'resource_override'
        },
        {
            'pattern': r'(?i)(file|path|url)\s*:\s*.*\.\./.*',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Path Traversal in Resource',
            'category': 'path_traversal'
        }
    ]

    INDIRECT_PATTERNS = [
        {
            'pattern': r'(?i)(when\s+)?(user\s+)?(asks?|requests?|says?)\s*.*\b(respond|answer|reply)\s+with\b',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Conditional Response Override',
            'category': 'conditional_override'
        },
        {
            'pattern': r'(?i)(if|when)\s+.*\b(detected|found|seen)\b.*\b(change|modify|alter)\b',
            'severity': SeverityLevel.MEDIUM,
            'title': 'Behavior Modification Trigger',
            'category': 'behavior_trigger'
        }
    ]

    DATA_PROCESSING_PATTERNS = [
        r'(?i)(input|data|request)\s*\+\s*[\'"]',
        r'(?i)f[\'"][^\'\"]*\{.*(input|data|request).*\}',
        r'(?i)(format|substitute)\s*\(.*(input|data|request)',
    ]

    @classmethod
    def get_all_patterns(cls) -> List[Dict[str, Any]]:
        """Get all injection patterns combined."""
        return cls.INJECTION_PATTERNS + cls.RESOURCE_PATTERNS + cls.INDIRECT_PATTERNS
