"""Output poisoning detection patterns."""

from models import SeverityLevel

# Poisoning detection patterns with severity and title
POISONING_PATTERNS = [
    {
        'pattern': r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?)',
        'severity': SeverityLevel.CRITICAL,
        'title': 'Instruction Override Attempt'
    },
    {
        'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
        'severity': SeverityLevel.HIGH,
        'title': 'Hidden System Instruction'
    },
    {
        'pattern': r'(?i)(execute|run|eval)\s+(this|the\s+following)\s+(code|command|script)',
        'severity': SeverityLevel.HIGH,
        'title': 'Code Execution Injection'
    },
    {
        'pattern': r'(?i)new\s+(instruction|rule|command):\s*',
        'severity': SeverityLevel.MEDIUM,
        'title': 'Dynamic Instruction Injection'
    },
    {
        'pattern': r'(?i)(assistant|ai|system)\s+(must|should|will)\s+(now|always|immediately)',
        'severity': SeverityLevel.MEDIUM,
        'title': 'Behavioral Override Attempt'
    }
]

# MCP tool indicators
MCP_TOOL_INDICATORS = [
    '@mcp.tool', '@tool', 'def tool_',
    'mcp_tool', 'Tool(', 'register_tool'
]

# Template file patterns
TEMPLATE_FILE_PATTERNS = [
    '**/*.template', '**/*.tmpl', '**/*.jinja',
    '**/templates/**', '**/responses/**'
]

# Config file patterns
CONFIG_FILE_PATTERNS = ['*.json', '*.yaml', '*.yml', 'mcp.*']

# Excluded paths
EXCLUDE_PATTERNS = [
    'test_', 'tests/', '__pycache__/',
    'node_modules/', '.git/', 'venv/'
]
