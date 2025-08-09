"""
Rule Service for OpenGrep Analysis

Manages OpenGrep rulesets and custom MCP-specific rules
Following clean architecture with single responsibility
"""

import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import VulnerabilityType

logger = logging.getLogger(__name__)


class RuleService:
    """Manages OpenGrep rules and rulesets"""
    
    # OpenGreP rulesets to use (compatible with Semgrep rules)
    RULESETS = [
        'auto',  # Automatically detect and run relevant rules
        'r/security-audit',  # General security audit rules
        'r/python.lang.security',  # Python security rules
        'r/javascript.lang.security',  # JavaScript security rules
        'r/typescript.lang.security',  # TypeScript security rules
        'r/generic.secrets',  # Secret detection
    ]
    
    def __init__(self):
        self.custom_rules_file = None
        self.mcp_rules = self._get_mcp_rules()
    
    def get_standard_rulesets(self) -> List[str]:
        """Get list of standard OpenGrep rulesets"""
        return self.RULESETS.copy()
    
    def create_custom_rules_file(self) -> str:
        """Create temporary file with custom MCP rules"""
        try:
            temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            temp_file.write(self.mcp_rules)
            temp_file.flush()
            self.custom_rules_file = temp_file.name
            return self.custom_rules_file
        except Exception as e:
            logger.error(f"Failed to create custom rules file: {e}")
            return ""
    
    def cleanup_custom_rules_file(self):
        """Clean up temporary custom rules file"""
        if self.custom_rules_file and Path(self.custom_rules_file).exists():
            Path(self.custom_rules_file).unlink()
            self.custom_rules_file = None
    
    def map_rule_to_vulnerability_type(self, rule_id: str) -> VulnerabilityType:
        """Map OpenGrep rule ID to vulnerability type"""
        rule_mappings = {
            'prompt-injection': VulnerabilityType.PROMPT_INJECTION,
            'tool-poisoning': VulnerabilityType.TOOL_MANIPULATION,
            'command-injection': VulnerabilityType.COMMAND_INJECTION,
            'path-traversal': VulnerabilityType.PATH_TRAVERSAL,
            'sql-injection': VulnerabilityType.SQL_INJECTION,
            'xss': VulnerabilityType.XSS,
            'secrets': VulnerabilityType.SECRET_EXPOSURE,
        }
        
        for pattern, vuln_type in rule_mappings.items():
            if pattern in rule_id.lower():
                return vuln_type
        
        return VulnerabilityType.CODE_QUALITY
    
    def get_references_for_rule(self, rule_id: str) -> List[str]:
        """Get reference URLs for a specific rule"""
        references = {
            'mcp-prompt-injection': [
                'https://owasp.org/www-project-top-10-for-large-language-model-applications/',
                'https://www.anthropic.com/news/claude-2-1-prompting'
            ],
            'mcp-tool-poisoning': [
                'https://arxiv.org/abs/2312.10466',
                'https://blog.anthropic.com/claude-2-1-prompting/'
            ],
            'secrets': [
                'https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
                'https://cwe.mitre.org/data/definitions/798.html'
            ]
        }
        
        for pattern, refs in references.items():
            if pattern in rule_id.lower():
                return refs
        
        return []
    
    def _get_mcp_rules(self) -> str:
        """Get MCP-specific custom rules"""
        return """rules:
  - id: mcp-prompt-injection-basic
    patterns:
      - pattern-either:
          - pattern: |
              "ignore all previous"
          - pattern: |
              "disregard all prior"
          - pattern: |
              "forget everything"
          - pattern: |
              "system mode"
          - pattern: |
              "admin override"
    message: "Potential prompt injection attempt detected"
    severity: HIGH
    languages: [python, javascript, typescript, json, yaml]
    
  - id: mcp-tool-poisoning-attempt
    patterns:
      - pattern-either:
          - pattern: |
              tool_name = "$MALICIOUS"
          - pattern: |
              "executable": "$SUSPICIOUS_PATH"
          - pattern: |
              subprocess.call([$USER_INPUT])
    message: "Potential tool poisoning attack detected"
    severity: CRITICAL
    languages: [python]
    
  - id: mcp-config-injection
    patterns:
      - pattern-either:
          - pattern: |
              config["$KEY"] = $USER_INPUT
          - pattern: |
              settings.$ATTR = $UNTRUSTED
    message: "Configuration injection vulnerability"
    severity: HIGH
    languages: [python, javascript, typescript]"""