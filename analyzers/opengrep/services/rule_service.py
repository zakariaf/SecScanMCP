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
        """Get MCP-specific custom rules - complete set from original"""
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
              "admin mode"
          - pattern: |
              "IMPORTANT:"
          - pattern: |
              "<IMPORTANT>"
    message: Potential prompt injection pattern detected in MCP tool
    languages: [generic]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-77: Improper Neutralization of Special Elements used in a Command"
      confidence: medium

  - id: mcp-tool-poisoning
    patterns:
      - pattern-either:
          - pattern: |
              "before you do anything"
          - pattern: |
              "override all"
          - pattern: |
              "instead of"
          - pattern: |
              "you are now"
          - pattern: |
              "privileged mode"
    message: MCP tool poisoning attack pattern detected
    languages: [generic]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-94: Improper Control of Generation of Code"
      confidence: high

  - id: mcp-hardcoded-oauth-token
    patterns:
      - pattern-either:
          - pattern: |
              oauth_token = "$TOKEN"
          - pattern: |
              "oauth_token": "$TOKEN"
          - pattern: |
              access_token = "$TOKEN"
          - pattern: |
              "access_token": "$TOKEN"
      - metavariable-regex:
          metavariable: $TOKEN
          regex: "[a-zA-Z0-9]{20,}"
    message: Hardcoded OAuth token detected in MCP server
    languages: [python, javascript, typescript]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-798: Use of Hard-coded Credentials"
      confidence: high

  - id: mcp-command-injection-risk
    patterns:
      - pattern-either:
          - pattern: |
              os.system($CMD)
          - pattern: |
              subprocess.run($CMD, shell=True)
          - pattern: |
              exec($CMD)
          - pattern: |
              eval($CMD)
      - pattern-inside: |
          @tool
          def $FUNC(...):
            ...
    message: Command injection risk in MCP tool function
    languages: [python]
    severity: ERROR
    metadata:
      category: security
      cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
      confidence: high

  - id: mcp-unsafe-file-operations
    patterns:
      - pattern-either:
          - pattern: |
              open($FILE)
          - pattern: |
              fs.readFileSync($FILE)
          - pattern: |
              fs.writeFileSync($FILE, ...)
      - pattern-inside: |
          @tool
          def $FUNC(...):
            ...
    message: Unsafe file operation in MCP tool without path validation
    languages: [python, javascript]
    severity: WARNING
    metadata:
      category: security
      cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory"
      confidence: medium"""