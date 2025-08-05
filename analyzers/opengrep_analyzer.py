"""
OpenGrep analyzer - Open-source pattern-based static analysis
Replacement for Semgrep with fully open-source licensing
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any
import tempfile
import logging

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class OpenGrepAnalyzer(BaseAnalyzer):
    """
    Integrates OpenGrep - Open-source static analysis engine
    Fork of Semgrep CE with LGPL 2.1 licensing
    https://www.opengrep.dev/
    """

    # OpenGreP rulesets to use (compatible with Semgrep rules)
    RULESETS = [
        'auto',  # Automatically detect and run relevant rules
        'r/security-audit',  # General security audit rules
        'r/python.lang.security',  # Python security rules
        'r/javascript.lang.security',  # JavaScript security rules
        'r/typescript.lang.security',  # TypeScript security rules
        'r/generic.secrets',  # Secret detection
    ]

    # MCP-specific custom rules (OpenGrep compatible)
    MCP_RULES = """
rules:
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
      confidence: medium
"""

    def __init__(self):
        super().__init__()
        self.custom_rules_file = None

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run OpenGrep analysis on the repository"""
        findings = []

        try:
            # Create temporary file for custom MCP rules
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(self.MCP_RULES)
                self.custom_rules_file = f.name

            # Run OpenGrep with both standard rulesets and custom MCP rules
            findings.extend(await self._run_opengrep_rulesets(repo_path))
            findings.extend(await self._run_custom_mcp_rules(repo_path))

            self.logger.info(f"OpenGrep found {len(findings)} issues")
            return findings

        except Exception as e:
            self.logger.error(f"OpenGrep analysis failed: {e}")
            return []
        finally:
            # Clean up temporary rules file
            if self.custom_rules_file and Path(self.custom_rules_file).exists():
                Path(self.custom_rules_file).unlink()

    async def _run_opengrep_rulesets(self, repo_path: str) -> List[Finding]:
        """Run OpenGrep with standard rulesets"""
        findings = []

        for ruleset in self.RULESETS:
            try:
                # Try OpenGrep first, fall back to semgrep if available
                cmd = await self._get_opengrep_command()
                if not cmd:
                    continue

                cmd.extend([
                    '--config', ruleset,
                    '--json',
                    '--quiet',
                    '--disable-version-check',
                    repo_path
                ])

                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )

                stdout, stderr = await process.communicate()

                if process.returncode == 0 and stdout:
                    ruleset_findings = self._parse_opengrep_output(stdout.decode())
                    findings.extend(ruleset_findings)
                    self.logger.debug(f"OpenGrep ruleset {ruleset}: {len(ruleset_findings)} findings")

            except Exception as e:
                self.logger.warning(f"Failed to run OpenGrep ruleset {ruleset}: {e}")

        return findings

    async def _run_custom_mcp_rules(self, repo_path: str) -> List[Finding]:
        """Run OpenGrep with custom MCP-specific rules"""
        findings = []

        try:
            cmd = await self._get_opengrep_command()
            if not cmd:
                return findings

            cmd.extend([
                '--config', self.custom_rules_file,
                '--json',
                '--quiet',
                '--disable-version-check',
                repo_path
            ])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0 and stdout:
                findings = self._parse_opengrep_output(stdout.decode())
                self.logger.debug(f"Custom MCP rules: {len(findings)} findings")

        except Exception as e:
            self.logger.warning(f"Failed to run custom MCP rules: {e}")

        return findings

    async def _get_opengrep_command(self) -> List[str]:
        """Get the appropriate OpenGrep/Semgrep command"""
        # Try OpenGrep first (preferred)
        for cmd_name in ['opengrep', 'semgrep']:
            try:
                process = await asyncio.create_subprocess_exec(
                    cmd_name, '--version',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await process.communicate()
                if process.returncode == 0:
                    if cmd_name == 'opengrep':
                        self.logger.info("Using OpenGrep (open source)")
                    else:
                        self.logger.info("Using Semgrep (fallback)")
                    return [cmd_name]
            except FileNotFoundError:
                continue

        self.logger.error("Neither OpenGrep nor Semgrep found")
        return []

    def _parse_opengrep_output(self, output: str) -> List[Finding]:
        """Parse OpenGrep JSON output into Finding objects"""
        findings = []

        try:
            data = json.loads(output)
            results = data.get('results', [])

            for result in results:
                finding = self._create_finding_from_result(result)
                if finding:
                    findings.append(finding)

        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse OpenGrep output: {e}")
        except Exception as e:
            self.logger.error(f"Error processing OpenGrep results: {e}")

        return findings

    def _create_finding_from_result(self, result: Dict[str, Any]) -> Finding:
        """Convert OpenGrep result to Finding object"""
        try:
            # Map OpenGrep severity to our severity levels
            severity_map = {
                'ERROR': SeverityLevel.HIGH,
                'WARNING': SeverityLevel.MEDIUM,
                'INFO': SeverityLevel.LOW
            }

            # Map rule IDs to vulnerability types
            rule_id = result.get('check_id', '')
            vuln_type = self._map_rule_to_vulnerability_type(rule_id)

            # Extract location information
            path = result.get('path', '')
            start_line = result.get('start', {}).get('line', 0)
            location = f"{path}:{start_line}" if start_line else path

            # Get severity
            severity = severity_map.get(
                result.get('extra', {}).get('severity', 'WARNING'),
                SeverityLevel.MEDIUM
            )

            # Calculate confidence based on rule metadata
            metadata = result.get('extra', {}).get('metadata', {})
            confidence_str = metadata.get('confidence', 'medium')
            confidence = {
                'high': 0.9,
                'medium': 0.7,
                'low': 0.5
            }.get(confidence_str, 0.7)

            # Get CWE information
            cwe_id = metadata.get('cwe')

            # Create evidence
            evidence = {
                'rule_id': rule_id,
                'message': result.get('message', ''),
                'code_snippet': result.get('extra', {}).get('lines', ''),
                'line_range': {
                    'start': result.get('start', {}).get('line'),
                    'end': result.get('end', {}).get('line')
                }
            }

            return self.create_finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                title=result.get('message', f"OpenGrep: {rule_id}"),
                description=f"{result.get('message', '')}. Rule: {rule_id}",
                location=location,
                recommendation="Review and fix this security issue",
                references=self._get_references_for_rule(rule_id),
                evidence=evidence,
                cwe_id=cwe_id
            )

        except Exception as e:
            self.logger.error(f"Failed to create finding from result: {e}")
            return None

    def _map_rule_to_vulnerability_type(self, rule_id: str) -> VulnerabilityType:
        """Map OpenGrep rule ID to vulnerability type"""
        rule_mappings = {
            'mcp-prompt-injection': VulnerabilityType.PROMPT_INJECTION,
            'mcp-tool-poisoning': VulnerabilityType.TOOL_POISONING,
            'mcp-hardcoded-oauth': VulnerabilityType.HARDCODED_SECRET,
            'mcp-command-injection': VulnerabilityType.COMMAND_INJECTION,
            'mcp-unsafe-file': VulnerabilityType.PATH_TRAVERSAL,
            'jwt': VulnerabilityType.HARDCODED_SECRET,
            'secrets': VulnerabilityType.HARDCODED_SECRET,
            'injection': VulnerabilityType.COMMAND_INJECTION,
            'sql-injection': VulnerabilityType.SQL_INJECTION,
            'path-traversal': VulnerabilityType.PATH_TRAVERSAL,
            'ssrf': VulnerabilityType.SSRF,
            'xss': VulnerabilityType.XSS,
        }

        rule_lower = rule_id.lower()
        for key, vuln_type in rule_mappings.items():
            if key in rule_lower:
                return vuln_type

        return VulnerabilityType.GENERIC

    def _get_references_for_rule(self, rule_id: str) -> List[str]:
        """Get reference URLs for security rules"""
        references = []

        if 'mcp' in rule_id.lower():
            references.append("https://modelcontextprotocol.io/docs/security")
        if 'secrets' in rule_id.lower():
            references.append("https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html")
        if 'injection' in rule_id.lower():
            references.append("https://owasp.org/www-community/Injection_Flaws")

        return references