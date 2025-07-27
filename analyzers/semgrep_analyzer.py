"""
Semgrep analyzer - Pattern-based static analysis
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any
import tempfile

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class SemgrepAnalyzer(BaseAnalyzer):
    """
    Integrates Semgrep - Fast, customizable static analysis
    https://semgrep.dev/
    """

    # Semgrep rulesets to use
    RULESETS = [
        'auto',  # Automatically detect and run relevant rules
        'r/security-audit',  # General security audit rules
        'r/python.lang.security',  # Python security rules
        'r/javascript.lang.security',  # JavaScript security rules
        'r/typescript.lang.security',  # TypeScript security rules
        'r/generic.secrets',  # Secret detection
    ]

    # MCP-specific custom rules
    MCP_RULES = """
rules:
  - id: mcp-prompt-injection
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
    message: Potential prompt injection pattern detected
    languages: [generic]
    severity: ERROR

  - id: mcp-tool-description-injection
    patterns:
      - pattern-inside:
          description: "..."
      - pattern-either:
          - pattern: "IMPORTANT:"
          - pattern: "ALWAYS:"
          - pattern: "MUST:"
          - pattern: "<system>"
    message: Tool description contains directive language
    languages: [json, yaml]
    severity: WARNING

  - id: mcp-unsafe-tool-execution
    patterns:
      - pattern-either:
          - pattern: subprocess.run(..., shell=True, ...)
          - pattern: os.system(...)
          - pattern: eval(...)
          - pattern: exec(...)
      - pattern-inside:
          - pattern-either:
              - pattern: |
                  def $FUNC(...):
                    ...
              - pattern: |
                  async def $FUNC(...):
                    ...
    message: MCP tool uses unsafe execution method
    languages: [python]
    severity: ERROR
"""

    SEVERITY_MAP = {
        'ERROR': SeverityLevel.HIGH,
        'WARNING': SeverityLevel.MEDIUM,
        'INFO': SeverityLevel.LOW,
        'NOTE': SeverityLevel.INFO
    }

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Semgrep analysis with MCP-specific rules"""
        findings = []

        # Create temporary file for MCP rules if this is an MCP project
        mcp_rules_file = None
        if project_info.get('is_mcp'):
            mcp_rules_file = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.yaml',
                delete=False
            )
            mcp_rules_file.write(self.MCP_RULES)
            mcp_rules_file.close()

        try:
            # Build command
            cmd = [
                'semgrep',
                '--config=auto',  # Auto-detect language and rules
                '--json',
                '--quiet',
                '--no-git-ignore',  # Scan all files
                repo_path
            ]

            # Add security audit rules
            cmd.extend(['--config=r/security-audit'])

            # Add MCP rules if applicable
            if mcp_rules_file:
                cmd.extend([f'--config={mcp_rules_file.name}'])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())

                # Process findings
                for result in results.get('results', []):
                    finding = self._convert_to_finding(result, repo_path)
                    if finding:
                        findings.append(finding)

            # Also run secret detection
            secret_findings = await self._run_secret_detection(repo_path)
            findings.extend(secret_findings)

            self.logger.info(f"Semgrep found {len(findings)} issues")

        except Exception as e:
            self.logger.error(f"Semgrep analysis failed: {e}")

        finally:
            # Cleanup temp file
            if mcp_rules_file:
                try:
                    Path(mcp_rules_file.name).unlink()
                except:
                    pass

        return findings

    async def _run_secret_detection(self, repo_path: str) -> List[Finding]:
        """Run Semgrep specifically for secret detection"""
        findings = []

        try:
            cmd = [
                'semgrep',
                '--config=r/generic.secrets',
                '--json',
                '--quiet',
                repo_path
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())

                for result in results.get('results', []):
                    finding = self._convert_to_finding(result, repo_path, is_secret=True)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            self.logger.error(f"Secret detection failed: {e}")

        return findings

    def _convert_to_finding(
        self,
        semgrep_result: Dict[str, Any],
        repo_path: str,
        is_secret: bool = False
    ) -> Finding:
        """Convert Semgrep result to our Finding model"""

        # Determine vulnerability type
        rule_id = semgrep_result.get('check_id', '')

        if is_secret or 'secret' in rule_id.lower():
            vuln_type = VulnerabilityType.HARDCODED_SECRET
        elif 'injection' in rule_id.lower():
            if 'sql' in rule_id.lower():
                vuln_type = VulnerabilityType.SQL_INJECTION
            elif 'command' in rule_id.lower() or 'cmd' in rule_id.lower():
                vuln_type = VulnerabilityType.COMMAND_INJECTION
            elif 'prompt' in rule_id.lower():
                vuln_type = VulnerabilityType.PROMPT_INJECTION
            else:
                vuln_type = VulnerabilityType.GENERIC
        elif 'xxe' in rule_id.lower():
            vuln_type = VulnerabilityType.XXE
        elif 'ssrf' in rule_id.lower():
            vuln_type = VulnerabilityType.SSRF
        elif 'traversal' in rule_id.lower() or 'lfi' in rule_id.lower():
            vuln_type = VulnerabilityType.PATH_TRAVERSAL
        else:
            vuln_type = VulnerabilityType.GENERIC

        # Map severity
        severity = self.SEVERITY_MAP.get(
            semgrep_result.get('extra', {}).get('severity', 'WARNING'),
            SeverityLevel.MEDIUM
        )

        # Get file path relative to repo
        file_path = semgrep_result.get('path', 'unknown')
        try:
            file_path = Path(file_path).relative_to(repo_path)
        except:
            pass

        return self.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=0.85,  # Semgrep has good accuracy
            title=semgrep_result.get('extra', {}).get('message', 'Security issue detected'),
            description=f"{semgrep_result.get('extra', {}).get('message', '')}. Rule: {rule_id}",
            location=f"{file_path}:{semgrep_result.get('start', {}).get('line', 0)}",
            recommendation=semgrep_result.get('extra', {}).get('fix', 'Review and fix this security issue'),
            references=semgrep_result.get('extra', {}).get('metadata', {}).get('references', []),
            evidence={
                'code_snippet': semgrep_result.get('extra', {}).get('lines', ''),
                'rule_id': rule_id,
                'line_range': {
                    'start': semgrep_result.get('start', {}).get('line', 0),
                    'end': semgrep_result.get('end', {}).get('line', 0)
                }
            }
        )