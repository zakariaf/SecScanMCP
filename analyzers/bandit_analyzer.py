"""
Bandit analyzer - Security linter for Python code
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class BanditAnalyzer(BaseAnalyzer):
    """
    Integrates Bandit - AST-based security linter for Python
    https://github.com/PyCQA/bandit
    """

    # Map Bandit severity to our severity levels
    SEVERITY_MAP = {
        'HIGH': SeverityLevel.HIGH,
        'MEDIUM': SeverityLevel.MEDIUM,
        'LOW': SeverityLevel.LOW
    }

    # Map Bandit test IDs to vulnerability types
    VULN_TYPE_MAP = {
        'B201': VulnerabilityType.COMMAND_INJECTION,  # flask_debug
        'B301': VulnerabilityType.INSECURE_CONFIGURATION,  # pickle
        'B302': VulnerabilityType.INSECURE_CONFIGURATION,  # marshal
        'B303': VulnerabilityType.INSECURE_CONFIGURATION,  # md5
        'B304': VulnerabilityType.INSECURE_CONFIGURATION,  # des
        'B305': VulnerabilityType.INSECURE_CONFIGURATION,  # cipher
        'B306': VulnerabilityType.INSECURE_CONFIGURATION,  # mktemp
        'B307': VulnerabilityType.COMMAND_INJECTION,  # eval
        'B308': VulnerabilityType.INSECURE_CONFIGURATION,  # mark_safe
        'B309': VulnerabilityType.INSECURE_CONFIGURATION,  # httpsconnection
        'B310': VulnerabilityType.PATH_TRAVERSAL,  # urllib_urlopen
        'B311': VulnerabilityType.INSECURE_CONFIGURATION,  # random
        'B312': VulnerabilityType.INSECURE_CONFIGURATION,  # telnetlib
        'B313': VulnerabilityType.XXE,  # xml_bad_cElementTree
        'B314': VulnerabilityType.XXE,  # xml_bad_ElementTree
        'B315': VulnerabilityType.XXE,  # xml_bad_expatreader
        'B316': VulnerabilityType.XXE,  # xml_bad_expatbuilder
        'B317': VulnerabilityType.XXE,  # xml_bad_sax
        'B318': VulnerabilityType.XXE,  # xml_bad_minidom
        'B319': VulnerabilityType.XXE,  # xml_bad_pulldom
        'B320': VulnerabilityType.XXE,  # xml_bad_etree
        'B321': VulnerabilityType.INSECURE_CONFIGURATION,  # ftplib
        'B322': VulnerabilityType.COMMAND_INJECTION,  # input
        'B323': VulnerabilityType.INSECURE_CONFIGURATION,  # unverified_context
        'B324': VulnerabilityType.INSECURE_CONFIGURATION,  # hashlib_new_insecure_functions
        'B325': VulnerabilityType.INSECURE_CONFIGURATION,  # tempnam
        'B601': VulnerabilityType.COMMAND_INJECTION,  # paramiko_calls
        'B602': VulnerabilityType.COMMAND_INJECTION,  # subprocess_popen_with_shell_equals_true
        'B603': VulnerabilityType.COMMAND_INJECTION,  # subprocess_without_shell_equals_true
        'B604': VulnerabilityType.COMMAND_INJECTION,  # any_other_function_with_shell_equals_true
        'B605': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_a_shell
        'B606': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_no_shell
        'B607': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_partial_path
        'B608': VulnerabilityType.SQL_INJECTION,  # hardcoded_sql_expressions
        'B609': VulnerabilityType.COMMAND_INJECTION,  # linux_commands_wildcard_injection
        'B610': VulnerabilityType.SQL_INJECTION,  # django_extra_used
        'B611': VulnerabilityType.SQL_INJECTION,  # django_rawsql_used
        'B701': VulnerabilityType.INSECURE_CONFIGURATION,  # jinja2_autoescape_false
        'B702': VulnerabilityType.INSECURE_CONFIGURATION,  # use_of_mako_templates
        'B703': VulnerabilityType.SQL_INJECTION,  # django_mark_safe
    }

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to Python projects"""
        return project_info.get('language') == 'python'

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Bandit security analysis"""
        if not self.is_applicable(project_info):
            return []

        findings = []

        try:
            # Log scan summary
            self.log_scan_summary(repo_path)
            
            # Create ignore file for Bandit
            ignore_file = self.create_ignore_file(repo_path)
            
            # Run bandit as Python module
            cmd = [
                'python3', '-m', 'bandit',
                '-r',  # Recursive
                repo_path,
                '-f', 'json',  # JSON output
                '-ll',  # Only medium and high severity
                '--quiet'
            ]
            
            # Add ignore patterns
            if ignore_file:
                cmd.extend(['--exclude', ignore_file])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Bandit returns non-zero if issues found, which is expected
            if stdout:
                results = json.loads(stdout.decode())

                # Process each finding
                for result in results.get('results', []):
                    finding = self._convert_to_finding(result)
                    if finding:
                        findings.append(finding)

            self.logger.info(f"Bandit found {len(findings)} issues")
            
            # Clean up ignore file
            if ignore_file and Path(ignore_file).exists():
                Path(ignore_file).unlink()

        except Exception as e:
            self.logger.error(f"Bandit analysis failed: {e}")

        return findings

    def _convert_to_finding(self, bandit_result: Dict[str, Any]) -> Finding:
        """Convert Bandit result to our Finding model"""

        # Determine vulnerability type
        test_id = bandit_result.get('test_id', '')
        vuln_type = self.VULN_TYPE_MAP.get(test_id, VulnerabilityType.GENERIC)

        # Map severity
        severity = self.SEVERITY_MAP.get(
            bandit_result.get('issue_severity', 'MEDIUM'),
            SeverityLevel.MEDIUM
        )

        # Calculate confidence based on Bandit's confidence
        confidence_map = {'HIGH': 0.9, 'MEDIUM': 0.7, 'LOW': 0.5}
        confidence = confidence_map.get(
            bandit_result.get('issue_confidence', 'MEDIUM'),
            0.7
        )

        return self.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            title=f"{bandit_result.get('test_name', 'Unknown')} - {bandit_result.get('issue_text', '')}",
            description=bandit_result.get('issue_text', ''),
            location=f"{bandit_result.get('filename', 'unknown')}:{bandit_result.get('line_number', 0)}",
            recommendation=f"Review and fix the {bandit_result.get('test_name', 'security issue')}. {bandit_result.get('more_info', '')}",
            references=[bandit_result.get('more_info', '')] if bandit_result.get('more_info') else [],
            evidence={
                'code_snippet': bandit_result.get('code', ''),
                'test_id': test_id,
                'line_range': bandit_result.get('line_range', [])
            }
        )