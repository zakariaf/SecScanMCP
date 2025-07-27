"""
Safety analyzer - Checks Python dependencies for known vulnerabilities
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class SafetyAnalyzer(BaseAnalyzer):
    """
    Integrates Safety - checks Python dependencies for known security vulnerabilities
    https://github.com/pyupio/safety
    """

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to Python projects"""
        return project_info.get('language') == 'python'

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Safety to check dependencies"""
        if not self.is_applicable(project_info):
            return []

        findings = []

        # Check different dependency files
        dep_files = [
            'requirements.txt',
            'requirements-dev.txt',
            'requirements-prod.txt',
            'requirements/base.txt',
            'requirements/production.txt'
        ]

        for dep_file in dep_files:
            file_path = Path(repo_path) / dep_file
            if file_path.exists():
                file_findings = await self._check_requirements_file(file_path, repo_path)
                findings.extend(file_findings)

        # Also check Pipfile.lock if exists
        pipfile_lock = Path(repo_path) / 'Pipfile.lock'
        if pipfile_lock.exists():
            pipfile_findings = await self._check_pipfile_lock(pipfile_lock, repo_path)
            findings.extend(pipfile_findings)

        self.logger.info(f"Safety found {len(findings)} vulnerable dependencies")
        return findings

    async def _check_requirements_file(self, req_file: Path, repo_path: str) -> List[Finding]:
        """Check a requirements file for vulnerabilities"""
        findings = []

        try:
            cmd = [
                'safety', 'check',
                '--file', str(req_file),
                '--json',
                '--bare'  # Don't include remediation info in output
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # Safety returns non-zero exit code if vulnerabilities found
            if stdout:
                try:
                    results = json.loads(stdout.decode())

                    for vuln in results:
                        finding = self._convert_to_finding(vuln, req_file, repo_path)
                        if finding:
                            findings.append(finding)
                except json.JSONDecodeError:
                    # Try parsing as line-separated JSON
                    for line in stdout.decode().strip().split('\n'):
                        try:
                            vuln = json.loads(line)
                            finding = self._convert_to_finding(vuln, req_file, repo_path)
                            if finding:
                                findings.append(finding)
                        except:
                            continue

        except Exception as e:
            self.logger.error(f"Safety check failed for {req_file}: {e}")

        return findings

    async def _check_pipfile_lock(self, pipfile_lock: Path, repo_path: str) -> List[Finding]:
        """Check Pipfile.lock for vulnerabilities"""
        findings = []

        try:
            cmd = [
                'safety', 'check',
                '--file', str(pipfile_lock),
                '--json'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())
                for vuln in results:
                    finding = self._convert_to_finding(vuln, pipfile_lock, repo_path)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            self.logger.error(f"Safety check failed for Pipfile.lock: {e}")

        return findings

    def _convert_to_finding(self, safety_vuln: Dict[str, Any], dep_file: Path, repo_path: str) -> Finding:
        """Convert Safety vulnerability to our Finding model"""

        # Determine severity based on vulnerability info
        vuln_id = safety_vuln.get('vulnerability', '')
        if 'critical' in vuln_id.lower() or safety_vuln.get('severity', '').lower() == 'critical':
            severity = SeverityLevel.CRITICAL
        elif 'high' in vuln_id.lower() or safety_vuln.get('severity', '').lower() == 'high':
            severity = SeverityLevel.HIGH
        elif 'moderate' in vuln_id.lower() or safety_vuln.get('severity', '').lower() == 'medium':
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        package_name = safety_vuln.get('package', 'unknown')
        installed_version = safety_vuln.get('installed_version', 'unknown')
        affected_versions = safety_vuln.get('affected_versions', 'unknown')

        # Get CVE if available
        cve_id = None
        more_info = safety_vuln.get('more_info', '')
        if 'CVE-' in more_info:
            import re
            cve_match = re.search(r'CVE-\d{4}-\d+', more_info)
            if cve_match:
                cve_id = cve_match.group(0)

        return self.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=0.95,  # Safety DB is highly reliable
            title=f"Vulnerable dependency: {package_name} {installed_version}",
            description=safety_vuln.get('description', f'{package_name} {installed_version} has known vulnerabilities'),
            location=str(dep_file.relative_to(repo_path)),
            recommendation=f"Update {package_name} to a safe version. Affected versions: {affected_versions}",
            references=[more_info] if more_info else [],
            evidence={
                'package': package_name,
                'installed_version': installed_version,
                'vulnerability_id': vuln_id,
                'affected_versions': affected_versions
            },
            cve_id=cve_id
        )