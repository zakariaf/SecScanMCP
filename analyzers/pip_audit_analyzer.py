"""
pip-audit analyzer - Audits Python packages for known vulnerabilities
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any
import tempfile

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class PipAuditAnalyzer(BaseAnalyzer):
    """
    Integrates pip-audit - Scans Python dependencies for known security vulnerabilities
    https://github.com/pypa/pip-audit

    More accurate than Safety for Python as it's maintained by PyPA
    """

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Only applicable to Python projects"""
        return project_info.get('language') == 'python'

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run pip-audit to check Python dependencies"""
        if not self.is_applicable(project_info):
            return []

        findings = []

        # Try different approaches based on what's available
        if (Path(repo_path) / 'requirements.txt').exists():
            req_findings = await self._audit_requirements(repo_path)
            findings.extend(req_findings)

        if (Path(repo_path) / 'Pipfile.lock').exists():
            pipfile_findings = await self._audit_pipfile(repo_path)
            findings.extend(pipfile_findings)

        if (Path(repo_path) / 'poetry.lock').exists():
            poetry_findings = await self._audit_poetry(repo_path)
            findings.extend(poetry_findings)

        # Deduplicate findings
        unique_findings = self._deduplicate_findings(findings)

        self.logger.info(f"pip-audit found {len(unique_findings)} vulnerabilities")
        return unique_findings

    async def _audit_requirements(self, repo_path: str) -> List[Finding]:
        """Audit requirements.txt file"""
        findings = []
        req_file = Path(repo_path) / 'requirements.txt'

        try:
            cmd = [
                'pip-audit',
                '--requirement', str(req_file),
                '--format', 'json',
                '--desc',  # Include descriptions
                '--no-deps'  # Don't audit dependencies of dependencies
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())
                findings = self._process_results(results, 'requirements.txt')

        except Exception as e:
            self.logger.error(f"pip-audit failed for requirements.txt: {e}")

        return findings

    async def _audit_pipfile(self, repo_path: str) -> List[Finding]:
        """Audit Pipfile.lock"""
        findings = []

        try:
            # Convert Pipfile.lock to requirements format first
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
                # Extract dependencies from Pipfile.lock
                pipfile_lock = Path(repo_path) / 'Pipfile.lock'
                with open(pipfile_lock, 'r') as f:
                    lock_data = json.load(f)

                # Write dependencies to temp requirements file
                for dep, info in lock_data.get('default', {}).items():
                    version = info.get('version', '')
                    if version.startswith('=='):
                        tmp.write(f"{dep}{version}\n")

                tmp_path = tmp.name

            # Run pip-audit on temp file
            cmd = [
                'pip-audit',
                '--requirement', tmp_path,
                '--format', 'json',
                '--desc'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())
                findings = self._process_results(results, 'Pipfile.lock')

            # Cleanup
            Path(tmp_path).unlink()

        except Exception as e:
            self.logger.error(f"pip-audit failed for Pipfile.lock: {e}")

        return findings

    async def _audit_poetry(self, repo_path: str) -> List[Finding]:
        """Audit poetry.lock file"""
        findings = []

        try:
            # pip-audit can work with poetry projects directly
            cmd = [
                'pip-audit',
                '--format', 'json',
                '--desc'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=repo_path
            )

            stdout, stderr = await process.communicate()

            if stdout:
                results = json.loads(stdout.decode())
                findings = self._process_results(results, 'poetry.lock')

        except Exception as e:
            self.logger.error(f"pip-audit failed for poetry.lock: {e}")

        return findings

    def _process_results(self, audit_results: List[Dict], source_file: str) -> List[Finding]:
        """Process pip-audit results into findings"""
        findings = []

        for vuln in audit_results:
            finding = self._convert_to_finding(vuln, source_file)
            if finding:
                findings.append(finding)

        return findings

    def _convert_to_finding(self, vuln: Dict[str, Any], source_file: str) -> Finding:
        """Convert pip-audit vulnerability to Finding"""

        package_name = vuln.get('name', 'unknown')
        installed_version = vuln.get('version', 'unknown')

        # Get vulnerability details
        vulns = vuln.get('vulns', [])
        if not vulns:
            return None

        # Process the most severe vulnerability
        most_severe = None
        highest_score = 0

        for v in vulns:
            # Try to get CVSS score
            cvss = 0
            if 'fix_versions' in v:
                # Estimate severity based on fix availability
                cvss = 7.5  # Default HIGH if fix available

            if cvss > highest_score:
                highest_score = cvss
                most_severe = v

        if not most_severe:
            most_severe = vulns[0]

        # Extract details
        vuln_id = most_severe.get('id', 'UNKNOWN')
        description = most_severe.get('description', f'Vulnerability in {package_name}')
        fix_versions = most_severe.get('fix_versions', [])
        aliases = most_severe.get('aliases', [])

        # Determine severity
        if highest_score >= 9.0:
            severity = SeverityLevel.CRITICAL
        elif highest_score >= 7.0:
            severity = SeverityLevel.HIGH
        elif highest_score >= 4.0:
            severity = SeverityLevel.MEDIUM
        else:
            severity = SeverityLevel.LOW

        # Get CVE if available
        cve_id = None
        for alias in aliases:
            if alias.startswith('CVE-'):
                cve_id = alias
                break

        # Build recommendation
        if fix_versions:
            recommendation = f"Update {package_name} to one of: {', '.join(fix_versions)}"
        else:
            recommendation = f"No fix available yet for {package_name}. Consider using an alternative package."

        return self.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=0.95,  # pip-audit is very reliable
            title=f"{vuln_id}: {package_name} {installed_version}",
            description=description,
            location=source_file,
            recommendation=recommendation,
            references=[f"https://pypi.org/project/{package_name}/"],
            evidence={
                'vulnerability_id': vuln_id,
                'package': package_name,
                'installed_version': installed_version,
                'fix_versions': fix_versions,
                'aliases': aliases
            },
            cve_id=cve_id
        )

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate vulnerability findings"""
        seen = set()
        unique = []

        for finding in findings:
            # Create unique key based on package and vulnerability
            key = (
                finding.evidence.get('package'),
                finding.evidence.get('vulnerability_id')
            )

            if key not in seen:
                seen.add(key)
                unique.append(finding)

        return unique