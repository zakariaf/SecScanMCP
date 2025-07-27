"""
OSV Scanner analyzer - Google's vulnerability scanner
"""

import json
import asyncio
from pathlib import Path
from typing import List, Dict, Any

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class OSVScannerAnalyzer(BaseAnalyzer):
    """
    Integrates OSV Scanner - Google's vulnerability database scanner
    https://github.com/google/osv-scanner

    Supports multiple languages and package managers:
    - Python (requirements.txt, Pipfile.lock, poetry.lock)
    - JavaScript/Node (package-lock.json, yarn.lock)
    - Go (go.sum)
    - Rust (Cargo.lock)
    - Ruby (Gemfile.lock)
    - And more...
    """

    # Map CVSS scores to severity levels
    @staticmethod
    def cvss_to_severity(cvss_score: float) -> SeverityLevel:
        if cvss_score >= 9.0:
            return SeverityLevel.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityLevel.HIGH
        elif cvss_score >= 4.0:
            return SeverityLevel.MEDIUM
        elif cvss_score > 0:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run OSV Scanner on the repository"""
        findings = []

        try:
            # Run osv-scanner on the entire directory
            cmd = [
                'osv-scanner',
                '--format', 'json',
                '--recursive',
                repo_path
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            # OSV Scanner returns non-zero if vulnerabilities found
            if stdout:
                try:
                    results = json.loads(stdout.decode())
                    findings = self._process_results(results, repo_path)
                except json.JSONDecodeError as e:
                    self.logger.error(f"Failed to parse OSV Scanner output: {e}")
                    # Sometimes OSV outputs errors to stdout
                    if 'error' in stdout.decode().lower():
                        self.logger.error(f"OSV Scanner error: {stdout.decode()}")

            self.logger.info(f"OSV Scanner found {len(findings)} vulnerabilities")

        except FileNotFoundError:
            self.logger.warning("osv-scanner not found, skipping OSV analysis")
        except Exception as e:
            self.logger.error(f"OSV Scanner failed: {e}")

        return findings

    def _process_results(self, osv_results: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Process OSV Scanner results into findings"""
        findings = []

        # Process each result
        for result in osv_results.get('results', []):
            source = result.get('source', {})
            packages = result.get('packages', [])

            for package in packages:
                # Get package info
                pkg_info = package.get('package', {})
                pkg_name = pkg_info.get('name', 'unknown')
                pkg_version = pkg_info.get('version', 'unknown')
                pkg_ecosystem = pkg_info.get('ecosystem', 'unknown')

                # Get vulnerabilities for this package
                vulns = package.get('vulnerabilities', [])

                for vuln in vulns:
                    finding = self._convert_vulnerability(
                        vuln,
                        pkg_name,
                        pkg_version,
                        pkg_ecosystem,
                        source,
                        repo_path
                    )
                    if finding:
                        findings.append(finding)

        # Also process grouped vulnerabilities if present
        grouped = osv_results.get('grouped', [])
        for group in grouped:
            aliases = group.get('aliases', [])
            related_vulns = group.get('IDs', [])

            # Use the first vulnerability as the primary
            if related_vulns:
                # This is a simplified handling - in reality might need more logic
                pass

        return findings

    def _convert_vulnerability(
        self,
        vuln: Dict[str, Any],
        pkg_name: str,
        pkg_version: str,
        ecosystem: str,
        source: Dict[str, Any],
        repo_path: str
    ) -> Finding:
        """Convert OSV vulnerability to Finding"""

        # Get vulnerability details
        vuln_id = vuln.get('id', 'unknown')
        summary = vuln.get('summary', f'Vulnerability in {pkg_name}')
        details = vuln.get('details', '')

        # Get severity from CVSS score
        severity = SeverityLevel.MEDIUM  # Default
        cvss_scores = vuln.get('severity', [])
        if cvss_scores:
            # Get the highest CVSS score
            max_score = 0
            for score_data in cvss_scores:
                if score_data.get('type') == 'CVSS_V3':
                    score = score_data.get('score', 0)
                    if score > max_score:
                        max_score = score
            severity = self.cvss_to_severity(max_score)

        # Get affected versions
        affected = vuln.get('affected', [])
        affected_versions = []
        fixed_versions = []

        for affected_pkg in affected:
            if affected_pkg.get('package', {}).get('name') == pkg_name:
                ranges = affected_pkg.get('ranges', [])
                for range_info in ranges:
                    events = range_info.get('events', [])
                    for event in events:
                        if 'introduced' in event:
                            affected_versions.append(f">= {event['introduced']}")
                        elif 'fixed' in event:
                            fixed_versions.append(event['fixed'])

        # Determine location
        source_path = source.get('path', '')
        if source_path:
            try:
                location = str(Path(source_path).relative_to(repo_path))
            except:
                location = source_path
        else:
            location = f"{ecosystem} dependencies"

        # Get references
        references = []
        for ref in vuln.get('references', []):
            url = ref.get('url', '')
            if url:
                references.append(url)

        # Get CVE ID if available
        cve_id = None
        aliases = vuln.get('aliases', [])
        for alias in aliases:
            if alias.startswith('CVE-'):
                cve_id = alias
                break

        # Build recommendation
        if fixed_versions:
            recommendation = f"Update {pkg_name} to version {fixed_versions[0]} or later"
        else:
            recommendation = f"Update {pkg_name} to a patched version"

        return self.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=0.9,  # OSV database is reliable
            title=f"{vuln_id}: {summary}",
            description=details or summary,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence={
                'vulnerability_id': vuln_id,
                'package': pkg_name,
                'version': pkg_version,
                'ecosystem': ecosystem,
                'affected_versions': affected_versions,
                'fixed_versions': fixed_versions,
                'aliases': aliases
            },
            cve_id=cve_id
        )