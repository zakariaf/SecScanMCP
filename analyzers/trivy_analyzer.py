"""
Trivy analyzer - Comprehensive vulnerability scanner by Aqua Security
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


class TrivyAnalyzer(BaseAnalyzer):
    """
    Integrates Trivy - All-in-one security scanner
    https://github.com/aquasecurity/trivy

    Features:
    - Scans vulnerabilities in OS packages and language dependencies
    - Detects misconfigurations
    - Finds secrets
    - Checks licenses
    - Supports 20+ programming languages
    - Works with containers, filesystems, git repos, and more
    """

    # Map Trivy severity to our severity levels
    SEVERITY_MAP = {
        'CRITICAL': SeverityLevel.CRITICAL,
        'HIGH': SeverityLevel.HIGH,
        'MEDIUM': SeverityLevel.MEDIUM,
        'LOW': SeverityLevel.LOW,
        'UNKNOWN': SeverityLevel.INFO
    }

    # Map Trivy vulnerability classes to our types
    VULN_CLASS_MAP = {
        'lang-pkgs': VulnerabilityType.VULNERABLE_DEPENDENCY,
        'os-pkgs': VulnerabilityType.VULNERABLE_DEPENDENCY,
        'config': VulnerabilityType.INSECURE_CONFIGURATION,
        'secret': VulnerabilityType.HARDCODED_SECRET,
        'license': VulnerabilityType.LICENSE_VIOLATION
    }

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Trivy comprehensive security scan"""
        findings = []

        try:
            # Run Trivy with multiple scanners
            cmd = [
                'trivy',
                'fs',  # Filesystem scan
                repo_path,
                '--format', 'json',
                '--scanners', 'vuln,secret',  # Enable all scanners, we can add misconfig and license too
                '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                '--quiet',
                '--timeout', '10m',
                # '--license-full',  # Get full license info, if we add license scanning
                '--include-non-failures'  # Include all findings
            ]

            # Add cache directory for offline mode
            cache_dir = tempfile.gettempdir() + '/.trivy_cache'
            cmd.extend(['--cache-dir', cache_dir])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                try:
                    results = json.loads(stdout.decode())

                    # Process different result types
                    if isinstance(results, dict) and 'Results' in results:
                        # New format
                        for result in results.get('Results', []):
                            findings.extend(self._process_result(result, repo_path))
                    else:
                        # Old format or single result
                        findings.extend(self._process_result(results, repo_path))

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Trivy output: {e}")
                    if stderr:
                        logger.error(f"Trivy stderr: {stderr.decode()}")

            elif process.returncode != 0 and stderr:
                logger.error(f"Trivy scan failed: {stderr.decode()}")

            logger.info(f"Trivy found {len(findings)} issues")

        except FileNotFoundError:
            logger.warning("Trivy not found, skipping Trivy analysis")
        except Exception as e:
            logger.error(f"Trivy analysis failed: {e}")

        return findings

    def _process_result(self, result: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Process a single Trivy result object"""
        findings = []

        # Get target information
        target = result.get('Target', 'unknown')
        target_type = result.get('Type', 'unknown')

        # Process vulnerabilities
        for vuln in result.get('Vulnerabilities', []):
            finding = self._convert_vulnerability(vuln, target, repo_path)
            if finding:
                findings.append(finding)

        # Process misconfigurations
        for misconfig in result.get('Misconfigurations', []):
            finding = self._convert_misconfiguration(misconfig, target, repo_path)
            if finding:
                findings.append(finding)

        # Process secrets
        for secret in result.get('Secrets', []):
            finding = self._convert_secret(secret, target, repo_path)
            if finding:
                findings.append(finding)

        # Process licenses
        for license_finding in result.get('Licenses', []):
            finding = self._convert_license(license_finding, target, repo_path)
            if finding:
                findings.append(finding)

        return findings

    def _convert_vulnerability(self, vuln: Dict[str, Any], target: str, repo_path: str) -> Finding:
        """Convert Trivy vulnerability to our Finding model"""

        # Extract basic info
        vuln_id = vuln.get('VulnerabilityID', 'UNKNOWN')
        pkg_name = vuln.get('PkgName', 'unknown')
        installed_version = vuln.get('InstalledVersion', 'unknown')
        fixed_version = vuln.get('FixedVersion', '')

        # Get severity
        severity = self.SEVERITY_MAP.get(
            vuln.get('Severity', 'UNKNOWN'),
            SeverityLevel.MEDIUM
        )

        # Build description
        description = vuln.get('Description', f'Vulnerability in {pkg_name}')
        if vuln.get('Title'):
            description = f"{vuln['Title']}. {description}"

        # Get references
        references = vuln.get('References', [])
        if vuln.get('PrimaryURL'):
            references.insert(0, vuln['PrimaryURL'])

        # Determine location
        try:
            location = str(Path(target).relative_to(repo_path))
        except:
            location = target

        # Build recommendation
        if fixed_version:
            recommendation = f"Update {pkg_name} to version {fixed_version} or later"
        else:
            recommendation = f"No fix available yet for {pkg_name}. Monitor for updates or consider alternatives."

        # Get CVSS score
        cvss_score = 0.0
        cvss_data = vuln.get('CVSS', {})
        for source, scores in cvss_data.items():
            if isinstance(scores, dict) and 'V3Score' in scores:
                cvss_score = max(cvss_score, scores['V3Score'])
            elif isinstance(scores, dict) and 'V2Score' in scores:
                cvss_score = max(cvss_score, scores['V2Score'])

        return self.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=0.95,  # Trivy is highly accurate
            title=f"{vuln_id}: {pkg_name} {installed_version}",
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence={
                'vulnerability_id': vuln_id,
                'package': pkg_name,
                'installed_version': installed_version,
                'fixed_version': fixed_version,
                'data_source': vuln.get('DataSource', {}),
                'cvss_score': cvss_score,
                'exploit_available': 'exploit' in description.lower()
            },
            cve_id=vuln_id if vuln_id.startswith('CVE-') else None
        )

    def _convert_misconfiguration(self, misconfig: Dict[str, Any], target: str, repo_path: str) -> Finding:
        """Convert Trivy misconfiguration to Finding"""

        # Extract info
        check_id = misconfig.get('ID', 'UNKNOWN')
        title = misconfig.get('Title', 'Configuration issue')

        # Map severity
        severity = self.SEVERITY_MAP.get(
            misconfig.get('Severity', 'UNKNOWN'),
            SeverityLevel.MEDIUM
        )

        # Get location with line numbers if available
        location = target
        if misconfig.get('CauseMetadata'):
            cause = misconfig['CauseMetadata']
            if cause.get('StartLine'):
                location = f"{target}:{cause['StartLine']}"

        # Build evidence
        evidence = {
            'check_id': check_id,
            'type': misconfig.get('Type', 'unknown'),
            'message': misconfig.get('Message', '')
        }

        if misconfig.get('CauseMetadata', {}).get('Code'):
            evidence['code_sample'] = misconfig['CauseMetadata']['Code']

        return self.create_finding(
            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
            severity=severity,
            confidence=0.9,
            title=f"Misconfiguration: {title}",
            description=misconfig.get('Description', title),
            location=location,
            recommendation=misconfig.get('Resolution', 'Review and fix the configuration issue'),
            references=misconfig.get('References', []),
            evidence=evidence
        )

    def _convert_secret(self, secret: Dict[str, Any], target: str, repo_path: str) -> Finding:
        """Convert Trivy secret finding to Finding"""

        # Extract info
        rule_id = secret.get('RuleID', 'generic-secret')
        category = secret.get('Category', 'unknown')

        # Severity is always high for secrets
        severity = self.SEVERITY_MAP.get(
            secret.get('Severity', 'HIGH'),
            SeverityLevel.HIGH
        )

        # Get location with line number
        location = target
        if secret.get('StartLine'):
            location = f"{target}:{secret['StartLine']}"

        # Mask the actual secret
        match = secret.get('Match', '')
        if len(match) > 8:
            masked = match[:4] + '*' * (len(match) - 8) + match[-4:]
        else:
            masked = '*' * len(match)

        return self.create_finding(
            vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
            severity=severity,
            confidence=0.9,
            title=f"Exposed Secret: {category}",
            description=f"Found {category} in source code",
            location=location,
            recommendation="Remove the secret immediately and rotate credentials. Use environment variables or secret management systems.",
            references=["https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"],
            evidence={
                'rule_id': rule_id,
                'category': category,
                'masked_secret': masked,
                'line': secret.get('StartLine', 0)
            }
        )

    def _convert_license(self, license_finding: Dict[str, Any], target: str, repo_path: str) -> Finding:
        """Convert Trivy license finding to Finding"""

        # Extract info
        pkg_name = license_finding.get('PkgName', 'unknown')
        license_name = license_finding.get('Name', 'unknown')

        # Determine severity based on license type
        severity = SeverityLevel.INFO
        confidence = license_finding.get('Confidence', 1.0)

        # Check for problematic licenses
        problematic_licenses = ['GPL', 'AGPL', 'LGPL', 'CC-BY-SA']
        if any(lic in license_name.upper() for lic in problematic_licenses):
            severity = SeverityLevel.MEDIUM

        return self.create_finding(
            vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
            severity=severity,
            confidence=confidence,
            title=f"License: {pkg_name} uses {license_name}",
            description=f"Package {pkg_name} is licensed under {license_name}",
            location=target,
            recommendation="Review license compatibility with your project's license policy",
            references=[license_finding.get('Link', '')] if license_finding.get('Link') else [],
            evidence={
                'package': pkg_name,
                'license': license_name,
                'category': license_finding.get('Category', ''),
                'confidence': confidence
            }
        )