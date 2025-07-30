"""
Grype analyzer - Vulnerability scanner by Anchore
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


class GrypeAnalyzer(BaseAnalyzer):
    """
    Integrates Grype - Vulnerability scanner for container images and filesystems
    https://github.com/anchore/grype

    Features:
    - Fast vulnerability scanning
    - Low false positive rate
    - Works with Syft SBOMs
    - Supports multiple output formats
    - Includes EPSS and KEV data for risk prioritization
    """

    # Map Grype severity to our severity levels
    SEVERITY_MAP = {
        'Critical': SeverityLevel.CRITICAL,
        'High': SeverityLevel.HIGH,
        'Medium': SeverityLevel.MEDIUM,
        'Low': SeverityLevel.LOW,
        'Negligible': SeverityLevel.INFO,
        'Unknown': SeverityLevel.INFO
    }

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run Grype vulnerability scan"""
        findings = []

        try:
            # First, check if we have an SBOM from Syft
            sbom_path = await self._get_or_create_sbom(repo_path)

            if sbom_path:
                # Scan the SBOM (faster)
                cmd = [
                    'grype',
                    f'sbom:{sbom_path}',
                    '-o', 'json',
                    '--quiet'
                ]
            else:
                # Direct filesystem scan
                cmd = [
                    'grype',
                    f'dir:{repo_path}',
                    '-o', 'json',
                    '--quiet',
                    '--exclude', '.git/**',
                    '--exclude', '**/node_modules/**',
                    '--exclude', '**/__pycache__/**'
                ]

            # Add additional options
            cmd.extend([
                '--add-cpes-if-none',  # Generate CPEs if missing
                '--by-cve',  # Organize by CVE
                '--scope', 'all-layers'  # Scan all layers if container
            ])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if stdout:
                try:
                    results = json.loads(stdout.decode())

                    # Process matches
                    for match in results.get('matches', []):
                        finding = self._convert_match(match, repo_path)
                        if finding:
                            findings.append(finding)

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Grype output: {e}")

            elif process.returncode != 0 and stderr:
                logger.error(f"Grype scan failed: {stderr.decode()}")

            # Clean up SBOM if we created it
            if sbom_path and sbom_path.startswith('/tmp/'):
                try:
                    Path(sbom_path).unlink()
                except:
                    pass

            logger.info(f"Grype found {len(findings)} vulnerabilities")

        except FileNotFoundError:
            logger.warning("Grype not found, skipping Grype analysis")
        except Exception as e:
            logger.error(f"Grype analysis failed: {e}")

        return findings

    async def _get_or_create_sbom(self, repo_path: str) -> str:
        """Check for existing SBOM or create one with Syft"""
        # Look for existing SBOM files
        sbom_patterns = ['*sbom*.json', '*sbom*.spdx', '*sbom*.cdx']

        for pattern in sbom_patterns:
            for sbom_file in Path(repo_path).glob(pattern):
                if sbom_file.is_file():
                    logger.info(f"Found existing SBOM: {sbom_file}")
                    return str(sbom_file)

        # Try to generate SBOM with Syft if available
        try:
            sbom_path = tempfile.mktemp(suffix='.json')

            cmd = [
                'syft',
                repo_path,
                '-o', f'json={sbom_path}',
                '--quiet'
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            await process.communicate()

            if process.returncode == 0 and Path(sbom_path).exists():
                logger.info("Generated SBOM with Syft for faster scanning")
                return sbom_path

        except:
            pass

        return None

    def _convert_match(self, match: Dict[str, Any], repo_path: str) -> Finding:
        """Convert Grype match to Finding"""

        # Extract vulnerability info
        vulnerability = match.get('vulnerability', {})
        vuln_id = vulnerability.get('id', 'UNKNOWN')

        # Extract package info
        artifact = match.get('artifact', {})
        pkg_name = artifact.get('name', 'unknown')
        pkg_version = artifact.get('version', 'unknown')
        pkg_type = artifact.get('type', 'unknown')

        # Get severity
        severity = self.SEVERITY_MAP.get(
            vulnerability.get('severity', 'Unknown'),
            SeverityLevel.MEDIUM
        )

        # Get fix information (handle both dict and list formats)
        fix_versions = []
        fix_field = vulnerability.get('fix', {})

        if isinstance(fix_field, dict):
            # old format: { "versions": [ ... ] }
            fix_versions = fix_field.get('versions', [])
        elif isinstance(fix_field, list):
            # new format: [ { "versions": [...] }, ... ] or just a list of version strings
            for entry in fix_field:
                if isinstance(entry, dict) and 'versions' in entry:
                    fix_versions.extend(entry.get('versions', []))
                elif isinstance(entry, str):
                    fix_versions.append(entry)
        # else: nothing to do if it's some other type

        # Build description
        description = vulnerability.get('description', f'Vulnerability in {pkg_name}')

        # Get location
        locations = artifact.get('locations', [])
        if locations:
            location = locations[0].get('path', 'unknown')
            try:
                location = str(Path(location).relative_to(repo_path))
            except:
                pass
        else:
            location = f"{pkg_type} package"

        # Build recommendation
        if fix_versions:
            recommendation = f"Update {pkg_name} to one of: {', '.join(fix_versions)}"
        else:
            recommendation = f"No fix available for {pkg_name}. Monitor for updates or consider alternatives."

        # Get references
        references = []
        for url in vulnerability.get('urls', []):
            references.append(url)

        # Get related vulnerabilities
        related = []
        for rel in vulnerability.get('relatedVulnerabilities', []):
            related.append(rel.get('id'))

        # Extract CVSS scores
        cvss_scores = {}
        for cvss in vulnerability.get('cvss', []):
            version = cvss.get('version', 'unknown')
            cvss_scores[version] = {
                'score': cvss.get('metrics', {}).get('baseScore', 0),
                'vector': cvss.get('vector', '')
            }

        # Get highest CVSS score
        max_cvss = 0
        for version, data in cvss_scores.items():
            max_cvss = max(max_cvss, data['score'])

        # Check for EPSS data
        epss_score = None
        epss_percentile = None

        epss_field = vulnerability.get('epss')
        if isinstance(epss_field, dict):
            # older (hypothetical) single-object format
            epss_score      = epss_field.get('score') or epss_field.get('epss')
            epss_percentile = epss_field.get('percentile')
        elif isinstance(epss_field, list) and epss_field:
            # new array format: pick the first entry
            first = epss_field[0]
            if isinstance(first, dict):
                epss_score      = first.get('epss', first.get('score'))
                epss_percentile = first.get('percentile')

        # Check for KEV data
        is_kev = False
        if 'kev' in vulnerability:
            is_kev = True

        # Calculate confidence based on match quality
        confidence = 0.9  # Base confidence
        match_details = match.get('matchDetails', [])
        if match_details:
            detail = match_details[0]
            if detail.get('type') == 'exact-direct-match':
                confidence = 0.95
            elif detail.get('type') == 'exact-indirect-match':
                confidence = 0.85

        # Build evidence
        evidence = {
            'vulnerability_id': vuln_id,
            'package': pkg_name,
            'version': pkg_version,
            'package_type': pkg_type,
            'fixed_versions': fix_versions,
            'cvss_scores': cvss_scores,
            'cvss_max': max_cvss,
            'related_vulnerabilities': related,
            'match_confidence': confidence
        }

        # Add risk scoring data if available
        if epss_score is not None:
            evidence['epss_score'] = epss_score
            if epss_percentile is not None:
                evidence['epss_percentile'] = epss_percentile

        if is_kev:
            evidence['is_known_exploited'] = True
            evidence['kev_data'] = vulnerability.get('kev', {})
            # Increase severity if actively exploited
            if severity == SeverityLevel.MEDIUM:
                severity = SeverityLevel.HIGH
            elif severity == SeverityLevel.LOW:
                severity = SeverityLevel.MEDIUM

        return self.create_finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=severity,
            confidence=confidence,
            title=f"{vuln_id}: {pkg_name} {pkg_version}",
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence=evidence,
            cve_id=vuln_id if vuln_id.startswith('CVE-') else None
        )