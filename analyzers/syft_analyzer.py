"""
Syft analyzer - SBOM generation and analysis by Anchore
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


class SyftAnalyzer(BaseAnalyzer):
    """
    Integrates Syft - Software Bill of Materials (SBOM) generator
    https://github.com/anchore/syft

    While Syft doesn't find vulnerabilities directly, it:
    - Generates comprehensive SBOMs
    - Identifies all packages and dependencies
    - Detects licenses
    - Finds packages without package managers (e.g., binaries)
    - Outputs in multiple formats (SPDX, CycloneDX, JSON)

    We use it to identify components and licensing issues.
    """

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Generate SBOM and analyze for licensing and component issues"""
        findings = []

        try:
            # Generate SBOM in JSON format
            sbom_path = tempfile.mktemp(suffix='.json')

            cmd = [
                'syft',
                repo_path,
                '-o', f'json={sbom_path}',
                '--quiet',
                '--scope', 'all-layers',
                '--catalogers', 'all'  # Use all catalogers
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode == 0 and Path(sbom_path).exists():
                # Read and analyze SBOM
                with open(sbom_path, 'r') as f:
                    sbom_data = json.load(f)

                # Analyze the SBOM for issues
                findings.extend(self._analyze_licenses(sbom_data, repo_path))
                findings.extend(self._analyze_components(sbom_data, repo_path))
                findings.extend(self._analyze_metadata(sbom_data, repo_path))

                # Store SBOM info in project metadata for other analyzers
                if 'sbom_summary' not in project_info:
                    project_info['sbom_summary'] = self._create_sbom_summary(sbom_data)

                # Clean up
                Path(sbom_path).unlink()

            elif stderr:
                logger.error(f"Syft SBOM generation failed: {stderr.decode()}")

            logger.info(f"Syft analysis found {len(findings)} issues")

        except FileNotFoundError:
            logger.warning("Syft not found, skipping SBOM analysis")
        except Exception as e:
            logger.error(f"Syft analysis failed: {e}")

        return findings

    def _analyze_licenses(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze licenses in SBOM for potential issues"""
        findings = []

        # Track license types
        license_summary = {}
        problematic_packages = []

        # Define problematic licenses for different use cases
        restrictive_licenses = {
            'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'GPL-2.0+', 'GPL-3.0+',
            'GPL-2.0-only', 'GPL-3.0-only', 'AGPL-3.0-only'
        }

        # Weak copyleft that might cause issues
        weak_copyleft = {'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0'}

        # Analyze each artifact
        for artifact in sbom.get('artifacts', []):
            licenses = artifact.get('licenses', [])
            if not licenses:
                continue

            pkg_name = artifact.get('name', 'unknown')
            pkg_version = artifact.get('version', 'unknown')

            for license_info in licenses:
                license_name = license_info.get('value', 'unknown')
                if not license_name or license_name == 'unknown':
                    continue

                # Track license usage
                if license_name not in license_summary:
                    license_summary[license_name] = []
                license_summary[license_name].append(f"{pkg_name}@{pkg_version}")

                # Check for problematic licenses
                if license_name in restrictive_licenses:
                    problematic_packages.append({
                        'package': pkg_name,
                        'version': pkg_version,
                        'license': license_name,
                        'type': 'restrictive'
                    })
                elif license_name in weak_copyleft:
                    problematic_packages.append({
                        'package': pkg_name,
                        'version': pkg_version,
                        'license': license_name,
                        'type': 'weak_copyleft'
                    })

        # Create findings for problematic licenses
        for pkg in problematic_packages:
            severity = SeverityLevel.HIGH if pkg['type'] == 'restrictive' else SeverityLevel.MEDIUM

            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
                severity=severity,
                confidence=0.95,
                title=f"Restrictive License: {pkg['package']} uses {pkg['license']}",
                description=f"Package {pkg['package']} is licensed under {pkg['license']}, which may conflict with commercial use or require source code disclosure.",
                location=f"dependency:{pkg['package']}",
                recommendation="Review license compatibility with your project. Consider finding alternatives with more permissive licenses.",
                references=[
                    f"https://spdx.org/licenses/{pkg['license']}.html",
                    "https://choosealicense.com/licenses/"
                ],
                evidence={
                    'package': pkg['package'],
                    'version': pkg['version'],
                    'license': pkg['license'],
                    'license_type': pkg['type']
                }
            ))

        # Create summary finding if multiple license types detected
        if len(license_summary) > 5:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.LICENSE_VIOLATION,
                severity=SeverityLevel.LOW,
                confidence=1.0,
                title="Complex License Landscape",
                description=f"Project uses {len(license_summary)} different licenses across dependencies.",
                location="project",
                recommendation="Consider standardizing on compatible licenses and document license policy.",
                evidence={
                    'license_count': len(license_summary),
                    'licenses': list(license_summary.keys())[:10]  # Top 10
                }
            ))

        return findings

    def _analyze_components(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze components for potential issues"""
        findings = []

        # Check for concerning patterns
        duplicate_packages = {}
        binary_packages = []
        unknown_packages = []

        for artifact in sbom.get('artifacts', []):
            pkg_name = artifact.get('name', 'unknown')
            pkg_version = artifact.get('version', 'unknown')
            pkg_type = artifact.get('type', 'unknown')

            # Check for binaries (potential security risk)
            if pkg_type in ['binary', 'executable', 'archive']:
                binary_packages.append({
                    'name': pkg_name,
                    'type': pkg_type,
                    'locations': [loc.get('path', '') for loc in artifact.get('locations', [])]
                })

            # Check for unknown/unidentified packages
            if pkg_version == 'unknown' or not pkg_version:
                unknown_packages.append(pkg_name)

            # Track duplicates (different versions of same package)
            if pkg_name in duplicate_packages:
                duplicate_packages[pkg_name].append(pkg_version)
            else:
                duplicate_packages[pkg_name] = [pkg_version]

        # Create findings for binary packages
        for binary in binary_packages:
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.MEDIUM,
                confidence=0.8,
                title=f"Binary Package Detected: {binary['name']}",
                description=f"Binary or executable package '{binary['name']}' found. Binary packages are harder to audit for vulnerabilities.",
                location=binary['locations'][0] if binary['locations'] else 'unknown',
                recommendation="Consider building from source or using package manager versions when possible.",
                evidence={
                    'package': binary['name'],
                    'type': binary['type'],
                    'locations': binary['locations']
                }
            ))

        # Create findings for duplicate packages
        for pkg_name, versions in duplicate_packages.items():
            if len(set(versions)) > 1:  # Multiple different versions
                findings.append(self.create_finding(
                    vulnerability_type=VulnerabilityType.GENERIC,
                    severity=SeverityLevel.LOW,
                    confidence=1.0,
                    title=f"Multiple Versions: {pkg_name}",
                    description=f"Package '{pkg_name}' has multiple versions in the project: {', '.join(set(versions))}",
                    location="dependencies",
                    recommendation="Consolidate to a single version to avoid conflicts and reduce attack surface.",
                    evidence={
                        'package': pkg_name,
                        'versions': list(set(versions))
                    }
                ))

        return findings

    def _analyze_metadata(self, sbom: Dict[str, Any], repo_path: str) -> List[Finding]:
        """Analyze SBOM metadata for completeness and issues"""
        findings = []

        # Check for SBOM completeness
        artifacts = sbom.get('artifacts', [])
        total_packages = len(artifacts)

        # Count packages with incomplete information
        incomplete_count = 0
        missing_licenses = 0
        missing_versions = 0

        for artifact in artifacts:
            if not artifact.get('version') or artifact.get('version') == 'unknown':
                missing_versions += 1
                incomplete_count += 1
            if not artifact.get('licenses'):
                missing_licenses += 1

        # Create finding if many packages have incomplete info
        if incomplete_count > total_packages * 0.1:  # More than 10%
            findings.append(self.create_finding(
                vulnerability_type=VulnerabilityType.GENERIC,
                severity=SeverityLevel.LOW,
                confidence=1.0,
                title="Incomplete Package Information",
                description=f"{incomplete_count} out of {total_packages} packages have incomplete information.",
                location="sbom",
                recommendation="Improve package detection by using proper package managers and maintaining metadata.",
                evidence={
                    'total_packages': total_packages,
                    'incomplete_count': incomplete_count,
                    'missing_versions': missing_versions,
                    'missing_licenses': missing_licenses
                }
            ))

        return findings

    def _create_sbom_summary(self, sbom: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of SBOM contents for other analyzers"""
        artifacts = sbom.get('artifacts', [])

        # Count by type
        type_counts = {}
        language_counts = {}

        for artifact in artifacts:
            pkg_type = artifact.get('type', 'unknown')
            type_counts[pkg_type] = type_counts.get(pkg_type, 0) + 1

            # Infer language from type
            if pkg_type in ['python', 'wheel', 'egg']:
                language_counts['python'] = language_counts.get('python', 0) + 1
            elif pkg_type in ['npm', 'yarn']:
                language_counts['javascript'] = language_counts.get('javascript', 0) + 1
            elif pkg_type in ['gem']:
                language_counts['ruby'] = language_counts.get('ruby', 0) + 1
            elif pkg_type in ['go-module']:
                language_counts['go'] = language_counts.get('go', 0) + 1
            elif pkg_type in ['cargo', 'rust']:
                language_counts['rust'] = language_counts.get('rust', 0) + 1
            elif pkg_type in ['jar', 'maven']:
                language_counts['java'] = language_counts.get('java', 0) + 1

        return {
            'total_packages': len(artifacts),
            'package_types': type_counts,
            'languages': language_counts,
            'has_binaries': any(a.get('type') in ['binary', 'executable'] for a in artifacts),
            'source': sbom.get('source', {})
        }