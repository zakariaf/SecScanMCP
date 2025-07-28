"""
Core security scanner that coordinates all analysis tools
"""

import asyncio
import subprocess
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
import tempfile
import shutil

from analyzers import (
    BanditAnalyzer,
    SemgrepAnalyzer,
    TrivyAnalyzer,
    GrypeAnalyzer,
    SyftAnalyzer,
    TruffleHogAnalyzer,
    MCPSpecificAnalyzer,
    DynamicAnalyzer
)
from models import Finding, ScanResult
from scoring import SecurityScorer

logger = logging.getLogger(__name__)


class SecurityScanner:
    """Main scanner that orchestrates all security analysis tools"""

    def __init__(self):
        # Initialize all analyzers
        self.analyzers = {
            'syft': SyftAnalyzer(),          # SBOM generation first
            'trivy': TrivyAnalyzer(),        # Comprehensive scanner
            'grype': GrypeAnalyzer(),        # Fast vulnerability scanner
            'bandit': BanditAnalyzer(),      # Python AST analysis
            'semgrep': SemgrepAnalyzer(),    # Pattern-based analysis
            'trufflehog': TruffleHogAnalyzer(), # Secret detection
            'mcp_specific': MCPSpecificAnalyzer(), # MCP vulnerabilities
            'dynamic': DynamicAnalyzer()     # Behavioral analysis
        }

        self.scorer = SecurityScorer()

    async def scan_repository(
        self,
        repository_url: str,
        temp_dir: str,
        scan_options: Dict[str, Any] = None
    ) -> ScanResult:
        """
        Main scanning orchestration

        Args:
            repository_url: Git repository URL to scan
            temp_dir: Temporary directory for cloning
            scan_options: Optional configuration

        Returns:
            Complete scan results with findings and score
        """
        scan_options = scan_options or {}

        # Clone repository
        repo_path = await self._clone_repository(repository_url, temp_dir)

        # Detect project type and MCP configuration
        project_info = await self._analyze_project(repo_path)

        # Run all analyzers in parallel where possible
        findings = await self._run_analyzers(repo_path, project_info, scan_options)

        # Calculate security score
        score_data = self.scorer.calculate_score(findings)

        # Build result
        result = ScanResult(
            repository_url=repository_url,
            project_type=project_info['type'],
            is_mcp_server=project_info['is_mcp'],
            findings=findings,
            security_score=score_data['score'],
            security_grade=score_data['grade'],
            summary=self._generate_summary(findings, score_data),
            detailed_results=self._organize_findings(findings),
            scan_metadata={
                'analyzers_run': list(self.analyzers.keys()),
                'project_info': project_info,
                'options': scan_options
            }
        )

        return result

    async def _clone_repository(self, repo_url: str, target_dir: str) -> str:
        """Clone repository with security constraints"""
        try:
            # Use sparse checkout for efficiency
            clone_cmd = [
                'git', 'clone',
                '--depth', '1',
                '--single-branch',
                '--no-tags',
                repo_url,
                target_dir
            ]

            process = await asyncio.create_subprocess_exec(
                *clone_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                raise RuntimeError(f"Git clone failed: {stderr.decode()}")

            logger.info(f"Successfully cloned repository to {target_dir}")
            return target_dir

        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            raise

    async def _analyze_project(self, repo_path: str) -> Dict[str, Any]:
        """Detect project type and MCP configuration"""
        project_info = {
            'type': 'unknown',
            'language': None,
            'is_mcp': False,
            'mcp_config': None,
            'dependencies': []
        }

        # Check for MCP indicators
        mcp_files = ['mcp.json', 'mcp.yaml', 'mcp.yml']
        for mcp_file in mcp_files:
            if (Path(repo_path) / mcp_file).exists():
                project_info['is_mcp'] = True
                # Load MCP configuration
                try:
                    with open(Path(repo_path) / mcp_file) as f:
                        if mcp_file.endswith('.json'):
                            project_info['mcp_config'] = json.load(f)
                        else:
                            import yaml
                            project_info['mcp_config'] = yaml.safe_load(f)
                except Exception as e:
                    logger.warning(f"Failed to parse MCP config: {e}")
                break

        # Detect language and project type
        if (Path(repo_path) / 'package.json').exists():
            project_info['type'] = 'node'
            project_info['language'] = 'javascript'
            # Check for MCP in dependencies
            try:
                with open(Path(repo_path) / 'package.json') as f:
                    pkg = json.load(f)
                    deps = list(pkg.get('dependencies', {}).keys())
                    deps.extend(pkg.get('devDependencies', {}).keys())
                    project_info['dependencies'] = deps
                    if any('mcp' in dep.lower() for dep in deps):
                        project_info['is_mcp'] = True
            except:
                pass

        elif (Path(repo_path) / 'requirements.txt').exists() or (Path(repo_path) / 'pyproject.toml').exists() or (Path(repo_path) / 'setup.py').exists():
            project_info['type'] = 'python'
            project_info['language'] = 'python'
            # Check for MCP in Python files
            for py_file in Path(repo_path).rglob('*.py'):
                try:
                    with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        if 'import mcp' in content or 'from mcp' in content:
                            project_info['is_mcp'] = True
                            break
                except:
                    continue

        elif (Path(repo_path) / 'go.mod').exists():
            project_info['type'] = 'go'
            project_info['language'] = 'go'

        elif (Path(repo_path) / 'Cargo.toml').exists():
            project_info['type'] = 'rust'
            project_info['language'] = 'rust'

        return project_info

    async def _run_analyzers(
        self,
        repo_path: str,
        project_info: Dict[str, Any],
        scan_options: Dict[str, Any]
    ) -> List[Finding]:
        """Run all applicable analyzers"""
        all_findings = []

        # Determine which analyzers to run
        analyzers_to_run = []

        # Always run SBOM generation first
        analyzers_to_run.append('syft')

        # Universal analyzers that work for all languages
        analyzers_to_run.extend(['trivy', 'grype', 'semgrep', 'trufflehog'])

        # Language-specific analyzers
        if project_info['language'] == 'python':
            analyzers_to_run.append('bandit')

        # MCP-specific if applicable
        if project_info['is_mcp']:
            analyzers_to_run.append('mcp_specific')
            if scan_options.get('enable_dynamic_analysis', True):
                analyzers_to_run.append('dynamic')

        # Run analyzers
        tasks = []
        for analyzer_name in analyzers_to_run:
            if analyzer_name in self.analyzers:
                analyzer = self.analyzers[analyzer_name]
                logger.info(f"Running {analyzer_name} analyzer...")
                task = self._run_analyzer_safe(
                    analyzer,
                    repo_path,
                    project_info
                )
                tasks.append(task)

        # Wait for all analyzers to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect findings
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Analyzer failed: {result}")
                continue
            if result:
                all_findings.extend(result)

        # Deduplicate findings
        return self._deduplicate_findings(all_findings)

    async def _run_analyzer_safe(
        self,
        analyzer,
        repo_path: str,
        project_info: Dict[str, Any]
    ) -> List[Finding]:
        """Run analyzer with error handling"""
        try:
            return await analyzer.analyze(repo_path, project_info)
        except Exception as e:
            logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
            return []

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings"""
        seen = set()
        unique_findings = []

        for finding in findings:
            # Create a unique key for the finding
            key = (
                finding.vulnerability_type,
                finding.location,
                finding.title
            )

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings

    def _generate_summary(
        self,
        findings: List[Finding],
        score_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate executive summary"""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        type_counts = {}

        for finding in findings:
            severity_counts[finding.severity] += 1
            if finding.vulnerability_type not in type_counts:
                type_counts[finding.vulnerability_type] = 0
            type_counts[finding.vulnerability_type] += 1

        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'vulnerability_types': type_counts,
            'security_score': score_data['score'],
            'security_grade': score_data['grade'],
            'risk_level': self._determine_risk_level(score_data['score']),
            'top_risks': self._get_top_risks(findings)
        }

    def _determine_risk_level(self, score: float) -> str:
        """Determine overall risk level"""
        if score >= 90:
            return 'low'
        elif score >= 75:
            return 'medium'
        elif score >= 60:
            return 'high'
        else:
            return 'critical'

    def _get_top_risks(self, findings: List[Finding], limit: int = 3) -> List[Dict]:
        """Get top risk findings"""
        # Sort by severity and confidence
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

        sorted_findings = sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), -f.confidence)
        )

        top_risks = []
        for finding in sorted_findings[:limit]:
            top_risks.append({
                'title': finding.title,
                'severity': finding.severity,
                'type': finding.vulnerability_type,
                'location': finding.location
            })

        return top_risks

    def _organize_findings(self, findings: List[Finding]) -> Dict[str, List[Dict]]:
        """Organize findings by analyzer"""
        organized = {}

        for finding in findings:
            tool = finding.tool
            if tool not in organized:
                organized[tool] = []

            organized[tool].append({
                'title': finding.title,
                'severity': finding.severity,
                'type': finding.vulnerability_type,
                'location': finding.location,
                'description': finding.description,
                'recommendation': finding.recommendation,
                'confidence': finding.confidence,
                'evidence': finding.evidence
            })

        return organized