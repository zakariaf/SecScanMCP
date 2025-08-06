"""
Core security scanner that coordinates all analysis tools
"""

import asyncio
import subprocess
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
import tempfile
import shutil

from analyzers import (
    BanditAnalyzer,
    OpenGrepAnalyzer,  # Open-source static analysis (replaces Semgrep)
    TrivyAnalyzer,
    GrypeAnalyzer,
    SyftAnalyzer,
    TruffleHogAnalyzer,
    MCPSpecificAnalyzer,
    MCPConfigAnalyzer,  # MCP-native configuration analysis
    DynamicAnalyzer,
    ClamAVAnalyzer,  # Military-grade malware detection
    YARAAnalyzer,    # Advanced pattern matching
    CodeQLAnalyzer   # Semantic code analysis
)
from models import Finding, ScanResult
from enhanced_scoring import EnhancedSecurityScorer

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
            'opengrep': OpenGrepAnalyzer(),  # Open-source pattern-based analysis
            'trufflehog': TruffleHogAnalyzer(), # Secret detection
            'mcp_specific': MCPSpecificAnalyzer(), # MCP vulnerabilities
            'mcp_config': MCPConfigAnalyzer(), # MCP configuration analysis
            'dynamic': DynamicAnalyzer(),    # Behavioral analysis
            'clamav': ClamAVAnalyzer(),       # Military-grade malware detection
            'yara': YARAAnalyzer(),          # Advanced pattern matching
            'codeql': CodeQLAnalyzer()       # Semantic code analysis
        }

        self.enhanced_scorer = EnhancedSecurityScorer()

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

        # Calculate enhanced dual scores
        enhanced_scores = self.enhanced_scorer.calculate_both_scores(findings)
        
        # Separate user-centric security issues
        user_centric_findings = self._extract_user_centric_findings(findings)

        # Build result
        result = ScanResult(
            repository_url=repository_url,
            project_type=project_info['type'],
            is_mcp_server=project_info['is_mcp'],
            findings=findings,
            user_centric_findings=user_centric_findings,
            security_score=enhanced_scores['user_safety']['score'],
            security_grade=enhanced_scores['user_safety']['grade'],
            enhanced_scores=enhanced_scores,
            summary=self._generate_summary(findings, enhanced_scores),
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

        # Smart analyzer selection to minimize overlap
        analyzers_to_run = self._select_optimal_analyzers(project_info, scan_options)

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

        # Deduplicate findings with enhanced logic for scoring
        deduplicated_findings = self._deduplicate_findings(all_findings)
        
        # Apply additional aggregation for enhanced scoring
        return self._aggregate_for_enhanced_scoring(deduplicated_findings)

    def _select_optimal_analyzers(self, project_info: Dict[str, Any], scan_options: Dict[str, Any]) -> List[str]:
        """Select non-overlapping analyzers based on project type and requirements"""
        analyzers = []
        language = project_info.get('language', 'unknown')
        is_mcp = project_info.get('is_mcp', False)
        
        # 1. Always generate SBOM first
        analyzers.append('syft')
        
        # 2. Core security tools (specialized, no overlap)
        analyzers.extend([
            'trufflehog',    # Best for secrets detection
            'clamav',        # Malware detection
        ])
        
        # 3. Language-specific analysis (avoid opengrep+bandit overlap)
        if language == 'python':
            analyzers.append('bandit')     # Python-specific security linting
            # Skip opengrep for Python to avoid overlap with bandit
        else:
            analyzers.append('opengrep')   # Multi-language pattern matching
        
        # 4. Dependency scanning (choose one primary)
        if scan_options.get('fast_scan', False):
            analyzers.append('grype')      # Faster for quick scans
        else:
            analyzers.append('trivy')      # More comprehensive (configs, licenses, etc.)
        
        # 5. Advanced semantic analysis
        codeql_languages = ['python', 'javascript', 'typescript', 'java', 'go', 'cpp', 'csharp', 'ruby']
        if language in codeql_languages and not scan_options.get('skip_advanced', False):
            analyzers.append('codeql')
        
        # 6. MCP-specific analysis (critical for MCP servers)
        if is_mcp:
            analyzers.append('mcp_specific')  # Always run for MCP servers
            analyzers.append('mcp_config')    # MCP-native configuration analysis
            
            # Dynamic analysis (optional but recommended)
            if scan_options.get('enable_dynamic_analysis', True):
                analyzers.append('dynamic')
        
        # 7. Advanced pattern matching (for complex threats)
        if not scan_options.get('skip_advanced', False):
            analyzers.append('yara')       # Advanced behavioral patterns
        
        logger.info(f"Selected {len(analyzers)} analyzers for {language} {'MCP ' if is_mcp else ''}project: {', '.join(analyzers)}")
        return analyzers

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
        """Remove duplicate findings with improved logic and tool priority"""
        from collections import defaultdict
        
        # Tool priority for same vulnerability type (higher number = higher priority)
        TOOL_PRIORITY = {
            'hardcoded_secret': {'trufflehog': 3, 'trivy': 2, 'bandit': 1},
            'command_injection': {'mcpspecific': 4, 'codeql': 3, 'dynamic': 2, 'bandit': 1},
            'prompt_injection': {'mcpspecific': 4, 'mcp_specific': 4, 'codeql': 2, 'opengrep': 1},
            'vulnerable_dependency': {'trivy': 3, 'grype': 2, 'syft': 1},
            'sql_injection': {'codeql': 3, 'bandit': 2, 'opengrep': 1},
            'generic': {'yara': 2, 'clamav': 3, 'opengrep': 1},  # Prioritize advanced pattern matching
        }
        
        # Group findings by vulnerability type + normalized location
        grouped = defaultdict(list)
        
        for finding in findings:
            # Normalize location to handle path variations
            normalized_location = finding.location.lstrip('/').strip()

            # Extract CVE ID if present for better deduplication
            cve_id = finding.cve_id or self._extract_cve_from_title(finding.title)

            # Create a more robust unique key
            if cve_id:
                # For CVE-based findings, use CVE ID + package info
                package_info = self._extract_package_info(finding.title, finding.evidence)
                key = (finding.vulnerability_type, cve_id, package_info)
            else:
                # For non-CVE findings, use type + location
                key = (finding.vulnerability_type, normalized_location)
            
            grouped[key].append(finding)

        # Process each group with tool priority
        unique_findings = []
        total_before = len(findings)
        
        for findings_group in grouped.values():
            if len(findings_group) == 1:
                unique_findings.extend(findings_group)
            else:
                # Multiple findings for same vulnerability - pick best tool
                vuln_type = findings_group[0].vulnerability_type.value
                priorities = TOOL_PRIORITY.get(vuln_type, {})
                
                # Sort by tool priority (desc) then confidence (desc)
                best_finding = max(findings_group, key=lambda f: (
                    priorities.get(f.tool, 0),  # Tool priority
                    f.confidence,               # Confidence
                    f.severity == 'critical'    # Critical severity bonus
                ))
                
                # If there are multiple high-priority findings, merge evidence
                other_findings = [f for f in findings_group if f != best_finding]
                if other_findings:
                    # Combine evidence from other high-confidence findings
                    high_conf_others = [f for f in other_findings if f.confidence >= 0.7]
                    for other in high_conf_others:
                        if other.evidence:
                            best_finding.evidence.update({
                                f"{other.tool}_evidence": other.evidence
                            })
                
                unique_findings.append(best_finding)

        logger.info(f"Deduplicated {total_before} findings down to {len(unique_findings)} ({(total_before-len(unique_findings))/total_before*100:.1f}% reduction)")
        return unique_findings

    def _extract_cve_from_title(self, title: str) -> str:
        """Extract CVE ID from finding title"""
        cve_match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
        return cve_match.group(0).upper() if cve_match else ''

    def _extract_package_info(self, title: str, evidence: Dict[str, Any]) -> str:
        """Extract package name and version for deduplication"""
        # Try to get from evidence first (more reliable)
        if evidence.get('package') and evidence.get('version'):
            return f"{evidence['package']}@{evidence['version']}"

        if evidence.get('package') and evidence.get('installed_version'):
            return f"{evidence['package']}@{evidence['installed_version']}"

        # Fallback to parsing title
        # Handle formats like "CVE-2024-6221: flask-cors 4.0.0"
        match = re.search(r':\s*([a-zA-Z0-9\-_\.]+)\s+([\d\.]+)', title)
        if match:
            package, version = match.groups()
            return f"{package}@{version}"

        return title.split(':')[-1].strip() if ':' in title else title

    def _generate_key_for_finding(self, finding: Finding) -> tuple:
        """Generate the same key used in deduplication"""
        normalized_location = finding.location.lstrip('/').strip()
        cve_id = finding.cve_id or self._extract_cve_from_title(finding.title)

        if cve_id:
            package_info = self._extract_package_info(finding.title, finding.evidence)
            return (
                finding.vulnerability_type,
                cve_id,
                package_info,
                normalized_location
            )
        else:
            return (
                finding.vulnerability_type,
                normalized_location,
                finding.title.lower().strip()
            )

    def _extract_user_centric_findings(self, findings: List[Finding]) -> List[Finding]:
        """Extract findings that directly impact MCP server users"""
        # Import the categories from enhanced scoring
        from enhanced_scoring import EnhancedSecurityScorer
        
        scorer = EnhancedSecurityScorer()
        user_centric = []
        
        for finding in findings:
            if finding.confidence < 0.5:  # Skip low confidence
                continue
                
            vuln_type = finding.vulnerability_type
            
            # Check if this is a user-impacting vulnerability
            if (vuln_type in scorer.MCP_EXPLOITABLE_CRITICAL or 
                vuln_type in scorer.MCP_RELATED_HIGH or 
                vuln_type in scorer.INDIRECT_USER_IMPACT):
                user_centric.append(finding)
        
        return user_centric
    
    def _generate_summary(
        self,
        findings: List[Finding],
        enhanced_scores: Dict[str, Any]
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

        # Add enhanced scoring information
        user_safety = enhanced_scores['user_safety']
        developer_security = enhanced_scores['developer_security']
        summary_info = enhanced_scores['summary']
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'vulnerability_types': type_counts,
            
            # MCP-specific information
            'mcp_exploitable_issues': summary_info['mcp_exploitable'],
            'requires_immediate_attention': summary_info['requires_immediate_attention'],
            'scan_completeness': summary_info['scan_completeness'],
            
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
    
    def _aggregate_for_enhanced_scoring(self, findings: List[Finding]) -> List[Finding]:
        """Apply enhanced aggregation logic for dual scoring system"""
        # Group related findings for better scoring
        aggregated_findings = []
        
        # Group findings by vulnerability type and location for potential merging
        vulnerability_groups = {}
        
        for finding in findings:
            # Create a group key based on vulnerability type and general location
            location_base = finding.location.split(':')[0] if ':' in finding.location else finding.location
            group_key = f"{finding.vulnerability_type.value}:{location_base}"
            
            if group_key not in vulnerability_groups:
                vulnerability_groups[group_key] = []
            vulnerability_groups[group_key].append(finding)
        
        # Process each group
        for group_key, group_findings in vulnerability_groups.items():
            if len(group_findings) == 1:
                # Single finding - add as is
                aggregated_findings.extend(group_findings)
            else:
                # Multiple findings - check if they should be merged
                merged_finding = self._merge_related_findings(group_findings)
                if merged_finding:
                    aggregated_findings.append(merged_finding)
                else:
                    # Keep separate if merging not appropriate
                    aggregated_findings.extend(group_findings)
        
        logger.info(f"Aggregated {len(findings)} findings into {len(aggregated_findings)} for enhanced scoring")
        return aggregated_findings
    
    def _merge_related_findings(self, findings: List[Finding]) -> Optional[Finding]:
        """Merge related findings if appropriate for enhanced scoring"""
        if not findings:
            return None
        
        # Only merge if they're the same vulnerability type and similar severity
        base_finding = findings[0]
        vuln_type = base_finding.vulnerability_type
        
        # Check if all findings are similar enough to merge
        similar_findings = [
            f for f in findings 
            if f.vulnerability_type == vuln_type 
            and abs(f.confidence - base_finding.confidence) <= 0.2  # Similar confidence
        ]
        
        if len(similar_findings) < len(findings):
            return None  # Don't merge if findings are too different
        
        # Select the highest severity and confidence
        best_finding = max(findings, key=lambda f: (
            {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}[f.severity.value],
            f.confidence
        ))
        
        # Create merged finding with combined evidence
        merged_evidence = {}
        all_locations = set()
        all_references = set()
        
        for finding in findings:
            if finding.evidence:
                merged_evidence.update(finding.evidence)
            all_locations.add(finding.location)
            all_references.update(finding.references)
        
        # Add instance count to evidence
        merged_evidence['instance_count'] = len(findings)
        merged_evidence['all_locations'] = list(all_locations)
        
        # Create the merged finding
        merged_finding = Finding(
            vulnerability_type=best_finding.vulnerability_type,
            severity=best_finding.severity,
            confidence=min(1.0, best_finding.confidence + 0.1),  # Slight confidence boost for multiple instances
            title=f"{best_finding.title} (Found in {len(findings)} locations)",
            description=best_finding.description,
            location=best_finding.location,  # Use the primary location
            recommendation=best_finding.recommendation,
            references=list(all_references),
            evidence=merged_evidence,
            tool=best_finding.tool,
            cwe_id=best_finding.cwe_id,
            cve_id=best_finding.cve_id
        )
        
        return merged_finding