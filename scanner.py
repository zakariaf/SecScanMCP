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
    DynamicAnalyzer,
    ClamAVAnalyzer,  # Military-grade malware detection
    YARAAnalyzer,    # Advanced pattern matching
    CodeQLAnalyzer   # Semantic code analysis
)
from models import Finding, ScanResult
from enhanced_scoring import EnhancedSecurityScorer
from mcp_detector import MCPDetector

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
            'dynamic': DynamicAnalyzer(),    # Behavioral analysis
            'clamav': ClamAVAnalyzer(),       # Military-grade malware detection
            'yara': YARAAnalyzer(),          # Advanced pattern matching
            'codeql': CodeQLAnalyzer()       # Semantic code analysis
        }

        self.enhanced_scorer = EnhancedSecurityScorer()
        self.mcp_detector = MCPDetector()

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
        
        # Separate user-centric and developer-centric findings
        user_centric_findings = self._extract_user_centric_findings(findings)
        developer_centric_findings = self._extract_developer_centric_findings(findings)

        # Build result
        result = ScanResult(
            repository_url=repository_url,
            project_type=project_info['type'],
            is_mcp_server=project_info['is_mcp'],
            findings=findings,
            user_centric_findings=user_centric_findings,
            developer_centric_findings=developer_centric_findings,
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

    def _parse_github_url(self, url: str) -> Dict[str, str]:
        """Parse GitHub URL to extract repo info and subdirectory path"""
        # Handle different GitHub URL formats
        patterns = [
            # https://github.com/owner/repo/tree/branch/path/to/dir
            r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.+)',
            # https://github.com/owner/repo/tree/branch
            r'github\.com/([^/]+)/([^/]+)/tree/([^/]+)/?$',
            # https://github.com/owner/repo
            r'github\.com/([^/]+)/([^/]+)/?$'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                groups = match.groups()
                result = {
                    'owner': groups[0],
                    'repo': groups[1],
                    'git_url': f"https://github.com/{groups[0]}/{groups[1]}.git"
                }
                
                if len(groups) >= 3:
                    result['branch'] = groups[2]
                else:
                    result['branch'] = None  # Let git determine the default branch
                    
                if len(groups) >= 4:
                    result['subdirectory'] = groups[3]
                else:
                    result['subdirectory'] = None
                    
                return result
        
        # If not a GitHub URL, treat as regular git URL
        # But if it contains github.com, it might be a malformed GitHub URL
        if 'github.com' in url:
            # This might be a GitHub URL that didn't match our patterns
            # Log a warning and try to handle it as a regular repo
            logger.warning(f"GitHub URL didn't match expected patterns: {url}")
            
        return {
            'git_url': url,
            'branch': None,  # Let git determine the default branch
            'subdirectory': None
        }

    async def _clone_repository(self, repo_url: str, target_dir: str) -> str:
        """Clone repository with security constraints and subdirectory support"""
        try:
            # Parse URL to handle GitHub subdirectories
            url_info = self._parse_github_url(repo_url)
            git_url = url_info['git_url']
            subdirectory = url_info.get('subdirectory')
            specified_branch = url_info.get('branch') if 'tree/' in repo_url else None
            
            # If no branch specified, use repository's default branch
            if not specified_branch:
                # Clone without specifying branch - git will use the repo's default
                clone_cmd = [
                    'git', 'clone',
                    '--depth', '1',
                    '--single-branch',
                    '--no-tags',
                    git_url,
                    target_dir
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *clone_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    logger.info(f"Successfully cloned repository using default branch")
                else:
                    error_msg = stderr.decode()
                    raise RuntimeError(f"Git clone failed: {error_msg}")
            else:
                # Branch specified in URL - try that specific branch
                clone_cmd = [
                    'git', 'clone',
                    '--depth', '1',
                    '--single-branch',
                    '--branch', specified_branch,
                    '--no-tags',
                    git_url,
                    target_dir
                ]
                
                process = await asyncio.create_subprocess_exec(
                    *clone_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode == 0:
                    logger.info(f"Successfully cloned repository using branch '{specified_branch}'")
                else:
                    error_msg = stderr.decode()
                    # If specified branch fails, try without branch as fallback
                    logger.warning(f"Clone failed with branch '{specified_branch}': {error_msg}")
                    logger.info("Attempting to clone with repository's default branch as fallback")
                    
                    # Clean up failed attempt
                    if Path(target_dir).exists():
                        import shutil
                        shutil.rmtree(target_dir, ignore_errors=True)
                    
                    # Try without specifying branch
                    clone_cmd = [
                        'git', 'clone',
                        '--depth', '1',
                        '--single-branch',
                        '--no-tags',
                        git_url,
                        target_dir
                    ]
                    
                    process = await asyncio.create_subprocess_exec(
                        *clone_cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    
                    stdout, stderr = await process.communicate()
                    
                    if process.returncode == 0:
                        logger.info(f"Successfully cloned repository using default branch (fallback)")
                    else:
                        last_error = stderr.decode()
                        raise RuntimeError(f"Git clone failed with specified branch '{specified_branch}' and default branch. Last error: {last_error}")

            # If subdirectory is specified, focus analysis on that directory
            if subdirectory:
                subdir_path = Path(target_dir) / subdirectory
                if subdir_path.exists() and subdir_path.is_dir():
                    logger.info(f"Focusing analysis on subdirectory: {subdirectory}")
                    return str(subdir_path)
                else:
                    logger.warning(f"Subdirectory {subdirectory} not found, analyzing full repository")

            logger.info(f"Successfully cloned repository to {target_dir}")
            return target_dir

        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            raise

    async def _analyze_project(self, repo_path: str) -> Dict[str, Any]:
        """Detect project type and MCP configuration using dedicated MCP detector"""
        try:
            project_info = await self.mcp_detector.analyze_project(repo_path)
            
            # Log detection results
            if project_info.get('is_mcp'):
                confidence_explanation = self.mcp_detector.get_detection_confidence_explanation(project_info)
                logger.info(f"MCP server detected: {confidence_explanation}")
                
                # Log detected packages if available
                detected_packages = project_info.get('detected_packages', [])
                if detected_packages:
                    logger.info(f"Detected MCP packages: {detected_packages}")
            else:
                logger.info(f"Project type: {project_info['type']} ({project_info['language'] or 'unknown language'}), MCP: No")
            
            return project_info
            
        except Exception as e:
            logger.error(f"Project analysis failed: {e}")
            # Return minimal project info on failure
            return {
                'type': 'unknown',
                'language': None,
                'is_mcp': False,
                'mcp_config': None,
                'dependencies': [],
                'detection_method': 'analysis_failed',
                'confidence': 0.0
            }

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

        if total_before > 0:
            reduction_percent = (total_before-len(unique_findings))/total_before*100
            logger.info(f"Deduplicated {total_before} findings down to {len(unique_findings)} ({reduction_percent:.1f}% reduction)")
        else:
            logger.info(f"No findings to deduplicate (0 findings found)")
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
    
    def _extract_developer_centric_findings(self, findings: List[Finding]) -> List[Finding]:
        """Extract findings that are developer-side security issues"""
        # Import the categories from enhanced scoring
        from enhanced_scoring import EnhancedSecurityScorer
        
        scorer = EnhancedSecurityScorer()
        developer_centric = []
        
        for finding in findings:
            if finding.confidence < 0.5:  # Skip low confidence
                continue
                
            vuln_type = finding.vulnerability_type
            
            # Check if this is a developer-side issue
            if vuln_type in scorer.DEVELOPER_CONCERNS:
                developer_centric.append(finding)
        
        return developer_centric
    
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