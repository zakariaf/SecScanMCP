"""Finding management service for deduplication and organization."""

import re
import logging
from typing import List, Dict, Any, Optional
from collections import defaultdict

from models import Finding, VulnerabilityType
from enhanced_scoring import EnhancedSecurityScorer

logger = logging.getLogger(__name__)


class FindingService:
    """Handles finding deduplication, merging, and organization."""
    
    # Tool priority for vulnerability types
    TOOL_PRIORITY = {
        'hardcoded_secret': {'trufflehog': 3, 'trivy': 2, 'bandit': 1},
        'command_injection': {'mcpspecific': 4, 'codeql': 3, 'dynamic': 2, 'bandit': 1},
        'prompt_injection': {'mcpspecific': 4, 'mcp_specific': 4, 'codeql': 2, 'opengrep': 1},
        'vulnerable_dependency': {'trivy': 3, 'grype': 2, 'syft': 1},
        'sql_injection': {'codeql': 3, 'bandit': 2, 'opengrep': 1},
        'generic': {'yara': 2, 'clamav': 3, 'opengrep': 1},
    }
    
    def __init__(self):
        self.scorer = EnhancedSecurityScorer()
    
    def deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove duplicate findings with improved logic and tool priority.
        
        Args:
            findings: List of raw findings
            
        Returns:
            Deduplicated list of findings
        """
        grouped = self._group_findings(findings)
        unique_findings = self._select_best_findings(grouped)
        
        self._log_deduplication_stats(len(findings), len(unique_findings))
        return unique_findings
    
    def _group_findings(self, findings: List[Finding]) -> Dict:
        """Group findings by unique key."""
        grouped = defaultdict(list)
        
        for finding in findings:
            key = self._generate_finding_key(finding)
            grouped[key].append(finding)
        
        return grouped
    
    def _generate_finding_key(self, finding: Finding) -> tuple:
        """Generate unique key for finding."""
        normalized_location = finding.location.lstrip('/').strip()
        cve_id = finding.cve_id or self._extract_cve_from_title(finding.title)
        
        if cve_id:
            package_info = self._extract_package_info(finding.title, finding.evidence)
            return (finding.vulnerability_type, cve_id, package_info)
        else:
            return (finding.vulnerability_type, normalized_location)
    
    def _select_best_findings(self, grouped: Dict) -> List[Finding]:
        """Select best finding from each group."""
        unique_findings = []
        
        for findings_group in grouped.values():
            if len(findings_group) == 1:
                unique_findings.extend(findings_group)
            else:
                best_finding = self._pick_best_finding(findings_group)
                self._merge_evidence(best_finding, findings_group)
                unique_findings.append(best_finding)
        
        return unique_findings
    
    def _pick_best_finding(self, findings: List[Finding]) -> Finding:
        """Pick the best finding from a group based on tool priority."""
        vuln_type = findings[0].vulnerability_type.value
        priorities = self.TOOL_PRIORITY.get(vuln_type, {})
        
        return max(findings, key=lambda f: (
            priorities.get(f.tool, 0),
            f.confidence,
            f.severity == 'critical'
        ))
    
    def _merge_evidence(self, best: Finding, group: List[Finding]) -> None:
        """Merge evidence from related findings."""
        other_findings = [f for f in group if f != best]
        
        for other in other_findings:
            if other.confidence >= 0.7 and other.evidence:
                best.evidence.update({
                    f"{other.tool}_evidence": other.evidence
                })
    
    def _extract_cve_from_title(self, title: str) -> str:
        """Extract CVE ID from finding title."""
        match = re.search(r'CVE-\d{4}-\d+', title, re.IGNORECASE)
        return match.group(0).upper() if match else ''
    
    def _extract_package_info(self, title: str, evidence: Dict) -> str:
        """Extract package name and version."""
        # Try evidence first
        if evidence.get('package'):
            version = evidence.get('version') or evidence.get('installed_version')
            if version:
                return f"{evidence['package']}@{version}"
        
        # Fallback to title parsing
        match = re.search(r':\s*([a-zA-Z0-9\-_\.]+)\s+([\d\.]+)', title)
        if match:
            package, version = match.groups()
            return f"{package}@{version}"
        
        return title.split(':')[-1].strip() if ':' in title else title
    
    def _log_deduplication_stats(self, before: int, after: int) -> None:
        """Log deduplication statistics."""
        if before > 0:
            reduction = (before - after) / before * 100
            logger.info(
                f"Deduplicated {before} findings to {after} "
                f"({reduction:.1f}% reduction)"
            )
        else:
            logger.info("No findings to deduplicate")
    
    def extract_user_centric_findings(self, findings: List[Finding]) -> List[Finding]:
        """Extract findings that directly impact MCP server users."""
        user_centric = []
        
        for finding in findings:
            if finding.confidence < 0.5:
                continue
            
            vuln_type = finding.vulnerability_type
            
            if (vuln_type in self.scorer.MCP_EXPLOITABLE_CRITICAL or
                vuln_type in self.scorer.MCP_RELATED_HIGH or
                vuln_type in self.scorer.INDIRECT_USER_IMPACT):
                user_centric.append(finding)
        
        return user_centric
    
    def extract_developer_centric_findings(self, findings: List[Finding]) -> List[Finding]:
        """Extract findings that are developer-side security issues."""
        developer_centric = []
        
        for finding in findings:
            if finding.confidence < 0.5:
                continue
            
            if finding.vulnerability_type in self.scorer.DEVELOPER_CONCERNS:
                developer_centric.append(finding)
        
        return developer_centric
    
    def organize_by_analyzer(self, findings: List[Finding]) -> Dict[str, List[Dict]]:
        """Organize findings by analyzer tool."""
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