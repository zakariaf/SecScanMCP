"""Result building service for scan results."""

import logging
from typing import List, Dict, Any

from models import Finding, ScanResult
from enhanced_scoring import EnhancedSecurityScorer

logger = logging.getLogger(__name__)


class ResultBuilder:
    """Builds and formats scan results."""
    
    def __init__(self):
        self.scorer = EnhancedSecurityScorer()
    
    def build_result(self, repository_url: str, project_info: Dict[str, Any],
                    findings: List[Finding], enhanced_scores: Dict[str, Any],
                    user_centric: List[Finding], developer_centric: List[Finding],
                    organized_findings: Dict, scan_options: Dict) -> ScanResult:
        """
        Build complete scan result.
        
        Args:
            repository_url: Repository URL
            project_info: Project information
            findings: All findings
            enhanced_scores: Enhanced scoring results
            user_centric: User-centric findings
            developer_centric: Developer-centric findings
            organized_findings: Findings organized by tool
            scan_options: Scan configuration
            
        Returns:
            Complete scan result
        """
        summary = self._generate_summary(findings, enhanced_scores)
        
        return ScanResult(
            repository_url=repository_url,
            project_type=project_info['type'],
            is_mcp_server=project_info['is_mcp'],
            findings=findings,
            user_centric_findings=user_centric,
            developer_centric_findings=developer_centric,
            security_score=enhanced_scores['user_safety']['score'],
            security_grade=enhanced_scores['user_safety']['grade'],
            enhanced_scores=enhanced_scores,
            summary=summary,
            detailed_results=organized_findings,
            scan_metadata={
                'analyzers_run': list(organized_findings.keys()),
                'project_info': project_info,
                'options': scan_options
            }
        )
    
    def _generate_summary(self, findings: List[Finding], 
                         enhanced_scores: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary."""
        severity_counts = self._count_severities(findings)
        type_counts = self._count_vulnerability_types(findings)
        summary_info = enhanced_scores['summary']
        
        return {
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'vulnerability_types': type_counts,
            'mcp_exploitable_issues': summary_info['mcp_exploitable'],
            'requires_immediate_attention': summary_info['requires_immediate_attention'],
            'scan_completeness': summary_info['scan_completeness'],
            'top_risks': self._get_top_risks(findings)
        }
    
    def _count_severities(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        for finding in findings:
            counts[finding.severity] += 1
        
        return counts
    
    def _count_vulnerability_types(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        type_counts = {}
        
        for finding in findings:
            vuln_type = finding.vulnerability_type
            if vuln_type not in type_counts:
                type_counts[vuln_type] = 0
            type_counts[vuln_type] += 1
        
        return type_counts
    
    def _get_top_risks(self, findings: List[Finding], limit: int = 3) -> List[Dict]:
        """Get top risk findings."""
        severity_order = {
            'critical': 0, 'high': 1, 'medium': 2, 
            'low': 3, 'info': 4
        }
        
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