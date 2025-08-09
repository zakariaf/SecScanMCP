"""Finding aggregation service for enhanced scoring."""

import logging
from typing import List, Optional

from models import Finding

logger = logging.getLogger(__name__)


class FindingAggregator:
    """Aggregates and merges related findings for enhanced scoring."""
    
    def aggregate_for_scoring(self, findings: List[Finding]) -> List[Finding]:
        """
        Apply enhanced aggregation logic for dual scoring system.
        
        Args:
            findings: Deduplicated findings
            
        Returns:
            Aggregated findings ready for scoring
        """
        vulnerability_groups = self._group_by_vulnerability(findings)
        aggregated_findings = self._process_groups(vulnerability_groups)
        
        logger.info(
            f"Aggregated {len(findings)} findings into "
            f"{len(aggregated_findings)} for enhanced scoring"
        )
        
        return aggregated_findings
    
    def _group_by_vulnerability(self, findings: List[Finding]) -> dict:
        """Group findings by vulnerability type and location."""
        groups = {}
        
        for finding in findings:
            location_base = finding.location.split(':')[0] if ':' in finding.location else finding.location
            group_key = f"{finding.vulnerability_type.value}:{location_base}"
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(finding)
        
        return groups
    
    def _process_groups(self, groups: dict) -> List[Finding]:
        """Process each group of findings."""
        aggregated = []
        
        for group_findings in groups.values():
            if len(group_findings) == 1:
                aggregated.extend(group_findings)
            else:
                merged = self._merge_if_appropriate(group_findings)
                if merged:
                    aggregated.append(merged)
                else:
                    aggregated.extend(group_findings)
        
        return aggregated
    
    def _merge_if_appropriate(self, findings: List[Finding]) -> Optional[Finding]:
        """Merge related findings if appropriate."""
        if not findings:
            return None
        
        base = findings[0]
        
        # Check if findings are similar enough to merge
        if not self._are_similar(findings, base):
            return None
        
        # Select best finding and merge evidence
        best = self._select_best(findings)
        self._merge_evidence(best, findings)
        
        return best
    
    def _are_similar(self, findings: List[Finding], base: Finding) -> bool:
        """Check if findings are similar enough to merge."""
        for finding in findings:
            if (finding.vulnerability_type != base.vulnerability_type or
                abs(finding.confidence - base.confidence) > 0.2):
                return False
        return True
    
    def _select_best(self, findings: List[Finding]) -> Finding:
        """Select the best finding from a group."""
        severity_values = {
            'critical': 5, 'high': 4, 'medium': 3, 
            'low': 2, 'info': 1
        }
        
        best = max(findings, key=lambda f: (
            severity_values.get(f.severity.value, 0),
            f.confidence
        ))
        
        # Create a copy with updated title
        return Finding(
            vulnerability_type=best.vulnerability_type,
            severity=best.severity,
            confidence=min(1.0, best.confidence + 0.1),
            title=f"{best.title} (Found in {len(findings)} locations)",
            description=best.description,
            location=best.location,
            recommendation=best.recommendation,
            references=best.references,
            evidence=best.evidence.copy() if best.evidence else {},
            tool=best.tool,
            cwe_id=best.cwe_id,
            cve_id=best.cve_id
        )
    
    def _merge_evidence(self, best: Finding, findings: List[Finding]) -> None:
        """Merge evidence from all findings."""
        all_locations = set()
        all_references = set()
        
        for finding in findings:
            if finding.evidence:
                best.evidence.update(finding.evidence)
            all_locations.add(finding.location)
            all_references.update(finding.references)
        
        best.evidence['instance_count'] = len(findings)
        best.evidence['all_locations'] = list(all_locations)
        best.references = list(all_references)