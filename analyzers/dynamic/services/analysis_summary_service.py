"""Analysis summary service for dynamic analysis."""

import time
import logging
from typing import List, Dict, Any

from models import Finding

logger = logging.getLogger(__name__)


class AnalysisSummaryService:
    """Generates summaries for dynamic analysis results."""

    SEVERITY_EMOJIS = {
        'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'
    }

    def generate_summary(
        self, findings: List[Finding], start_time: float = None
    ) -> str:
        """Generate a comprehensive summary of analysis results."""
        if not findings:
            return "🟢 Dynamic analysis completed - No security issues detected"

        try:
            severity_counts = self._count_severities(findings)
            vuln_counts = self._count_vulnerability_types(findings)
            return self._build_summary(
                severity_counts, vuln_counts, start_time
            )
        except Exception as e:
            logger.error(f"Failed to generate analysis summary: {e}")
            return f"📊 Dynamic analysis completed with {len(findings)} findings"

    def _count_severities(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in findings:
            sev = finding.severity.value
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _count_vulnerability_types(self, findings: List[Finding]) -> Dict[str, int]:
        """Count findings by vulnerability type."""
        counts = {}
        for finding in findings:
            vtype = finding.vulnerability_type.value
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts

    def _build_summary(
        self, severity_counts: Dict[str, int],
        vuln_counts: Dict[str, int], start_time: float
    ) -> str:
        """Build the summary string."""
        parts = ["📊 Dynamic Analysis Summary:"]
        parts.extend(self._format_severity_section(severity_counts))
        parts.extend(self._format_vuln_section(vuln_counts))
        parts.extend(self._format_duration(start_time))
        parts.extend(self._format_recommendations(severity_counts))
        return "\n".join(parts)

    def _format_severity_section(self, counts: Dict[str, int]) -> List[str]:
        """Format severity distribution section."""
        if not counts:
            return []
        lines = ["🎯 Severity Distribution:"]
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = counts.get(sev, 0)
            if count > 0:
                emoji = self.SEVERITY_EMOJIS.get(sev, '⚪')
                lines.append(f"  {emoji} {sev}: {count}")
        return lines

    def _format_vuln_section(self, counts: Dict[str, int]) -> List[str]:
        """Format top vulnerability types section."""
        if not counts:
            return []
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        lines = ["🚨 Top Vulnerability Types:"]
        for vtype, count in top:
            lines.append(f"  • {vtype}: {count}")
        return lines

    def _format_duration(self, start_time: float) -> List[str]:
        """Format analysis duration."""
        if not start_time:
            return []
        duration = time.time() - start_time
        return [f"⏱️ Analysis Duration: {duration:.1f}s"]

    def _format_recommendations(self, severity_counts: Dict[str, int]) -> List[str]:
        """Format recommendations based on findings."""
        critical_high = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
        if critical_high > 0:
            return [f"⚠️ IMMEDIATE ACTION REQUIRED: {critical_high} critical/high severity issues"]
        return []
