"""Analysis pipeline service for dynamic analysis."""

import logging
from typing import List, Dict, Any

from models import Finding

logger = logging.getLogger(__name__)


class AnalysisPipelineService:
    """Runs the complete analysis pipeline."""

    def __init__(
        self,
        security_testing,
        traffic_analysis,
        behavioral_analysis,
        performance_monitoring,
    ):
        self.security_testing = security_testing
        self.traffic_analysis = traffic_analysis
        self.behavioral_analysis = behavioral_analysis
        self.performance_monitoring = performance_monitoring

    async def run_all_analyses(self, session: Dict[str, Any]) -> List[Finding]:
        """Run all analysis phases."""
        findings = []
        findings.extend(await self._run_security(session))
        findings.extend(await self._run_traffic(session))
        findings.extend(await self._run_behavioral(session))
        findings.extend(await self._run_performance(session))
        return findings

    async def _run_security(self, session: Dict[str, Any]) -> List[Finding]:
        """Run security testing."""
        if not session.get('mcp_client'):
            return []
        return await self.security_testing.run_comprehensive_tests(
            session['mcp_client']
        )

    async def _run_traffic(self, session: Dict[str, Any]) -> List[Finding]:
        """Run network traffic analysis."""
        if not session.get('container_id'):
            return []
        findings = []
        findings.extend(await self.traffic_analysis.analyze_traffic(
            session['container_id']
        ))
        findings.extend(await self.traffic_analysis.analyze_network_traffic())
        findings.extend(await self.traffic_analysis.detect_data_exfiltration())
        return findings

    async def _run_behavioral(self, session: Dict[str, Any]) -> List[Finding]:
        """Run behavioral anomaly detection."""
        if not session.get('mcp_client'):
            return []
        findings = []
        findings.extend(await self.behavioral_analysis.analyze_behavior(
            session['mcp_client'], session.get('container_id')
        ))
        metrics = session.get('metrics_history', [])
        if metrics:
            findings.extend(
                await self.behavioral_analysis.run_ml_anomaly_detection(metrics)
            )
        return findings

    async def _run_performance(self, session: Dict[str, Any]) -> List[Finding]:
        """Run performance monitoring."""
        if not session.get('container_id'):
            return []
        return await self.performance_monitoring.analyze_performance(
            session['container_id']
        )
