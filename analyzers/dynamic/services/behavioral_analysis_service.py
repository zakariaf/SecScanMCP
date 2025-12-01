"""Behavioral analysis service for dynamic analysis."""

import asyncio
import logging
import time
from typing import List, Dict, Any

from models import Finding

from .metrics_collection_service import MetricsCollectionService
from .anomaly_detection_service import AnomalyDetectionService
from .performance_pattern_service import PerformancePatternService
from .behavior_data_service import BehaviorDataService

logger = logging.getLogger(__name__)


class BehavioralAnalysisService:
    """Orchestrates ML-based behavioral analysis for MCP servers."""

    BEHAVIOR_DURATION = 30  # seconds
    METRICS_INTERVAL = 2   # seconds

    def __init__(self):
        self.analysis_session = {}
        self.metrics_service = MetricsCollectionService()
        self.anomaly_service = AnomalyDetectionService()
        self.performance_service = PerformancePatternService()
        self.behavior_data_service = BehaviorDataService()

    async def analyze_behavior(self, mcp_client, container_id: str) -> List[Finding]:
        """Analyze MCP server behavior for anomalies."""
        findings = []
        try:
            behavior_data = await self.behavior_data_service.collect_behavior_data(mcp_client)
            findings.extend(self.behavior_data_service.analyze_response_times(behavior_data))
            findings.extend(self.behavior_data_service.analyze_error_rates(behavior_data))

            container = await self._get_container(container_id)
            if container:
                findings.extend(await self._run_advanced_analysis(container))

            logger.info(f"Behavioral analysis completed with {len(findings)} findings")
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
        return findings

    async def _get_container(self, container_id: str):
        """Get Docker container for advanced monitoring."""
        try:
            import docker
            return docker.from_env().containers.get(container_id)
        except Exception:
            return None

    async def _run_advanced_analysis(self, container) -> List[Finding]:
        """Run advanced behavioral analysis with metrics collection."""
        findings = []
        logger.info("Running advanced behavioral analysis...")

        metrics = await self._collect_metrics_over_time(container)
        if metrics:
            findings.extend(await self.anomaly_service.detect_anomalies(metrics))
            findings.extend(await self.performance_service.analyze_patterns(metrics))
            self._store_metrics(metrics)

        logger.info(f"Advanced analysis found {len(findings)} anomalies")
        return findings

    async def _collect_metrics_over_time(self, container) -> List[Dict[str, Any]]:
        """Collect metrics over the behavior duration period."""
        metrics = []
        start_time = time.time()
        while time.time() - start_time < self.BEHAVIOR_DURATION:
            snapshot = await self.metrics_service.collect_snapshot(container)
            if snapshot:
                metrics.append(snapshot)
            await asyncio.sleep(self.METRICS_INTERVAL)
        return metrics

    def _store_metrics(self, metrics: List[Dict[str, Any]]) -> None:
        """Store metrics in analysis session."""
        if 'metrics_history' not in self.analysis_session:
            self.analysis_session['metrics_history'] = []
        self.analysis_session['metrics_history'].extend(metrics)

    async def run_ml_anomaly_detection(self, metrics_history: List[Dict[str, Any]]) -> List[Finding]:
        """Run ML-based anomaly detection on behavioral data."""
        if len(metrics_history) < 10:
            logger.info("Insufficient data for ML anomaly detection")
            return []
        logger.info("Running ML-based anomaly detection...")
        findings = await self.anomaly_service.detect_anomalies(metrics_history)
        findings.extend(await self.performance_service.analyze_patterns(metrics_history))
        logger.info(f"ML anomaly detection found {len(findings)} anomalies")
        return findings
