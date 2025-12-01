"""Component analysis runner service."""

import time
import logging
from typing import Dict, Any

from ..models.analysis_models import CodeContext
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class ComponentRunnerService:
    """Runs component analyses with timing."""

    def __init__(self, semantic, behavioral, ecosystem, anomaly):
        self.semantic_analyzer = semantic
        self.behavioral_analyzer = behavioral
        self.ecosystem_analyzer = ecosystem
        self.anomaly_detector = anomaly

    async def run_all(self, context: CodeContext) -> Dict[str, Any]:
        """Run all component analyses with timing."""
        results = {}
        durations = {}

        results['semantic'], durations['semantic'] = await self._run_analysis(
            'semantic', self.semantic_analyzer, context
        )
        results['behavioral'], durations['behavioral'] = await self._run_analysis(
            'behavioral', self.behavioral_analyzer, context
        )
        results['ecosystem'], durations['ecosystem'] = await self._run_analysis(
            'ecosystem', self.ecosystem_analyzer, context
        )
        results['anomaly'], durations['anomaly'] = await self._run_analysis(
            'anomaly', self.anomaly_detector, context
        )

        self._log_completion(durations)
        return results

    async def _run_analysis(
        self, name: str, analyzer: Any, context: CodeContext
    ) -> tuple:
        """Run a single component analysis."""
        start = time.time()
        score, evidence = await analyzer.analyze(context)
        duration = time.time() - start

        logger.debug(
            f"{name.capitalize()} analysis completed",
            component=f"{name}_analyzer",
            score=score,
            duration_ms=int(duration * 1000)
        )
        return (score, evidence), duration

    def _log_completion(self, durations: Dict[str, float]):
        """Log completion of all analyses."""
        total = sum(durations.values())
        logger.info(
            "All component analyses completed",
            total_duration_ms=int(total * 1000),
            semantic_duration_ms=int(durations['semantic'] * 1000),
            behavioral_duration_ms=int(durations['behavioral'] * 1000),
            ecosystem_duration_ms=int(durations['ecosystem'] * 1000),
            anomaly_duration_ms=int(durations['anomaly'] * 1000)
        )
