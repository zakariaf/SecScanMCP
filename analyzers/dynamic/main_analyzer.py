"""Main dynamic analyzer orchestrator with clean architecture."""

import time
import logging
from typing import List, Dict, Any

from models import Finding
from analyzers.base import BaseAnalyzer

from .managers.docker_manager import DockerManager
from .managers.mcp_connection_manager import MCPConnectionManager
from .services import (
    SecurityTestingService, TrafficAnalysisService,
    BehavioralAnalysisService, PerformanceMonitoringService,
    RuntimeDetectionService, AnalysisSummaryService,
    AnalysisPipelineService, CleanupService,
)

logger = logging.getLogger(__name__)


class DynamicAnalyzer(BaseAnalyzer):
    """Advanced Dynamic Analysis Engine for MCP Servers."""

    def __init__(self):
        super().__init__()
        self.session = {
            'start_time': None, 'container_id': None,
            'mcp_client': None, 'findings': [], 'metrics_history': []
        }
        self._init_components()

    def _init_components(self):
        """Initialize all managers and services."""
        self.docker_manager = DockerManager()
        self.connection_manager = MCPConnectionManager()
        self.runtime_detection = RuntimeDetectionService()
        self.summary_service = AnalysisSummaryService()
        self.cleanup_service = CleanupService(
            self.docker_manager, self.connection_manager
        )
        self._init_pipeline()

    def _init_pipeline(self):
        """Initialize analysis pipeline with services."""
        security = SecurityTestingService()
        traffic = TrafficAnalysisService()
        behavioral = BehavioralAnalysisService()
        performance = PerformanceMonitoringService()
        traffic.analysis_session = self.session
        behavioral.analysis_session = self.session
        self.pipeline = AnalysisPipelineService(
            security, traffic, behavioral, performance
        )

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Check if dynamic analysis should be performed."""
        return (
            project_info.get('is_mcp_server', False) and
            project_info.get('enable_dynamic_analysis', True)
        )

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Comprehensive dynamic security analysis."""
        if not self.is_applicable(project_info):
            return []

        self.session['start_time'] = time.time()
        findings = []

        try:
            findings = await self._run_analysis(repo_path, project_info)
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
            await self.cleanup_service.emergency_cleanup(self.session)
        finally:
            await self.cleanup_service.cleanup(self.session)

        self._log_summary(findings)
        return findings

    async def _run_analysis(
        self, repo_path: str, project_info: Dict[str, Any]
    ) -> List[Finding]:
        """Run the complete analysis pipeline."""
        if not await self.docker_manager.initialize_environment():
            return []

        runtime = self.runtime_detection.determine_runtime(project_info, repo_path)
        if not runtime:
            return []

        container = await self.docker_manager.create_sandbox(repo_path, runtime)
        if not container:
            return []
        self.session['container_id'] = container.id

        client = await self.connection_manager.establish_connection(container, runtime)
        if not client:
            return []
        self.session['mcp_client'] = client

        return await self.pipeline.run_all_analyses(self.session)

    def _log_summary(self, findings: List[Finding]):
        """Log analysis summary."""
        summary = self.summary_service.generate_summary(
            findings, self.session.get('start_time')
        )
        logger.info(summary)
        logger.info(f"Dynamic analysis completed with {len(findings)} findings")
