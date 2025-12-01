"""Main intelligent context analyzer orchestrator."""

import logging
from pathlib import Path

from .models.analysis_models import CodeContext, LegitimacyAnalysis
from .models.risk_models import ComponentScores
from .components.semantic_analyzer import SemanticIntentAnalyzer
from .components.behavioral_analyzer import BehavioralPatternAnalyzer
from .components.ecosystem_analyzer import EcosystemIntelligenceAnalyzer
from .components.anomaly_detector import AnomalyDetector
from .services import (
    RiskAggregator, LearningSystem, ComponentRunnerService, SynthesisService
)
from .utils.config_manager import ConfigManager
from .utils.logging_utils import get_scan_logger, scan_id_context

logger = get_scan_logger(__name__)


class IntelligentContextAnalyzer:
    """Main orchestrator for intelligent context-aware security analysis."""

    def __init__(self, model_path: str = "/tmp/security_ml_models", config_path: str = None):
        self.config_manager = ConfigManager(Path(config_path) if config_path else None)
        self._init_components()
        self._init_services(model_path)
        logger.info("Intelligent Context Analyzer initialized with modular architecture")

    def _init_components(self):
        """Initialize analyzer components."""
        self.semantic_analyzer = SemanticIntentAnalyzer()
        self.behavioral_analyzer = BehavioralPatternAnalyzer()
        self.ecosystem_analyzer = EcosystemIntelligenceAnalyzer()
        self.anomaly_detector = AnomalyDetector(self.config_manager)

    def _init_services(self, model_path: str):
        """Initialize services."""
        self.risk_aggregator = RiskAggregator(self.config_manager)
        self.learning_system = LearningSystem(model_path)
        self.synthesis_service = SynthesisService()
        self.component_runner = ComponentRunnerService(
            self.semantic_analyzer, self.behavioral_analyzer,
            self.ecosystem_analyzer, self.anomaly_detector
        )

    async def analyze_legitimacy(self, context: CodeContext) -> LegitimacyAnalysis:
        """Main analysis orchestration method."""
        analysis_id = self._create_analysis_id(context)
        token = scan_id_context.set(analysis_id)

        try:
            logger.info("Starting intelligent analysis",
                       project_name=context.project_name, analysis_id=analysis_id)
            return await self._run_analysis(context)
        except Exception as e:
            logger.exception("Intelligent analysis failed",
                           project_name=context.project_name, error=str(e))
            return self.synthesis_service.create_fallback(context)
        finally:
            scan_id_context.reset(token)

    async def _run_analysis(self, context: CodeContext) -> LegitimacyAnalysis:
        """Run the complete analysis pipeline."""
        component_results = await self.component_runner.run_all(context)
        component_scores = self._create_scores(component_results)

        logger.debug("Component analysis completed",
                    intent_score=component_scores.intent,
                    behavior_score=component_scores.behavior,
                    ecosystem_score=component_scores.ecosystem,
                    anomaly_score=component_scores.anomaly)

        risk_assessment = self.risk_aggregator.aggregate_risk(component_scores)
        analysis = self.synthesis_service.synthesize(
            context, risk_assessment, component_results
        )

        await self.learning_system.record_analysis(context, analysis)

        logger.info("Analysis completed successfully",
                   is_legitimate=analysis.is_legitimate,
                   confidence_score=analysis.confidence_score,
                   risk_level=analysis.risk_level)
        return analysis

    def _create_analysis_id(self, context: CodeContext) -> str:
        """Create analysis-specific ID."""
        name = context.project_name[:8] if context.project_name else 'unknown'
        return f"analysis-{name}"

    def _create_scores(self, results: dict) -> ComponentScores:
        """Create component scores from results."""
        return ComponentScores(
            intent=results['semantic'][0],
            behavior=results['behavioral'][0],
            ecosystem=results['ecosystem'][0],
            anomaly=results['anomaly'][0]
        )
