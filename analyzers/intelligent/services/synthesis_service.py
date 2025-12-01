"""Analysis synthesis service."""

from typing import Dict, Any

from ..models.analysis_models import CodeContext, LegitimacyAnalysis
from .explanation_service import ExplanationGenerator
from .recommendation_service import RecommendationEngine


class SynthesisService:
    """Synthesizes component results into final analysis."""

    def __init__(self):
        self.explanation_generator = ExplanationGenerator()
        self.recommendation_engine = RecommendationEngine()

    def synthesize(
        self, context: CodeContext, risk_assessment: Any, component_results: Dict
    ) -> LegitimacyAnalysis:
        """Synthesize component results into final analysis."""
        is_legitimate = self._determine_legitimacy(risk_assessment)
        explanation = self._generate_explanation(risk_assessment)
        recommendations = self._generate_recommendations(
            context, risk_assessment, is_legitimate
        )
        evidence = self._compile_evidence(risk_assessment, component_results)

        return LegitimacyAnalysis(
            is_legitimate=is_legitimate,
            confidence_score=risk_assessment.confidence,
            risk_level=risk_assessment.risk_level,
            explanation=explanation,
            evidence=evidence,
            recommendations=recommendations,
            intent_alignment_score=risk_assessment.component_scores.intent,
            behavioral_anomaly_score=1.0 - risk_assessment.component_scores.anomaly,
            ecosystem_similarity_score=risk_assessment.component_scores.ecosystem
        )

    def _determine_legitimacy(self, risk_assessment: Any) -> bool:
        """Determine if code is legitimate based on risk assessment."""
        return (
            risk_assessment.legitimacy_score >= 0.55 and
            risk_assessment.confidence >= 0.3
        )

    def _generate_explanation(self, risk_assessment: Any) -> str:
        """Generate explanation from risk assessment."""
        return self.explanation_generator.generate_explanation(
            risk_assessment.__dict__, risk_assessment.component_scores
        )

    def _generate_recommendations(
        self, context: CodeContext, risk_assessment: Any, is_legitimate: bool
    ) -> list:
        """Generate recommendations."""
        return self.recommendation_engine.generate_recommendations(
            context, risk_assessment.__dict__, is_legitimate
        )

    def _compile_evidence(
        self, risk_assessment: Any, component_results: Dict
    ) -> Dict[str, Any]:
        """Compile evidence from all sources."""
        return {
            'risk_assessment': risk_assessment.__dict__,
            'component_evidence': {
                'semantic': component_results['semantic'][1],
                'behavioral': component_results['behavioral'][1],
                'ecosystem': component_results['ecosystem'][1],
                'anomaly': component_results['anomaly'][1]
            }
        }

    def create_fallback(self, context: CodeContext) -> LegitimacyAnalysis:
        """Create fallback analysis if main analysis fails."""
        return LegitimacyAnalysis(
            is_legitimate=True,
            confidence_score=0.3,
            risk_level="medium",
            explanation="Analysis failed, using conservative fallback assessment",
            evidence={"fallback": True},
            recommendations=["Manual security review recommended"],
            intent_alignment_score=0.5,
            behavioral_anomaly_score=0.5,
            ecosystem_similarity_score=0.5
        )
