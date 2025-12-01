"""Recommendation generation service."""

from typing import Dict, List, Any
from ..models.analysis_models import CodeContext


class RecommendationEngine:
    """Generates actionable security recommendations."""

    def generate_recommendations(
        self, context: CodeContext, risk_assessment: Dict, is_legitimate: bool
    ) -> List[str]:
        """Generate tailored recommendations."""
        recommendations = []
        if is_legitimate:
            recommendations.extend(self._legitimate_recommendations(risk_assessment))
        else:
            recommendations.extend(self._security_recommendations(context, risk_assessment))
        recommendations.extend(self._universal_recommendations())
        return recommendations

    def _get_score(self, component_scores: Any, key: str, default: float) -> float:
        """Get score from component_scores (handles dict or object)."""
        if isinstance(component_scores, dict):
            return component_scores.get(key, default)
        return getattr(component_scores, key, default)

    def _legitimate_recommendations(self, risk_assessment: Dict) -> List[str]:
        """Recommendations for legitimate code."""
        recommendations = ["Consider declaring permissions in manifest for transparency"]
        component_scores = risk_assessment.get('component_scores', {})
        if self._get_score(component_scores, 'intent', 1.0) < 0.7:
            recommendations.append(
                "Improve documentation to clearly explain functionality and required permissions"
            )
        return recommendations

    def _security_recommendations(
        self, context: CodeContext, risk_assessment: Dict
    ) -> List[str]:
        """Security-focused recommendations."""
        recommendations = [
            "Review and justify the necessity of these operations",
            "Implement proper input validation and sanitization"
        ]
        component_scores = risk_assessment.get('component_scores', {})
        if self._get_score(component_scores, 'anomaly', 1.0) < 0.5:
            recommendations.append("Address anomalous behavioral patterns identified by analysis")
        if len(context.system_operations) > 0:
            recommendations.append("Minimize or eliminate system command execution")
        return recommendations

    def _universal_recommendations(self) -> List[str]:
        """Universal security best practices."""
        return [
            "Follow principle of least privilege",
            "Implement comprehensive logging for security monitoring"
        ]
