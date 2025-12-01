"""Explanation generation service."""

from typing import Dict
from ..models.risk_models import ComponentScores


class ExplanationGenerator:
    """Generates human-readable explanations for analysis results."""

    def generate_explanation(
        self, risk_assessment: Dict, component_scores: ComponentScores
    ) -> str:
        """Generate comprehensive explanation of analysis."""
        legitimacy_score = risk_assessment['legitimacy_score']
        confidence = risk_assessment['confidence']
        base = self._get_base_explanation(legitimacy_score, confidence)
        insights = self._generate_component_insights(component_scores)
        if insights:
            return base + ". " + ". ".join(insights) + "."
        return base

    def _get_base_explanation(self, score: float, confidence: float) -> str:
        """Get base explanation based on legitimacy score."""
        if score >= 0.8:
            return f"Analysis indicates legitimate functionality (confidence: {confidence:.1%})"
        elif score >= 0.6:
            return f"Analysis suggests likely legitimate with some concerns (confidence: {confidence:.1%})"
        return f"Analysis identifies potential security concerns (confidence: {confidence:.1%})"

    def _generate_component_insights(self, scores: ComponentScores) -> list:
        """Generate insights from component scores."""
        insights = []
        if scores.intent >= 0.8:
            insights.append("Strong alignment between declared intent and actual behavior")
        elif scores.intent <= 0.4:
            insights.append("Weak alignment between declared intent and actual behavior")
        if scores.ecosystem >= 0.7:
            insights.append("Behavior patterns are common in similar legitimate projects")
        elif scores.ecosystem <= 0.4:
            insights.append("Behavior patterns are unusual compared to peer projects")
        if scores.anomaly <= 0.3:
            insights.append("Multiple anomalous patterns detected")
        return insights
