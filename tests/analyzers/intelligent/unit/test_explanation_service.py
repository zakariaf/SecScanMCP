"""Tests for ExplanationGenerator service."""

import pytest
from analyzers.intelligent.services.explanation_service import ExplanationGenerator
from analyzers.intelligent.models.risk_models import ComponentScores


@pytest.fixture
def generator():
    return ExplanationGenerator()


@pytest.fixture
def high_scores():
    return ComponentScores(intent=0.85, behavior=0.8, ecosystem=0.75, anomaly=0.9)


@pytest.fixture
def low_scores():
    return ComponentScores(intent=0.3, behavior=0.4, ecosystem=0.35, anomaly=0.25)


@pytest.fixture
def medium_scores():
    return ComponentScores(intent=0.6, behavior=0.65, ecosystem=0.5, anomaly=0.55)


class TestExplanationGenerator:
    """Tests for ExplanationGenerator."""

    def test_high_legitimacy_explanation(self, generator, high_scores):
        """Test explanation for high legitimacy score."""
        risk = {'legitimacy_score': 0.85, 'confidence': 0.9}
        result = generator.generate_explanation(risk, high_scores)
        assert 'legitimate functionality' in result
        assert '90.0%' in result

    def test_medium_legitimacy_explanation(self, generator, medium_scores):
        """Test explanation for medium legitimacy score."""
        risk = {'legitimacy_score': 0.65, 'confidence': 0.7}
        result = generator.generate_explanation(risk, medium_scores)
        assert 'likely legitimate with some concerns' in result

    def test_low_legitimacy_explanation(self, generator, low_scores):
        """Test explanation for low legitimacy score."""
        risk = {'legitimacy_score': 0.4, 'confidence': 0.8}
        result = generator.generate_explanation(risk, low_scores)
        assert 'security concerns' in result

    def test_high_intent_insight(self, generator, high_scores):
        """Test insight for high intent score."""
        risk = {'legitimacy_score': 0.8, 'confidence': 0.9}
        result = generator.generate_explanation(risk, high_scores)
        assert 'Strong alignment' in result

    def test_low_intent_insight(self, generator, low_scores):
        """Test insight for low intent score."""
        risk = {'legitimacy_score': 0.4, 'confidence': 0.8}
        result = generator.generate_explanation(risk, low_scores)
        assert 'Weak alignment' in result

    def test_high_ecosystem_insight(self, generator, high_scores):
        """Test insight for high ecosystem score."""
        risk = {'legitimacy_score': 0.8, 'confidence': 0.9}
        result = generator.generate_explanation(risk, high_scores)
        assert 'common in similar legitimate projects' in result

    def test_low_ecosystem_insight(self, generator, low_scores):
        """Test insight for low ecosystem score."""
        risk = {'legitimacy_score': 0.4, 'confidence': 0.8}
        result = generator.generate_explanation(risk, low_scores)
        assert 'unusual compared to peer projects' in result

    def test_low_anomaly_insight(self, generator, low_scores):
        """Test insight for low anomaly score."""
        risk = {'legitimacy_score': 0.4, 'confidence': 0.8}
        result = generator.generate_explanation(risk, low_scores)
        assert 'anomalous patterns detected' in result

    def test_no_insights_for_neutral_scores(self, generator):
        """Test no insights for neutral scores."""
        neutral = ComponentScores(intent=0.5, behavior=0.5, ecosystem=0.5, anomaly=0.5)
        risk = {'legitimacy_score': 0.5, 'confidence': 0.5}
        result = generator.generate_explanation(risk, neutral)
        # Should only have base explanation, no insights
        assert 'security concerns' in result
        assert 'Strong alignment' not in result
        assert 'Weak alignment' not in result
