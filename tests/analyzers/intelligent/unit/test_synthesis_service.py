"""Tests for SynthesisService."""

import pytest
from analyzers.intelligent.services.synthesis_service import SynthesisService
from analyzers.intelligent.models.risk_models import ComponentScores


class MockContext:
    """Mock CodeContext for testing."""
    project_name = "test_project"
    system_operations = []


class MockRiskAssessment:
    """Mock risk assessment for testing."""
    def __init__(self, legitimacy=0.7, confidence=0.8, risk_level="low"):
        self.legitimacy_score = legitimacy
        self.confidence = confidence
        self.risk_level = risk_level
        self.component_scores = ComponentScores(
            intent=0.8, behavior=0.7, ecosystem=0.75, anomaly=0.85
        )


@pytest.fixture
def service():
    return SynthesisService()


@pytest.fixture
def context():
    return MockContext()


@pytest.fixture
def component_results():
    return {
        'semantic': (0.8, {"semantic": "data"}),
        'behavioral': (0.7, {"behavioral": "data"}),
        'ecosystem': (0.75, {"ecosystem": "data"}),
        'anomaly': (0.85, {"anomaly": "data"}),
    }


class TestSynthesisService:
    """Tests for SynthesisService."""

    def test_synthesize_returns_legitimacy_analysis(self, service, context, component_results):
        """Test that synthesize returns a LegitimacyAnalysis."""
        risk = MockRiskAssessment(legitimacy=0.7, confidence=0.8)
        result = service.synthesize(context, risk, component_results)
        assert hasattr(result, 'is_legitimate')
        assert hasattr(result, 'confidence_score')
        assert hasattr(result, 'risk_level')

    def test_synthesize_legitimate_high_score(self, service, context, component_results):
        """Test that high legitimacy score results in is_legitimate=True."""
        risk = MockRiskAssessment(legitimacy=0.7, confidence=0.8)
        result = service.synthesize(context, risk, component_results)
        assert result.is_legitimate is True

    def test_synthesize_not_legitimate_low_score(self, service, context, component_results):
        """Test that low legitimacy score results in is_legitimate=False."""
        risk = MockRiskAssessment(legitimacy=0.4, confidence=0.8)
        result = service.synthesize(context, risk, component_results)
        assert result.is_legitimate is False

    def test_synthesize_not_legitimate_low_confidence(self, service, context, component_results):
        """Test that low confidence results in is_legitimate=False."""
        risk = MockRiskAssessment(legitimacy=0.7, confidence=0.2)
        result = service.synthesize(context, risk, component_results)
        assert result.is_legitimate is False

    def test_synthesize_includes_explanation(self, service, context, component_results):
        """Test that result includes explanation."""
        risk = MockRiskAssessment()
        result = service.synthesize(context, risk, component_results)
        assert result.explanation is not None
        assert len(result.explanation) > 0

    def test_synthesize_includes_recommendations(self, service, context, component_results):
        """Test that result includes recommendations."""
        risk = MockRiskAssessment()
        result = service.synthesize(context, risk, component_results)
        assert result.recommendations is not None
        assert len(result.recommendations) > 0

    def test_synthesize_includes_evidence(self, service, context, component_results):
        """Test that result includes evidence from components."""
        risk = MockRiskAssessment()
        result = service.synthesize(context, risk, component_results)
        assert 'component_evidence' in result.evidence
        assert 'semantic' in result.evidence['component_evidence']
        assert 'behavioral' in result.evidence['component_evidence']

    def test_synthesize_correct_scores(self, service, context, component_results):
        """Test that scores are correctly transferred."""
        risk = MockRiskAssessment(confidence=0.85)
        result = service.synthesize(context, risk, component_results)
        assert result.confidence_score == 0.85
        assert result.intent_alignment_score == 0.8
        assert result.ecosystem_similarity_score == 0.75

    def test_create_fallback(self, service, context):
        """Test fallback analysis creation."""
        result = service.create_fallback(context)
        assert result.is_legitimate is True
        assert result.confidence_score == 0.3
        assert result.risk_level == "medium"
        assert "fallback" in result.explanation.lower()
        assert result.evidence.get("fallback") is True

    def test_create_fallback_includes_recommendation(self, service, context):
        """Test fallback includes manual review recommendation."""
        result = service.create_fallback(context)
        assert any("manual" in r.lower() for r in result.recommendations)

    def test_determine_legitimacy_threshold(self, service):
        """Test legitimacy determination threshold."""
        # Just above threshold
        risk_above = MockRiskAssessment(legitimacy=0.56, confidence=0.31)
        assert service._determine_legitimacy(risk_above) is True

        # Just below threshold
        risk_below = MockRiskAssessment(legitimacy=0.54, confidence=0.31)
        assert service._determine_legitimacy(risk_below) is False
