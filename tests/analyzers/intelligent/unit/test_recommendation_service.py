"""Tests for RecommendationEngine service."""

import pytest
from analyzers.intelligent.services.recommendation_service import RecommendationEngine


class MockContext:
    """Mock CodeContext for testing."""
    def __init__(self, system_operations=None):
        self.system_operations = system_operations or []


@pytest.fixture
def engine():
    return RecommendationEngine()


class TestRecommendationEngine:
    """Tests for RecommendationEngine."""

    def test_legitimate_recommendations(self, engine):
        """Test recommendations for legitimate code."""
        ctx = MockContext()
        risk = {'component_scores': {'intent': 0.8}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=True)
        assert any('permissions in manifest' in r for r in recs)
        assert any('least privilege' in r for r in recs)

    def test_legitimate_low_intent_recommendation(self, engine):
        """Test documentation recommendation for low intent score."""
        ctx = MockContext()
        risk = {'component_scores': {'intent': 0.5}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=True)
        assert any('documentation' in r.lower() for r in recs)

    def test_security_recommendations(self, engine):
        """Test recommendations for suspicious code."""
        ctx = MockContext()
        risk = {'component_scores': {'anomaly': 0.8}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=False)
        assert any('Review and justify' in r for r in recs)
        assert any('input validation' in r for r in recs)

    def test_security_low_anomaly_recommendation(self, engine):
        """Test anomaly recommendation for low anomaly score."""
        ctx = MockContext()
        risk = {'component_scores': {'anomaly': 0.3}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=False)
        assert any('anomalous behavioral patterns' in r for r in recs)

    def test_system_operations_recommendation(self, engine):
        """Test recommendation when system operations exist."""
        ctx = MockContext(system_operations=['os.system("ls")'])
        risk = {'component_scores': {}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=False)
        assert any('system command execution' in r for r in recs)

    def test_universal_recommendations_included(self, engine):
        """Test that universal recommendations are always included."""
        ctx = MockContext()
        risk = {'component_scores': {}}

        # Test for legitimate
        recs_legit = engine.generate_recommendations(ctx, risk, is_legitimate=True)
        assert any('least privilege' in r for r in recs_legit)
        assert any('logging' in r for r in recs_legit)

        # Test for non-legitimate
        recs_suspicious = engine.generate_recommendations(ctx, risk, is_legitimate=False)
        assert any('least privilege' in r for r in recs_suspicious)
        assert any('logging' in r for r in recs_suspicious)

    def test_empty_component_scores(self, engine):
        """Test with empty component scores."""
        ctx = MockContext()
        risk = {'component_scores': {}}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=True)
        assert len(recs) >= 2  # At least universal recommendations

    def test_missing_component_scores_key(self, engine):
        """Test with missing component_scores key."""
        ctx = MockContext()
        risk = {}
        recs = engine.generate_recommendations(ctx, risk, is_legitimate=True)
        assert len(recs) >= 2  # At least universal recommendations
