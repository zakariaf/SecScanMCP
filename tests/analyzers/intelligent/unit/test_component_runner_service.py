"""Tests for ComponentRunnerService."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from analyzers.intelligent.services.component_runner_service import ComponentRunnerService


class MockContext:
    """Mock CodeContext for testing."""
    project_name = "test_project"


class MockAnalyzer:
    """Mock analyzer for testing."""
    def __init__(self, score=0.8, evidence=None):
        self.score = score
        self.evidence = evidence or {"test": "data"}

    async def analyze(self, context):
        return self.score, self.evidence


@pytest.fixture
def mock_analyzers():
    return {
        'semantic': MockAnalyzer(0.85, {"semantic": "evidence"}),
        'behavioral': MockAnalyzer(0.75, {"behavioral": "evidence"}),
        'ecosystem': MockAnalyzer(0.70, {"ecosystem": "evidence"}),
        'anomaly': MockAnalyzer(0.90, {"anomaly": "evidence"}),
    }


@pytest.fixture
def runner(mock_analyzers):
    return ComponentRunnerService(
        mock_analyzers['semantic'],
        mock_analyzers['behavioral'],
        mock_analyzers['ecosystem'],
        mock_analyzers['anomaly']
    )


@pytest.fixture
def context():
    return MockContext()


class TestComponentRunnerService:
    """Tests for ComponentRunnerService."""

    @pytest.mark.asyncio
    async def test_run_all_returns_all_components(self, runner, context):
        """Test that run_all returns results for all components."""
        results = await runner.run_all(context)
        assert 'semantic' in results
        assert 'behavioral' in results
        assert 'ecosystem' in results
        assert 'anomaly' in results

    @pytest.mark.asyncio
    async def test_run_all_returns_tuples(self, runner, context):
        """Test that each result is a tuple of (score, evidence)."""
        results = await runner.run_all(context)
        for key in ['semantic', 'behavioral', 'ecosystem', 'anomaly']:
            result = results[key]
            assert isinstance(result, tuple)
            assert len(result) == 2

    @pytest.mark.asyncio
    async def test_run_all_correct_scores(self, runner, context):
        """Test that scores are correctly returned."""
        results = await runner.run_all(context)
        assert results['semantic'][0] == 0.85
        assert results['behavioral'][0] == 0.75
        assert results['ecosystem'][0] == 0.70
        assert results['anomaly'][0] == 0.90

    @pytest.mark.asyncio
    async def test_run_all_correct_evidence(self, runner, context):
        """Test that evidence is correctly returned."""
        results = await runner.run_all(context)
        assert results['semantic'][1] == {"semantic": "evidence"}
        assert results['behavioral'][1] == {"behavioral": "evidence"}
        assert results['ecosystem'][1] == {"ecosystem": "evidence"}
        assert results['anomaly'][1] == {"anomaly": "evidence"}

    @pytest.mark.asyncio
    async def test_analyzers_called_with_context(self, context):
        """Test that analyzers are called with the context."""
        mock_semantic = AsyncMock(return_value=(0.8, {}))
        mock_behavioral = AsyncMock(return_value=(0.7, {}))
        mock_ecosystem = AsyncMock(return_value=(0.6, {}))
        mock_anomaly = AsyncMock(return_value=(0.9, {}))

        class AnalyzerWrapper:
            def __init__(self, mock):
                self.mock = mock
            async def analyze(self, ctx):
                return await self.mock(ctx)

        runner = ComponentRunnerService(
            AnalyzerWrapper(mock_semantic),
            AnalyzerWrapper(mock_behavioral),
            AnalyzerWrapper(mock_ecosystem),
            AnalyzerWrapper(mock_anomaly)
        )

        await runner.run_all(context)

        mock_semantic.assert_called_once_with(context)
        mock_behavioral.assert_called_once_with(context)
        mock_ecosystem.assert_called_once_with(context)
        mock_anomaly.assert_called_once_with(context)
