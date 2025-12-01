"""Tests for MetricsCollectionService."""

import pytest
from unittest.mock import MagicMock, AsyncMock

from analyzers.dynamic.services.metrics_collection_service import MetricsCollectionService


@pytest.fixture
def metrics_service():
    return MetricsCollectionService()


class MockContainer:
    """Mock Docker container."""
    def __init__(self, stats=None):
        self._stats = stats or {
            'cpu_stats': {
                'cpu_usage': {'total_usage': 100000},
                'system_cpu_usage': 1000000
            },
            'precpu_stats': {
                'cpu_usage': {'total_usage': 50000},
                'system_cpu_usage': 500000
            },
            'memory_stats': {'usage': 104857600}  # 100MB
        }

    def stats(self, stream=False):
        return self._stats

    def exec_run(self, cmd):
        result = MagicMock()
        result.exit_code = 0
        result.output = b'10'
        return result


@pytest.fixture
def mock_container():
    return MockContainer()


class TestMetricsCollectionService:
    """Tests for MetricsCollectionService."""

    @pytest.mark.asyncio
    async def test_collect_snapshot_success(self, metrics_service, mock_container):
        """Test collecting metrics snapshot."""
        snapshot = await metrics_service.collect_snapshot(mock_container)

        assert snapshot is not None
        assert 'timestamp' in snapshot
        assert 'cpu_percent' in snapshot
        assert 'memory_mb' in snapshot

    @pytest.mark.asyncio
    async def test_collect_snapshot_error(self, metrics_service):
        """Test handling error during collection."""
        bad_container = MagicMock()
        bad_container.stats.side_effect = Exception("Connection error")

        snapshot = await metrics_service.collect_snapshot(bad_container)
        assert snapshot is None

    def test_calculate_cpu_percent(self, metrics_service):
        """Test CPU percentage calculation."""
        stats = {
            'cpu_stats': {
                'cpu_usage': {'total_usage': 100000},
                'system_cpu_usage': 1000000
            },
            'precpu_stats': {
                'cpu_usage': {'total_usage': 50000},
                'system_cpu_usage': 500000
            }
        }

        cpu_percent = metrics_service._calculate_cpu_percent(stats)
        assert cpu_percent == 10.0  # (50000/500000) * 100

    def test_calculate_cpu_percent_missing_keys(self, metrics_service):
        """Test CPU calculation with missing keys."""
        cpu_percent = metrics_service._calculate_cpu_percent({})
        assert cpu_percent == 0.0

    def test_extract_memory_usage(self, metrics_service):
        """Test memory extraction."""
        stats = {'memory_stats': {'usage': 104857600}}  # 100MB
        memory_mb = metrics_service._extract_memory_usage(stats)
        assert memory_mb == 100.0

    def test_extract_memory_usage_missing(self, metrics_service):
        """Test memory extraction with missing keys."""
        memory_mb = metrics_service._extract_memory_usage({})
        assert memory_mb == 0.0

    @pytest.mark.asyncio
    async def test_get_network_connections(self, metrics_service, mock_container):
        """Test getting network connections."""
        count = await metrics_service._get_network_connections(mock_container)
        assert count == 10

    @pytest.mark.asyncio
    async def test_get_process_count(self, metrics_service, mock_container):
        """Test getting process count."""
        count = await metrics_service._get_process_count(mock_container)
        assert count == 10
