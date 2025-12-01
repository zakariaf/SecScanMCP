"""Tests for AnomalyDetectionService."""

import pytest
from unittest.mock import MagicMock

from analyzers.dynamic.services.anomaly_detection_service import AnomalyDetectionService


@pytest.fixture
def anomaly_service():
    return AnomalyDetectionService()


class TestAnomalyDetectionService:
    """Tests for AnomalyDetectionService."""

    @pytest.mark.asyncio
    async def test_detect_anomalies_empty_metrics(self, anomaly_service):
        """Test detecting anomalies with empty metrics."""
        findings = await anomaly_service.detect_anomalies([])
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_anomalies_normal_metrics(self, anomaly_service):
        """Test detecting anomalies with normal metrics."""
        metrics = [
            {'cpu_percent': 30, 'memory_mb': 100, 'network_connections': 10},
            {'cpu_percent': 35, 'memory_mb': 105, 'network_connections': 12},
            {'cpu_percent': 32, 'memory_mb': 102, 'network_connections': 11},
        ]
        findings = await anomaly_service.detect_anomalies(metrics)
        assert findings == []

    @pytest.mark.asyncio
    async def test_detect_high_cpu_anomaly(self, anomaly_service):
        """Test detecting high CPU anomaly."""
        metrics = [{'cpu_percent': 95}]
        findings = await anomaly_service.detect_anomalies(metrics)

        assert len(findings) == 1
        assert 'CPU' in findings[0].title

    @pytest.mark.asyncio
    async def test_detect_high_network_anomaly(self, anomaly_service):
        """Test detecting high network connections anomaly."""
        metrics = [{'network_connections': 60}]
        findings = await anomaly_service.detect_anomalies(metrics)

        assert len(findings) == 1
        assert 'Network' in findings[0].title

    @pytest.mark.asyncio
    async def test_detect_memory_growth(self, anomaly_service):
        """Test detecting memory growth anomaly."""
        metrics = [
            {'memory_mb': 100},
            {'memory_mb': 250},  # 150MB growth > 100MB threshold
        ]
        findings = await anomaly_service.detect_anomalies(metrics)

        assert any('Memory' in f.title for f in findings)

    def test_find_outliers_insufficient_data(self, anomaly_service):
        """Test find_outliers with insufficient data."""
        outliers = anomaly_service._find_outliers([1, 2])
        assert outliers == []

    def test_find_outliers_with_anomaly(self, anomaly_service):
        """Test find_outliers detects outliers."""
        values = [10, 11, 10, 12, 10, 100]  # 100 is an outlier
        outliers = anomaly_service._find_outliers(values)

        assert len(outliers) == 1
        assert outliers[0][1] == 100  # The outlier value

    def test_find_outliers_no_variance(self, anomaly_service):
        """Test find_outliers with no variance."""
        values = [5, 5, 5, 5, 5]
        outliers = anomaly_service._find_outliers(values)
        assert outliers == []
