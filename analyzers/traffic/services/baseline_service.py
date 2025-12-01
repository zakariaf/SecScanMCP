"""Baseline metrics service for network anomaly detection."""

import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class BaselineService:
    """Establishes and manages network baseline metrics."""

    def __init__(self):
        self.baseline_metrics = {}
        self.baseline_established = False

    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior."""
        if not metrics:
            return

        try:
            connection_counts = [m.get('connection_count', 0) for m in metrics]
            dns_query_counts = [m.get('dns_queries', 0) for m in metrics]
            data_volumes = [m.get('data_volume', 0) for m in metrics]
            request_rates = [m.get('request_rate', 0) for m in metrics]

            self.baseline_metrics = {
                'connection_count': self._calc_stats(connection_counts),
                'dns_queries': self._calc_stats(dns_query_counts),
                'data_volume': self._calc_stats(data_volumes),
                'request_rate': self._calc_stats(request_rates)
            }
            self.baseline_established = True
            logger.info("Network baseline established")
        except Exception as e:
            logger.error(f"Baseline establishment failed: {e}")

    def _calc_stats(self, values: List[float]) -> Dict[str, float]:
        """Calculate mean and std for values."""
        return {
            'mean': self._calculate_mean(values),
            'std': self._calculate_std(values)
        }

    def check_metric_anomaly(self, metric_name: str, current_value: float, threshold: float) -> Dict:
        """Check if a metric value is anomalous against baseline."""
        if metric_name not in self.baseline_metrics:
            return None

        baseline = self.baseline_metrics[metric_name]
        if baseline['std'] > 0:
            z_score = abs(current_value - baseline['mean']) / baseline['std']
            if z_score > threshold:
                return {
                    'type': 'statistical_anomaly',
                    'metric': metric_name,
                    'current_value': current_value,
                    'baseline_mean': baseline['mean'],
                    'z_score': z_score,
                    'confidence': min(z_score / 4.0, 1.0)
                }
        return None

    def _calculate_mean(self, values: List[float]) -> float:
        """Calculate mean of values."""
        return sum(values) / len(values) if values else 0.0

    def _calculate_std(self, values: List[float]) -> float:
        """Calculate standard deviation of values."""
        if len(values) < 2:
            return 0.0
        mean = self._calculate_mean(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
