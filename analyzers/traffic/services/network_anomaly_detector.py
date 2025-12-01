"""Network anomaly detector service."""

import logging
from typing import Dict, List, Any
from collections import deque

from .baseline_service import BaselineService
from .connection_anomaly_service import ConnectionAnomalyService

logger = logging.getLogger(__name__)


class NetworkAnomalyDetector:
    """ML-based network anomaly detection (simplified implementation)."""

    def __init__(self):
        self.anomaly_threshold = 2.0
        self.metrics_history = deque(maxlen=1000)
        self.baseline_service = BaselineService()
        self.connection_service = ConnectionAnomalyService()

    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior."""
        self.baseline_service.establish_baseline(metrics)

    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in current metrics compared to baseline."""
        anomalies = []
        if not self.baseline_service.baseline_established:
            return anomalies
        try:
            for metric_name, current_value in current_metrics.items():
                anomaly = self.baseline_service.check_metric_anomaly(
                    metric_name, current_value, self.anomaly_threshold
                )
                if anomaly:
                    anomaly['severity'] = 'high' if anomaly['z_score'] > 3.0 else 'medium'
                    anomalies.append(anomaly)
            self.metrics_history.append(current_metrics)
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        return anomalies

    def detect_trend_anomalies(self) -> List[Dict[str, Any]]:
        """Detect trend-based anomalies."""
        if len(self.metrics_history) < 10:
            return []
        anomalies = []
        try:
            recent = list(self.metrics_history)[-10:]
            for metric in ['connection_count', 'dns_queries', 'data_volume']:
                values = [m.get(metric, 0) for m in recent]
                if len(values) >= 5:
                    anomalies.extend(self._check_trends(metric, values))
        except Exception as e:
            logger.error(f"Trend anomaly detection failed: {e}")
        return anomalies

    def _check_trends(self, metric: str, values: List[float]) -> List[Dict]:
        """Check for trends in values."""
        anomalies = []
        if self._is_monotonic_increasing(values):
            anomalies.append({'type': 'trend_anomaly', 'metric': metric,
                           'pattern': 'monotonic_increase', 'confidence': 0.8,
                           'description': f'Consistent increase in {metric}'})
        if len(values) >= 3:
            recent_avg = sum(values[-3:]) / 3
            earlier_avg = sum(values[:-3]) / max(len(values) - 3, 1)
            if earlier_avg > 0 and recent_avg > earlier_avg * 3:
                anomalies.append({'type': 'trend_anomaly', 'metric': metric,
                               'pattern': 'sudden_spike', 'confidence': 0.9,
                               'spike_ratio': recent_avg / earlier_avg,
                               'description': f'Sudden spike in {metric}'})
        return anomalies

    def analyze_connection_patterns(self, connections: List[Dict[str, Any]]) -> List[Dict]:
        """Analyze connection patterns for anomalies."""
        if not connections:
            return []
        patterns = self.connection_service.detect_connection_anomalies(connections)
        # Add port scanning detection
        ports = [int(c.get('foreign_address', ':0').split(':')[-1])
                for c in connections if c.get('foreign_address', ':0').split(':')[-1].isdigit()]
        if len(set(ports)) > 50:
            patterns.append({'type': 'port_scanning', 'unique_ports': len(set(ports)),
                          'confidence': min(len(set(ports)) / 100, 1.0)})
        return patterns

    def _is_monotonic_increasing(self, values: List[float]) -> bool:
        """Check if values are monotonically increasing."""
        if len(values) < 3:
            return False
        increases = sum(1 for i in range(1, len(values)) if values[i] > values[i-1])
        return increases / (len(values) - 1) >= 0.8
