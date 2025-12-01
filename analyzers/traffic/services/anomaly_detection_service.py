"""Network anomaly detection service using ML techniques."""

import logging
from typing import Dict, List, Any
from collections import deque

from .baseline_service import BaselineService
from .burst_detection_service import BurstDetectionService
from .connection_anomaly_service import ConnectionAnomalyService

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """Orchestrates ML-based network anomaly detection."""

    def __init__(self):
        self.anomaly_threshold = 2.0
        self.metrics_history = deque(maxlen=1000)
        self.baseline_service = BaselineService()
        self.burst_service = BurstDetectionService(self.anomaly_threshold)
        self.connection_service = ConnectionAnomalyService()

    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior."""
        self.baseline_service.establish_baseline(metrics)

    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in current metrics."""
        anomalies = []
        if not self.baseline_service.baseline_established:
            return anomalies

        try:
            self.metrics_history.append(current_metrics)
            for metric_name, current_value in current_metrics.items():
                anomaly = self.baseline_service.check_metric_anomaly(
                    metric_name, current_value, self.anomaly_threshold
                )
                if anomaly:
                    anomalies.append(anomaly)
            anomalies.extend(self._detect_temporal_anomalies())
        except Exception as e:
            logger.error(f"Anomaly detection failed: {e}")
        return anomalies

    def detect_traffic_bursts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual traffic bursts."""
        return self.burst_service.detect_traffic_bursts(events)

    def detect_connection_anomalies(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalous connection patterns."""
        return self.connection_service.detect_connection_anomalies(connections)

    def detect_behavioral_changes(self) -> List[Dict[str, Any]]:
        """Detect behavioral changes over time."""
        if len(self.metrics_history) < 20:
            return []
        try:
            recent = list(self.metrics_history)[-10:]
            historical = list(self.metrics_history)[:-10]
            return [c for m in ['connection_count', 'data_volume', 'dns_queries']
                    if (c := self._check_change(m, recent, historical))]
        except Exception as e:
            logger.error(f"Behavioral change detection failed: {e}")
            return []

    def _check_change(self, metric: str, recent: List[Dict], hist: List[Dict]) -> Dict:
        """Check for behavioral change in a metric."""
        rv = [m.get(metric, 0) for m in recent]
        hv = [m.get(metric, 0) for m in hist]
        if not rv or not hv:
            return None
        r_mean, h_mean = sum(rv)/len(rv), sum(hv)/len(hv)
        h_std = self._calculate_std(hv)
        if h_std > 0 and (score := abs(r_mean - h_mean) / h_std) > self.anomaly_threshold:
            return {'type': 'behavioral_change', 'metric': metric,
                    'recent_mean': r_mean, 'historical_mean': h_mean,
                    'change_score': score, 'confidence': min(score / 4.0, 1.0)}
        return None

    def _detect_temporal_anomalies(self) -> List[Dict[str, Any]]:
        """Detect temporal patterns and anomalies."""
        if len(self.metrics_history) < 10:
            return []
        ts = [m.get('timestamp', 0) for m in list(self.metrics_history)[-10:]]
        intervals = [ts[i] - ts[i-1] for i in range(1, len(ts))]
        if intervals and (avg := sum(intervals)/len(intervals)) > 0 and min(intervals) < avg * 0.1:
            return [{'type': 'rapid_requests', 'min_interval': min(intervals),
                     'avg_interval': avg, 'confidence': 0.8}]
        return []

    def _calculate_std(self, values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        return (sum((x - mean) ** 2 for x in values) / (len(values) - 1)) ** 0.5
