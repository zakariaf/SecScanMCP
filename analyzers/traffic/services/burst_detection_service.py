"""Traffic burst detection service."""

import logging
import time
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class BurstDetectionService:
    """Detects unusual traffic bursts."""

    def __init__(self, anomaly_threshold: float = 2.0):
        self.anomaly_threshold = anomaly_threshold

    def detect_traffic_bursts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual traffic bursts."""
        bursts = []
        try:
            window_size = 60  # 1 minute windows
            time_windows = defaultdict(list)

            for event in events:
                timestamp = event.get('timestamp', time.time())
                window = int(timestamp // window_size)
                time_windows[window].append(event)

            window_counts = [len(events) for events in time_windows.values()]
            if not window_counts:
                return bursts

            mean_count = self._calculate_mean(window_counts)
            std_count = self._calculate_std(window_counts)

            for window, window_events in time_windows.items():
                event_count = len(window_events)
                if std_count > 0:
                    z_score = (event_count - mean_count) / std_count
                    if z_score > self.anomaly_threshold:
                        bursts.append({
                            'type': 'traffic_burst',
                            'window': window,
                            'event_count': event_count,
                            'normal_count': mean_count,
                            'z_score': z_score,
                            'confidence': min(z_score / 5.0, 1.0)
                        })
        except Exception as e:
            logger.error(f"Burst detection failed: {e}")
        return bursts

    def _calculate_mean(self, values: List[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    def _calculate_std(self, values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        mean = self._calculate_mean(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
