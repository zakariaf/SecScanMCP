"""Traffic Metrics Service - Calculates traffic metrics and baselines."""

import time
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import NetworkEvent


class MetricsService:
    """Calculates current and historical traffic metrics."""

    def calculate_current_metrics(
        self,
        network_events: List["NetworkEvent"],
        window_seconds: int = 300
    ) -> Dict[str, Any]:
        """Calculate current traffic metrics for recent window."""
        current_time = time.time()
        recent_window = current_time - window_seconds

        recent_events = [
            e for e in network_events if e.timestamp > recent_window
        ]

        return {
            'connection_count': self._count_by_type(recent_events, 'connection'),
            'dns_queries': self._count_by_type(recent_events, 'dns_query'),
            'data_volume': sum(e.size for e in recent_events),
            'request_rate': len(recent_events) / (window_seconds / 60),
            'timestamp': current_time
        }

    def get_historical_metrics(
        self,
        network_events: List["NetworkEvent"],
        window_size: int = 300
    ) -> List[Dict[str, Any]]:
        """Get historical metrics for baseline establishment."""
        if not network_events:
            return []

        metrics = []
        start_time = network_events[0].timestamp
        current_time = time.time()

        window_start = start_time
        while window_start < current_time:
            window_end = window_start + window_size
            window_events = self._get_window_events(
                network_events, window_start, window_end
            )

            if window_events:
                metrics.append(self._create_window_metrics(
                    window_events, window_start, window_size
                ))

            window_start = window_end

        return metrics

    def _count_by_type(self, events: List, event_type: str) -> int:
        """Count events of a specific type."""
        return len([e for e in events if e.event_type == event_type])

    def _get_window_events(
        self,
        events: List["NetworkEvent"],
        start: float,
        end: float
    ) -> List["NetworkEvent"]:
        """Get events within a time window."""
        return [e for e in events if start <= e.timestamp < end]

    def _create_window_metrics(
        self,
        events: List["NetworkEvent"],
        window_start: float,
        window_size: int
    ) -> Dict[str, Any]:
        """Create metrics for a time window."""
        return {
            'connection_count': self._count_by_type(events, 'connection'),
            'dns_queries': self._count_by_type(events, 'dns_query'),
            'data_volume': sum(e.size for e in events),
            'request_rate': len(events) / (window_size / 60),
            'timestamp': window_start
        }
