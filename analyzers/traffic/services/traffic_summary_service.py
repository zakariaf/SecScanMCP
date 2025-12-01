"""Traffic Summary Service - Generates traffic analysis summaries."""

import time
from collections import defaultdict
from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import NetworkEvent


class TrafficSummaryService:
    """Generates traffic analysis summaries and reports."""

    def get_summary(
        self,
        network_events: List["NetworkEvent"],
        dns_queries: List[Dict],
        http_requests: List[Dict],
        data_transfers: List[Dict]
    ) -> Dict[str, Any]:
        """Get comprehensive traffic analysis summary."""
        total_events = len(network_events)
        suspicious_events = sum(1 for e in network_events if e.suspicious)

        risk_score = self._calculate_risk_score(total_events, suspicious_events)
        event_types = self._categorize_events(network_events)
        exfil_attempts = self._get_exfiltration_attempts(network_events)

        return {
            'total_events': total_events,
            'suspicious_events': suspicious_events,
            'risk_score': risk_score,
            'event_types': event_types,
            'dns_queries': len(dns_queries),
            'http_requests': len(http_requests),
            'data_transfers': len(data_transfers),
            'exfiltration_attempts': len(exfil_attempts),
            'exfiltration_methods': [a.exfiltration_method.value for a in exfil_attempts],
            'monitoring_duration': self._get_duration(network_events)
        }

    def _calculate_risk_score(self, total: int, suspicious: int) -> float:
        """Calculate risk score as percentage."""
        if total == 0:
            return 0
        return (suspicious / total) * 100

    def _categorize_events(self, events: List["NetworkEvent"]) -> Dict[str, int]:
        """Categorize events by type."""
        event_types = defaultdict(int)
        for event in events:
            event_types[event.event_type] += 1
        return dict(event_types)

    def _get_exfiltration_attempts(self, events: List["NetworkEvent"]) -> List:
        """Get events with exfiltration methods."""
        return [e for e in events if e.exfiltration_method is not None]

    def _get_duration(self, events: List["NetworkEvent"]) -> float:
        """Calculate monitoring duration."""
        if not events:
            return 0
        return time.time() - events[0].timestamp
