"""Suspicious Activity Service - Detects and reports suspicious activities."""

from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import NetworkEvent


class SuspiciousActivityService:
    """Detects and compiles suspicious network activities."""

    def get_suspicious_activities(
        self,
        network_events: List["NetworkEvent"],
        dns_queries: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Get list of all suspicious activities detected."""
        activities = []

        activities.extend(self._get_suspicious_network_events(network_events))
        activities.extend(self._get_exfiltration_events(network_events))
        activities.extend(self._get_suspicious_dns(dns_queries))

        return sorted(activities, key=lambda x: x['timestamp'], reverse=True)

    def _get_suspicious_network_events(
        self,
        events: List["NetworkEvent"]
    ) -> List[Dict[str, Any]]:
        """Extract suspicious network events."""
        activities = []
        for event in events:
            if event.suspicious:
                activities.append({
                    'type': 'network_event',
                    'timestamp': event.timestamp,
                    'description': f"{event.event_type}: {event.source} -> {event.destination}",
                    'severity': self._calculate_severity(event),
                    'protocol': event.protocol
                })
        return activities

    def _get_exfiltration_events(
        self,
        events: List["NetworkEvent"]
    ) -> List[Dict[str, Any]]:
        """Extract exfiltration events."""
        activities = []
        for event in events:
            if event.exfiltration_method:
                activities.append({
                    'type': 'exfiltration',
                    'timestamp': event.timestamp,
                    'description': f"Data exfiltration via {event.exfiltration_method.value}",
                    'severity': 'high',
                    'method': event.exfiltration_method.value
                })
        return activities

    def _get_suspicious_dns(
        self,
        queries: List[Dict]
    ) -> List[Dict[str, Any]]:
        """Extract suspicious DNS queries."""
        activities = []
        for query in queries:
            if query.get('suspicious'):
                activities.append({
                    'type': 'dns_query',
                    'timestamp': query['timestamp'],
                    'description': f"Suspicious DNS query: {query['query']}",
                    'severity': 'medium',
                    'data': query['query']
                })
        return activities

    def _calculate_severity(self, event: "NetworkEvent") -> str:
        """Calculate severity of network event."""
        if event.exfiltration_method:
            return 'high'
        elif event.suspicious:
            return 'medium'
        return 'low'
