"""Event Handler - Creates NetworkEvent objects from monitoring data."""

from typing import Dict, List, Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..models import NetworkEvent


class EventHandler:
    """Handles creation of network events from monitoring data."""

    def __init__(self, network_events: List, dns_queries: List):
        self.network_events = network_events
        self.dns_queries = dns_queries

    def on_suspicious_connection(self, conn: Dict):
        """Handle suspicious connection event."""
        from ..models import NetworkEvent
        self.network_events.append(NetworkEvent(
            timestamp=conn['timestamp'],
            event_type='suspicious_connection',
            source=conn.get('local_address', ''),
            destination=conn.get('remote_address', ''),
            protocol=conn.get('protocol', ''),
            suspicious=True
        ))

    def on_dns_query(self, query: Dict):
        """Handle DNS query event."""
        self.dns_queries.append(query)

    def on_exfiltration(self, process: Dict, indicators: Dict):
        """Handle exfiltration event."""
        from ..models import NetworkEvent
        self.network_events.append(NetworkEvent(
            timestamp=process['timestamp'],
            event_type='data_exfiltration_attempt',
            source='container_process',
            destination='external',
            protocol='process',
            data=process.get('command', ''),
            suspicious=True,
            exfiltration_method=indicators['method']
        ))
