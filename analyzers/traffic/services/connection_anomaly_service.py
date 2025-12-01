"""Connection anomaly detection service."""

import logging
from typing import Dict, List, Any
from collections import defaultdict

logger = logging.getLogger(__name__)


class ConnectionAnomalyService:
    """Detects anomalous connection patterns."""

    SUSPICIOUS_PORTS = {1234, 4444, 5555, 6666, 8080, 9999}

    def detect_connection_anomalies(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalous connection patterns."""
        anomalies = []
        try:
            anomalies.extend(self._detect_concentration(connections))
            anomalies.extend(self._detect_port_anomalies(connections))
        except Exception as e:
            logger.error(f"Connection anomaly detection failed: {e}")
        return anomalies

    def _detect_concentration(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect connection concentration to single destination."""
        anomalies = []
        dest_counts = defaultdict(int)
        for conn in connections:
            dest = conn.get('foreign_address', '')
            if dest:
                dest_counts[dest] += 1

        total_connections = len(connections)
        if total_connections > 0:
            for dest, count in dest_counts.items():
                concentration = count / total_connections
                if concentration > 0.7 and count > 10:
                    anomalies.append({
                        'type': 'connection_concentration',
                        'destination': dest,
                        'connection_count': count,
                        'concentration': concentration,
                        'confidence': min(concentration, 1.0)
                    })
        return anomalies

    def _detect_port_anomalies(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual port usage patterns."""
        anomalies = []
        port_counts = defaultdict(int)

        for conn in connections:
            addr = conn.get('foreign_address', '')
            if ':' in addr:
                port = addr.split(':')[-1]
                if port.isdigit():
                    port_counts[int(port)] += 1

        high_ports = [p for p in port_counts.keys() if p > 49152]
        if len(high_ports) > 10:
            anomalies.append({
                'type': 'excessive_high_ports',
                'port_count': len(high_ports),
                'confidence': min(len(high_ports) / 50.0, 1.0)
            })

        used_suspicious = self.SUSPICIOUS_PORTS.intersection(port_counts.keys())
        if used_suspicious:
            anomalies.append({
                'type': 'suspicious_ports',
                'ports': list(used_suspicious),
                'confidence': 0.9
            })
        return anomalies
