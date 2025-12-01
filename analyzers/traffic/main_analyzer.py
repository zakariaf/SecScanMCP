"""Main traffic analyzer orchestrator with clean architecture."""

import logging
from typing import Dict, List, Any

from .managers.network_monitor import NetworkMonitor
from .services import (
    ThreatDetectionService,
    ExfiltrationDetectionService,
    AnomalyDetectionService,
    TrafficSummaryService,
    MetricsService,
    SuspiciousActivityService,
    MonitoringOrchestrator,
    EventHandler,
)

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Network traffic analysis for MCP containers."""

    def __init__(self, container_id: str):
        self.container_id = container_id
        self.logger = logging.getLogger(__name__)
        self.network_events: List[Dict] = []
        self.dns_queries: List[Dict] = []
        self.http_requests: List[Dict] = []
        self.data_transfers: List[Dict] = []
        self._init_services(container_id)

    def _init_services(self, container_id: str):
        """Initialize all services."""
        self.network_monitor = NetworkMonitor(container_id)
        self.threat_detection = ThreatDetectionService()
        self.exfiltration_detection = ExfiltrationDetectionService()
        self.anomaly_detection = AnomalyDetectionService()
        self.summary_service = TrafficSummaryService()
        self.metrics_service = MetricsService()
        self.suspicious_service = SuspiciousActivityService()
        self.event_handler = EventHandler(self.network_events, self.dns_queries)
        self.monitoring_orchestrator = MonitoringOrchestrator(
            self.network_monitor, self.threat_detection, self.exfiltration_detection,
            self.event_handler.on_suspicious_connection,
            self.event_handler.on_dns_query,
            self.event_handler.on_exfiltration,
        )

    async def start_monitoring(self) -> bool:
        """Start monitoring network traffic."""
        try:
            if not await self.network_monitor.start_monitoring():
                self.logger.error("Failed to start network monitoring")
                return False
            await self.monitoring_orchestrator.start()
            return True
        except Exception as e:
            self.logger.error(f"Failed to start traffic monitoring: {e}")
            return False

    def stop_monitoring(self):
        """Stop all monitoring."""
        self.monitoring_orchestrator.stop()
        self.network_monitor.stop_monitoring()

    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get traffic analysis summary."""
        return self.summary_service.get_summary(
            self.network_events, self.dns_queries,
            self.http_requests, self.data_transfers
        )

    def get_suspicious_activities(self) -> List[Dict[str, Any]]:
        """Get suspicious activities."""
        return self.suspicious_service.get_suspicious_activities(
            self.network_events, self.dns_queries
        )

    def run_anomaly_detection(self) -> List[Dict[str, Any]]:
        """Run anomaly detection."""
        metrics = self.metrics_service.calculate_current_metrics(self.network_events)
        if len(self.network_events) > 20 and not self.anomaly_detection.baseline_established:
            historical = self.metrics_service.get_historical_metrics(self.network_events)
            self.anomaly_detection.establish_baseline(historical)
        if self.anomaly_detection.baseline_established:
            return self.anomaly_detection.detect_anomalies(metrics)
        return []

    def analyze_data_exfiltration(self, data: str) -> List[Dict[str, Any]]:
        """Analyze data for exfiltration patterns."""
        return self.exfiltration_detection.detect_patterns(data)
