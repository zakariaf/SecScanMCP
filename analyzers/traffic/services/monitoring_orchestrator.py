"""Monitoring Orchestrator - Manages concurrent monitoring tasks."""

import asyncio
import logging
from typing import Dict, List, Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from ..managers.network_monitor import NetworkMonitor
    from .threat_detection_service import ThreatDetectionService
    from .exfiltration_detection_service import ExfiltrationDetectionService

logger = logging.getLogger(__name__)


class MonitoringOrchestrator:
    """Orchestrates concurrent network monitoring tasks."""

    def __init__(
        self,
        network_monitor: "NetworkMonitor",
        threat_detection: "ThreatDetectionService",
        exfiltration_detection: "ExfiltrationDetectionService",
        on_suspicious_connection: Callable,
        on_dns_query: Callable,
        on_exfiltration: Callable,
    ):
        self.network_monitor = network_monitor
        self.threat_detection = threat_detection
        self.exfiltration_detection = exfiltration_detection
        self.on_suspicious_connection = on_suspicious_connection
        self.on_dns_query = on_dns_query
        self.on_exfiltration = on_exfiltration
        self.monitoring = False

    async def start(self) -> bool:
        """Start all monitoring tasks."""
        self.monitoring = True
        tasks = [
            self._monitor_connections(),
            self._monitor_dns(),
            self._monitor_processes(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
        return True

    def stop(self):
        """Stop monitoring."""
        self.monitoring = False

    async def _monitor_connections(self):
        """Monitor network connections."""
        while self.monitoring:
            await self._process_connections()
            await asyncio.sleep(2)

    async def _monitor_dns(self):
        """Monitor DNS queries."""
        while self.monitoring:
            await self._process_dns()
            await asyncio.sleep(1)

    async def _monitor_processes(self):
        """Monitor network processes."""
        while self.monitoring:
            await self._process_network_processes()
            await asyncio.sleep(3)

    async def _process_connections(self):
        """Process connection data."""
        try:
            result = await self.network_monitor._exec_in_container("netstat -tuln")
            if result:
                for conn in self.network_monitor._parse_netstat_output(result):
                    if self.threat_detection.analyze_connection(conn):
                        self.on_suspicious_connection(conn)
        except Exception as e:
            logger.debug(f"Connection monitoring error: {e}")

    async def _process_dns(self):
        """Process DNS data."""
        try:
            result = await self.network_monitor._exec_in_container("ss -u")
            if result:
                for query in self.network_monitor._parse_dns_activity(result):
                    self.on_dns_query(query)
        except Exception as e:
            logger.debug(f"DNS monitoring error: {e}")

    async def _process_network_processes(self):
        """Process network process data."""
        try:
            cmd = "ps aux | grep -E '(curl|wget|nc|netcat)'"
            result = await self.network_monitor._exec_in_container(cmd)
            if result:
                for proc in self.network_monitor._parse_network_processes(result):
                    indicators = self.exfiltration_detection.detect_exfiltration_commands(
                        proc.get('command', '')
                    )
                    if indicators:
                        self.on_exfiltration(proc, indicators)
        except Exception as e:
            logger.debug(f"Process monitoring error: {e}")
