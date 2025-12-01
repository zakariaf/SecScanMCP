"""Metrics collection service for Docker containers."""

import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class MetricsCollectionService:
    """Collects runtime metrics from Docker containers."""

    async def collect_snapshot(self, container) -> Optional[Dict[str, Any]]:
        """Collect a single snapshot of runtime metrics."""
        try:
            import time
            stats = container.stats(stream=False)

            return {
                'timestamp': time.time(),
                'cpu_percent': self._calculate_cpu_percent(stats),
                'memory_mb': self._extract_memory_usage(stats),
                'network_connections': await self._get_network_connections(container),
                'process_count': await self._get_process_count(container),
                'file_descriptors': await self._get_file_descriptors(container),
            }
        except Exception as e:
            logger.debug(f"Metrics collection error: {e}")
            return None

    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from Docker stats."""
        try:
            cpu_stats = stats['cpu_stats']
            precpu_stats = stats['precpu_stats']
            cpu_delta = cpu_stats['cpu_usage']['total_usage'] - precpu_stats['cpu_usage']['total_usage']
            system_delta = cpu_stats['system_cpu_usage'] - precpu_stats['system_cpu_usage']
            if system_delta > 0:
                return (cpu_delta / system_delta) * 100.0
        except (KeyError, ZeroDivisionError, TypeError):
            pass
        return 0.0

    def _extract_memory_usage(self, stats: Dict[str, Any]) -> float:
        """Extract memory usage in MB."""
        try:
            return stats['memory_stats']['usage'] / (1024 * 1024)
        except (KeyError, TypeError):
            return 0.0

    async def _get_network_connections(self, container) -> int:
        """Get network connections count."""
        try:
            result = container.exec_run('netstat -an | wc -l')
            if result.exit_code == 0:
                return int(result.output.decode().strip())
        except (ValueError, TypeError):
            pass
        return 0

    async def _get_process_count(self, container) -> int:
        """Get process count."""
        try:
            result = container.exec_run('ps aux | wc -l')
            if result.exit_code == 0:
                return int(result.output.decode().strip())
        except (ValueError, TypeError):
            pass
        return 0

    async def _get_file_descriptors(self, container) -> int:
        """Get file descriptor count."""
        try:
            result = container.exec_run('ls /proc/*/fd 2>/dev/null | wc -l')
            if result.exit_code == 0:
                return int(result.output.decode().strip())
        except (ValueError, TypeError):
            pass
        return 0
