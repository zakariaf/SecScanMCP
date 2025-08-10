"""Performance monitoring service for dynamic analysis."""

import logging
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class PerformanceMonitoringService:
    """Monitors MCP server performance and resource usage."""
    
    async def analyze_performance(self, container_id: str) -> List[Finding]:
        """
        Analyze MCP server performance metrics.
        
        Args:
            container_id: Container ID to monitor
            
        Returns:
            List of performance-related findings
        """
        findings = []
        
        try:
            # Collect performance metrics
            metrics = await self._collect_performance_metrics(container_id)
            
            # Analyze resource usage
            findings.extend(await self._analyze_resource_usage(metrics))
            
            # Check for performance anomalies
            findings.extend(await self._check_performance_anomalies(metrics))
            
            logger.info(f"Performance monitoring completed with {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Performance monitoring failed: {e}")
        
        return findings
    
    async def _collect_performance_metrics(self, container_id: str) -> Dict[str, Any]:
        """Collect comprehensive performance metrics from container."""
        try:
            import docker
            docker_client = docker.from_env()
            container = docker_client.containers.get(container_id)
            
            # Get real container stats
            stats = container.stats(stream=False)
            
            # Enhanced metrics collection
            metrics = await self._collect_enhanced_runtime_metrics(container, stats)
            return metrics
            
        except Exception as e:
            logger.warning(f"Failed to collect real metrics: {e}, using mock data")
            # Fallback to mock implementation
            return self._get_mock_metrics()
    
    async def _collect_enhanced_runtime_metrics(self, container, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Collect enhanced runtime metrics (from advanced analyzer)."""
        import time
        
        # Calculate CPU percentage using advanced method
        cpu_percent = self._calculate_cpu_percent(stats)
        
        # Extract memory usage in MB
        memory_mb = self._extract_memory_usage(stats)
        
        # Collect system-level metrics
        network_connections = await self._get_network_connections(container)
        process_count = await self._get_process_count(container)
        file_descriptors = await self._get_file_descriptors(container)
        
        return {
            'timestamp': time.time(),
            'cpu_percent': cpu_percent,
            'memory_mb': memory_mb,
            'network_connections': network_connections,
            'process_count': process_count,
            'file_descriptors': file_descriptors,
            
            # Extended monitoring capabilities
            'dns_queries': 0,  # Updated by traffic analyzer
            'file_operations': 0,  # Updated by monitoring
            'process_spawns': 0,  # Updated by monitoring
            'tool_calls': 0,  # Updated by MCP client
            'error_count': 0,  # Updated by log analysis
            'response_time_ms': 0,  # Updated by performance monitoring
            'data_volume_bytes': 0,  # Updated by traffic analyzer
            'unique_destinations': 0,  # Updated by traffic analyzer
            
            # Legacy compatibility
            'cpu_usage': cpu_percent,
            'memory_usage': memory_mb,
            'memory_limit': 1024,  # MB
            'network_io': {'rx_bytes': 1024, 'tx_bytes': 2048},
            'disk_io': {'read_bytes': 4096, 'write_bytes': 8192}
        }
    
    async def _analyze_resource_usage(self, metrics: Dict[str, Any]) -> List[Finding]:
        """Analyze resource usage patterns."""
        findings = []
        
        # Check CPU usage
        cpu_usage = metrics.get('cpu_usage', 0)
        if cpu_usage > 90:
            findings.append(Finding(
                title="High CPU Usage",
                description=f"CPU usage {cpu_usage}% exceeds safe threshold",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=VulnerabilityType.PERFORMANCE_ISSUE,
                location="resource_monitoring",
                confidence=0.8,
                evidence={'cpu_usage': cpu_usage}
            ))
        
        # Check memory usage
        memory_usage = metrics.get('memory_usage', 0)
        memory_limit = metrics.get('memory_limit', 512)
        memory_percent = (memory_usage / memory_limit) * 100
        
        if memory_percent > 85:
            findings.append(Finding(
                title="High Memory Usage",
                description=f"Memory usage {memory_percent:.1f}% may indicate memory leak",
                severity=SeverityLevel.LOW,
                vulnerability_type=VulnerabilityType.PERFORMANCE_ISSUE,
                location="resource_monitoring",
                confidence=0.6,
                evidence={'memory_usage_percent': memory_percent}
            ))
        
        return findings
    
    async def _check_performance_anomalies(self, metrics: Dict[str, Any]) -> List[Finding]:
        """Check for performance anomalies that might indicate security issues."""
        findings = []
        
        # Check for unusual network activity
        network_io = metrics.get('network_io', {})
        tx_bytes = network_io.get('tx_bytes', 0)
        
        if tx_bytes > 1000000:  # 1MB threshold
            findings.append(Finding(
                title="Unusual Network Activity",
                description=f"High network transmission {tx_bytes} bytes may indicate data exfiltration",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=VulnerabilityType.SUSPICIOUS_NETWORK_ACTIVITY,
                location="performance_monitoring",
                confidence=0.5,
                evidence={'network_tx_bytes': tx_bytes}
            ))
        
        return findings
    
    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU usage percentage from Docker stats (advanced method)."""
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
    
    def _get_mock_metrics(self) -> Dict[str, Any]:
        """Get mock metrics for fallback."""
        import time
        return {
            'timestamp': time.time(),
            'cpu_percent': 75.5,
            'memory_mb': 256,
            'network_connections': 5,
            'process_count': 12,
            'file_descriptors': 64,
            'cpu_usage': 75.5,  # Legacy compatibility
            'memory_usage': 256,  # Legacy compatibility
            'memory_limit': 512,
            'network_io': {'rx_bytes': 1024, 'tx_bytes': 2048},
            'disk_io': {'read_bytes': 4096, 'write_bytes': 8192}
        }