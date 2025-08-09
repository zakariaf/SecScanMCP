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
        """Collect performance metrics from container."""
        # Mock implementation - real version would collect actual metrics
        return {
            'cpu_usage': 75.5,  # percentage
            'memory_usage': 256,  # MB
            'memory_limit': 512,  # MB
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