"""Network traffic analysis service for dynamic analysis."""

import logging
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class TrafficAnalysisService:
    """Analyzes network traffic for security issues."""
    
    async def analyze_traffic(self, container_id: str) -> List[Finding]:
        """
        Analyze network traffic from container.
        
        Args:
            container_id: Container ID to monitor
            
        Returns:
            List of traffic-related findings
        """
        findings = []
        
        try:
            # Collect network statistics
            network_stats = await self._collect_network_stats(container_id)
            
            # Check for suspicious connections
            findings.extend(await self._check_suspicious_connections(network_stats))
            
            # Check for data exfiltration patterns
            findings.extend(await self._check_data_exfiltration(network_stats))
            
            logger.info(f"Traffic analysis completed with {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Traffic analysis failed: {e}")
        
        return findings
    
    async def _collect_network_stats(self, container_id: str) -> Dict[str, Any]:
        """Collect network statistics from container."""
        # Mock implementation - real version would use netstat, tcpdump, etc.
        return {
            'connections': [
                {'remote_host': '8.8.8.8', 'port': 53, 'protocol': 'UDP'},
                {'remote_host': 'suspicious.example.com', 'port': 80, 'protocol': 'TCP'}
            ],
            'bytes_sent': 1024,
            'bytes_received': 2048,
            'connection_count': 2
        }
    
    async def _check_suspicious_connections(self, stats: Dict[str, Any]) -> List[Finding]:
        """Check for suspicious network connections."""
        findings = []
        
        suspicious_domains = [
            'malicious.com', 'attacker.net', 'suspicious.example.com'
        ]
        
        for connection in stats.get('connections', []):
            remote_host = connection.get('remote_host', '')
            
            if any(domain in remote_host for domain in suspicious_domains):
                findings.append(Finding(
                    title="Suspicious Network Connection",
                    description=f"Connection to suspicious host: {remote_host}",
                    severity=SeverityLevel.HIGH,
                    vulnerability_type=VulnerabilityType.SUSPICIOUS_NETWORK_ACTIVITY,
                    location="network_traffic",
                    confidence=0.8,
                    evidence=connection
                ))
        
        return findings
    
    async def _check_data_exfiltration(self, stats: Dict[str, Any]) -> List[Finding]:
        """Check for potential data exfiltration."""
        findings = []
        
        # Check for unusual data volumes
        bytes_sent = stats.get('bytes_sent', 0)
        if bytes_sent > 100000:  # 100KB threshold
            findings.append(Finding(
                title="Potential Data Exfiltration",
                description=f"Large amount of data sent: {bytes_sent} bytes",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=VulnerabilityType.DATA_EXFILTRATION,
                location="network_traffic",
                confidence=0.6,
                evidence={'bytes_sent': bytes_sent}
            ))
        
        return findings