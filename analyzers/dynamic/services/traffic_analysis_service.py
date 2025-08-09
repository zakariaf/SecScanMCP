"""Network traffic analysis service for dynamic analysis."""

import asyncio
import logging
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class TrafficAnalysisService:
    """Analyzes network traffic for security issues."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.traffic_analyzer = None
        self.analysis_session = {}
    
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
    
    async def analyze_network_traffic(self) -> List[Finding]:
        """Analyze network traffic for suspicious patterns"""
        findings = []
        
        if not self.traffic_analyzer:
            return findings
        
        try:
            self.logger.info("📡 Analyzing network traffic patterns...")
            
            # Stop traffic monitoring and get results
            self.traffic_analyzer.stop_monitoring()
            
            # Get traffic summary
            traffic_summary = self.traffic_analyzer.get_traffic_summary()
            
            # Check for high-risk network activity
            if traffic_summary['risk_score'] > 70:
                finding = Finding(
                    title="High-Risk Network Activity Detected",
                    description=f"Network risk score: {traffic_summary['risk_score']:.1f}%",
                    severity=SeverityLevel.HIGH,
                    vulnerability_type=VulnerabilityType.NETWORK_SECURITY,
                    location="network:traffic",
                    confidence=0.8,
                    recommendation="Investigate suspicious network connections and data transfers",
                    evidence=traffic_summary
                )
                findings.append(finding)
            
            # Check for suspicious activities
            suspicious_activities = self.traffic_analyzer.get_suspicious_activities()
            
            for activity in suspicious_activities[:10]:  # Limit to top 10
                severity = SeverityLevel.HIGH if activity['severity'] == 'high' else SeverityLevel.MEDIUM
                
                finding = Finding(
                    title=f"Suspicious Network Activity: {activity['type']}",
                    description=activity['description'],
                    severity=severity,
                    vulnerability_type=VulnerabilityType.NETWORK_SECURITY,
                    location="network:activity",
                    confidence=0.7,
                    recommendation="Review network activity patterns and validate legitimacy",
                    evidence=activity
                )
                findings.append(finding)
            
            self.logger.info(f"📊 Network analysis found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Network traffic analysis failed: {e}")
        
        return findings
    
    async def detect_data_exfiltration(self) -> List[Finding]:
        """Detect potential data exfiltration attempts"""
        findings = []
        
        try:
            self.logger.info("🔍 Detecting data exfiltration patterns...")
            
            metrics_history = self.analysis_session.get('metrics_history', [])
            
            if not metrics_history:
                return findings
            
            # Analyze data volume patterns
            data_volumes = [m.get('data_volume_bytes', 0) for m in metrics_history]
            avg_volume = sum(data_volumes) / len(data_volumes) if data_volumes else 0
            
            # Check for unusual data transfer spikes
            for i, volume in enumerate(data_volumes):
                if volume > avg_volume * 3 and volume > 10_000_000:  # 10MB threshold
                    finding = Finding(
                        title="Potential Data Exfiltration Detected",
                        description=f"Unusual data transfer: {volume:,} bytes (avg: {avg_volume:,.0f} bytes)",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.DATA_EXFILTRATION,
                        location="network:exfiltration",
                        confidence=0.7,
                        recommendation="Investigate large data transfers and validate business necessity",
                        evidence={
                            'data_volume': volume,
                            'average_volume': avg_volume,
                            'timestamp': metrics_history[i].get('timestamp'),
                            'spike_ratio': volume / avg_volume if avg_volume > 0 else 0
                        }
                    )
                    findings.append(finding)
            
            # Check for suspicious destination patterns
            unique_destinations = []
            for metrics in metrics_history:
                destinations = metrics.get('unique_destinations', 0)
                unique_destinations.append(destinations)
            
            avg_destinations = sum(unique_destinations) / len(unique_destinations) if unique_destinations else 0
            
            for i, dest_count in enumerate(unique_destinations):
                if dest_count > avg_destinations * 2 and dest_count > 10:
                    finding = Finding(
                        title="Suspicious Network Destination Pattern",
                        description=f"Unusual number of destinations: {dest_count} (avg: {avg_destinations:.1f})",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.NETWORK_SECURITY,
                        location="network:destinations",
                        confidence=0.6,
                        recommendation="Review connection patterns and validate legitimate business need",
                        evidence={
                            'destination_count': dest_count,
                            'average_destinations': avg_destinations,
                            'timestamp': metrics_history[i].get('timestamp')
                        }
                    )
                    findings.append(finding)
            
            self.logger.info(f"🔍 Data exfiltration detection found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Data exfiltration detection failed: {e}")
        
        return findings