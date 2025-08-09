"""Main traffic analyzer orchestrator with clean architecture."""

import time
import logging
from typing import Dict, List, Any
from collections import defaultdict

from .models import NetworkEvent, ExfiltrationMethod
from .managers.network_monitor import NetworkMonitor
from .services.threat_detection_service import ThreatDetectionService
from .services.exfiltration_detection_service import ExfiltrationDetectionService
from .services.anomaly_detection_service import AnomalyDetectionService

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """
    Advanced network traffic analysis for MCP containers.
    
    Features:
    - Real-time network monitoring
    - Threat detection and pattern matching
    - Data exfiltration detection
    - ML-based anomaly detection
    """
    
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.logger = logging.getLogger(__name__)
        
        # Data storage
        self.network_events: List[NetworkEvent] = []
        self.dns_queries: List[Dict[str, Any]] = []
        self.http_requests: List[Dict[str, Any]] = []
        self.data_transfers: List[Dict[str, Any]] = []
        
        # State
        self.monitoring = False
        self.baseline_established = False
        
        # Initialize components
        self.network_monitor = NetworkMonitor(container_id)
        self.threat_detection = ThreatDetectionService()
        self.exfiltration_detection = ExfiltrationDetectionService()
        self.anomaly_detection = AnomalyDetectionService()
    
    async def start_monitoring(self) -> bool:
        """Start monitoring network traffic."""
        try:
            self.monitoring = True
            
            # Start network monitoring
            monitor_success = await self.network_monitor.start_monitoring()
            if not monitor_success:
                self.logger.error("Failed to start network monitoring")
                return False
            
            # Process monitoring data
            await self._process_monitoring_data()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start traffic monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop all monitoring activities."""
        self.monitoring = False
        self.network_monitor.stop_monitoring()
    
    async def _process_monitoring_data(self):
        """Process data from network monitor."""
        try:
            # Collect data from monitoring streams
            async for connections in self.network_monitor._monitor_connections():
                if not self.monitoring:
                    break
                
                for connection in connections:
                    await self._analyze_connection(connection)
            
            async for dns_queries in self.network_monitor._monitor_dns_queries():
                if not self.monitoring:
                    break
                
                for query in dns_queries:
                    await self._analyze_dns_query(query)
            
            async for processes in self.network_monitor._monitor_processes():
                if not self.monitoring:
                    break
                
                for process in processes:
                    await self._analyze_network_process(process)
            
        except Exception as e:
            self.logger.error(f"Data processing failed: {e}")
    
    async def _analyze_connection(self, connection: Dict[str, Any]):
        """Analyze network connection."""
        try:
            # Threat detection
            is_suspicious = self.threat_detection.analyze_connection(connection)
            
            # Create network event
            event = NetworkEvent(
                timestamp=time.time(),
                event_type="connection",
                source=connection.get('local_address', ''),
                destination=connection.get('foreign_address', ''),
                protocol=connection.get('protocol', ''),
                suspicious=is_suspicious
            )
            
            self.network_events.append(event)
            
        except Exception as e:
            self.logger.debug(f"Connection analysis error: {e}")
    
    async def _analyze_dns_query(self, query: Dict[str, Any]):
        """Analyze DNS query."""
        try:
            # Threat detection
            is_suspicious = self.threat_detection.analyze_dns_query(query)
            
            # Store query
            self.dns_queries.append({
                **query,
                'suspicious': is_suspicious
            })
            
            # Create network event if suspicious
            if is_suspicious:
                event = NetworkEvent(
                    timestamp=query.get('timestamp', time.time()),
                    event_type="dns_query",
                    source="container",
                    destination=query.get('query', ''),
                    protocol="DNS",
                    suspicious=True
                )
                self.network_events.append(event)
            
        except Exception as e:
            self.logger.debug(f"DNS analysis error: {e}")
    
    async def _analyze_network_process(self, process: Dict[str, Any]):
        """Analyze network process."""
        try:
            # Threat detection
            is_suspicious = self.threat_detection.analyze_network_process(process)
            
            if is_suspicious:
                event = NetworkEvent(
                    timestamp=process.get('timestamp', time.time()),
                    event_type="network_process",
                    source=process.get('user', ''),
                    destination=process.get('command', ''),
                    protocol="PROCESS",
                    suspicious=True
                )
                self.network_events.append(event)
            
        except Exception as e:
            self.logger.debug(f"Process analysis error: {e}")
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get comprehensive traffic analysis summary."""
        total_events = len(self.network_events)
        suspicious_events = sum(1 for event in self.network_events if event.suspicious)
        
        # Calculate risk metrics
        risk_score = 0
        if total_events > 0:
            risk_score = (suspicious_events / total_events) * 100
        
        # Categorize events by type
        event_types = defaultdict(int)
        for event in self.network_events:
            event_types[event.event_type] += 1
        
        # Analyze exfiltration attempts
        exfiltration_attempts = [
            event for event in self.network_events 
            if event.exfiltration_method is not None
        ]
        
        return {
            'total_events': total_events,
            'suspicious_events': suspicious_events,
            'risk_score': risk_score,
            'event_types': dict(event_types),
            'dns_queries': len(self.dns_queries),
            'http_requests': len(self.http_requests),
            'data_transfers': len(self.data_transfers),
            'exfiltration_attempts': len(exfiltration_attempts),
            'exfiltration_methods': [
                attempt.exfiltration_method.value 
                for attempt in exfiltration_attempts
            ],
            'monitoring_duration': time.time() - (
                self.network_events[0].timestamp if self.network_events else time.time()
            )
        }
    
    def get_suspicious_activities(self) -> List[Dict[str, Any]]:
        """Get list of all suspicious activities detected."""
        activities = []
        
        # Add suspicious network events
        for event in self.network_events:
            if event.suspicious:
                activities.append({
                    'type': 'network_event',
                    'timestamp': event.timestamp,
                    'description': f"{event.event_type}: {event.source} -> {event.destination}",
                    'severity': self._calculate_severity(event),
                    'protocol': event.protocol
                })
        
        # Add exfiltration indicators
        for event in self.network_events:
            if event.exfiltration_method:
                activities.append({
                    'type': 'exfiltration',
                    'timestamp': event.timestamp,
                    'description': f"Data exfiltration via {event.exfiltration_method.value}",
                    'severity': 'high',
                    'method': event.exfiltration_method.value
                })
        
        # Sort by timestamp (most recent first)
        activities.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return activities
    
    def run_anomaly_detection(self) -> List[Dict[str, Any]]:
        """Run ML-based anomaly detection."""
        anomalies = []
        
        try:
            # Prepare metrics for analysis
            current_metrics = self._calculate_current_metrics()
            
            # Establish baseline if needed
            if not self.anomaly_detection.baseline_established and len(self.network_events) > 20:
                historical_metrics = self._get_historical_metrics()
                self.anomaly_detection.establish_baseline(historical_metrics)
            
            # Detect anomalies
            if self.anomaly_detection.baseline_established:
                stat_anomalies = self.anomaly_detection.detect_anomalies(current_metrics)
                anomalies.extend(stat_anomalies)
                
                # Detect traffic bursts
                burst_anomalies = self.anomaly_detection.detect_traffic_bursts(
                    [event.__dict__ for event in self.network_events]
                )
                anomalies.extend(burst_anomalies)
                
                # Detect behavioral changes
                behavior_changes = self.anomaly_detection.detect_behavioral_changes()
                anomalies.extend(behavior_changes)
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def analyze_data_exfiltration(self, data: str) -> List[Dict[str, Any]]:
        """Analyze data for exfiltration patterns."""
        findings = []
        
        try:
            # Pattern detection
            indicators = self.exfiltration_detection.detect_patterns(data)
            for indicator in indicators:
                findings.append({
                    'type': 'pattern_match',
                    'pattern': indicator.data_pattern,
                    'confidence': indicator.confidence,
                    'volume': indicator.volume,
                    'method': indicator.method.value
                })
            
            # Encoding analysis
            encoding_info = self.exfiltration_detection.analyze_encoding_patterns(data)
            if encoding_info['base64_detected'] or encoding_info['encryption_suspected']:
                findings.append({
                    'type': 'encoding_detected',
                    'encoding_info': encoding_info
                })
            
            # Steganography detection
            steg_info = self.exfiltration_detection.detect_steganography(data)
            if steg_info['detected']:
                findings.append({
                    'type': 'steganography',
                    'confidence': steg_info['confidence'],
                    'indicators': steg_info['indicators']
                })
            
        except Exception as e:
            self.logger.error(f"Exfiltration analysis failed: {e}")
        
        return findings
    
    def _calculate_current_metrics(self) -> Dict[str, Any]:
        """Calculate current traffic metrics."""
        current_time = time.time()
        recent_window = current_time - 300  # Last 5 minutes
        
        recent_events = [
            event for event in self.network_events 
            if event.timestamp > recent_window
        ]
        
        return {
            'connection_count': len([e for e in recent_events if e.event_type == 'connection']),
            'dns_queries': len([e for e in recent_events if e.event_type == 'dns_query']),
            'data_volume': sum(e.size for e in recent_events),
            'request_rate': len(recent_events) / 5.0 if recent_events else 0,  # per minute
            'timestamp': current_time
        }
    
    def _get_historical_metrics(self) -> List[Dict[str, Any]]:
        """Get historical metrics for baseline."""
        metrics = []
        window_size = 300  # 5 minute windows
        
        if not self.network_events:
            return metrics
        
        start_time = self.network_events[0].timestamp
        current_time = time.time()
        
        # Create metrics for each window
        window_start = start_time
        while window_start < current_time:
            window_end = window_start + window_size
            
            window_events = [
                event for event in self.network_events
                if window_start <= event.timestamp < window_end
            ]
            
            if window_events:
                metrics.append({
                    'connection_count': len([e for e in window_events if e.event_type == 'connection']),
                    'dns_queries': len([e for e in window_events if e.event_type == 'dns_query']),
                    'data_volume': sum(e.size for e in window_events),
                    'request_rate': len(window_events) / 5.0,
                    'timestamp': window_start
                })
            
            window_start = window_end
        
        return metrics
    
    def _calculate_severity(self, event: NetworkEvent) -> str:
        """Calculate severity of network event."""
        if event.exfiltration_method:
            return 'high'
        elif event.suspicious:
            return 'medium'
        else:
            return 'low'