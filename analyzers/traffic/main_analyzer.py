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
            # Create monitoring tasks that run concurrently
            tasks = [
                asyncio.create_task(self._monitor_and_analyze_connections()),
                asyncio.create_task(self._monitor_and_analyze_dns()),
                asyncio.create_task(self._monitor_and_analyze_processes()),
                asyncio.create_task(self._monitor_and_analyze_files()),
            ]
            
            # Run monitoring tasks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)
            
        except Exception as e:
            self.logger.error(f"Data processing failed: {e}")
    
    async def _monitor_and_analyze_connections(self):
        """Monitor and analyze network connections."""
        while self.monitoring:
            try:
                # Use netstat to check active connections
                result = await self.network_monitor._exec_in_container("netstat -tuln")
                if result:
                    connections = self.network_monitor._parse_netstat_output(result)
                    for conn in connections:
                        await self._analyze_connection(conn)
                
                await asyncio.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                self.logger.debug(f"Connection monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_and_analyze_dns(self):
        """Monitor and analyze DNS queries."""
        while self.monitoring:
            try:
                # Monitor DNS-related system calls
                result = await self.network_monitor._exec_in_container("ss -u")
                if result:
                    dns_activity = self.network_monitor._parse_dns_activity(result)
                    for query in dns_activity:
                        await self._analyze_dns_query(query)
                
                await asyncio.sleep(1)  # Check frequently for DNS
                
            except Exception as e:
                self.logger.debug(f"DNS monitoring error: {e}")
                await asyncio.sleep(3)
    
    async def _monitor_and_analyze_processes(self):
        """Monitor and analyze network processes."""
        while self.monitoring:
            try:
                # Check for processes making network calls
                result = await self.network_monitor._exec_in_container("ps aux | grep -E '(curl|wget|nc|netcat|telnet|ssh|ftp)'")
                if result:
                    network_processes = self.network_monitor._parse_network_processes(result)
                    for process in network_processes:
                        await self._analyze_network_process(process)
                
                await asyncio.sleep(3)
                
            except Exception as e:
                self.logger.debug(f"Process monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_and_analyze_files(self):
        """Monitor and analyze file operations."""
        while self.monitoring:
            try:
                # Monitor for file operations that might indicate data staging
                result = await self.network_monitor._exec_in_container("lsof -i")
                if result:
                    file_operations = self.network_monitor._parse_file_operations(result)
                    for operation in file_operations:
                        await self._analyze_file_operation(operation)
                
                await asyncio.sleep(4)
                
            except Exception as e:
                self.logger.debug(f"File monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _analyze_connection(self, connection: Dict[str, Any]):
        """Analyze a network connection for suspicious activity."""
        try:
            remote_addr = connection.get('remote_address', '')
            
            # Check for connections to suspicious destinations
            is_suspicious = self.threat_detection.analyze_connection(connection)
            
            if is_suspicious:
                event = NetworkEvent(
                    timestamp=connection['timestamp'],
                    event_type='suspicious_connection',
                    source=connection.get('local_address', ''),
                    destination=remote_addr,
                    protocol=connection.get('protocol', ''),
                    suspicious=True
                )
                self.network_events.append(event)
                self.logger.warning(f"Suspicious connection detected: {remote_addr}")
            
        except Exception as e:
            self.logger.debug(f"Connection analysis error: {e}")
    
    async def _analyze_dns_query(self, query: Dict[str, Any]):
        """Analyze DNS query for potential data exfiltration."""
        try:
            query_text = query.get('query', '')
            
            # Check for DNS tunneling patterns
            if self._detect_dns_tunneling(query_text):
                self.dns_queries.append({
                    **query,
                    'exfiltration_method': ExfiltrationMethod.DNS,
                    'confidence': 0.8
                })
                self.logger.warning(f"Potential DNS tunneling detected: {query_text}")
            
            # Store all DNS queries
            self.dns_queries.append(query)
            
        except Exception as e:
            self.logger.debug(f"DNS analysis error: {e}")
    
    async def _analyze_network_process(self, process: Dict[str, Any]):
        """Analyze network process for malicious activity."""
        try:
            command = process.get('command', '')
            
            # Check for data exfiltration commands
            exfil_indicators = self._detect_exfiltration_commands(command)
            if exfil_indicators:
                event = NetworkEvent(
                    timestamp=process['timestamp'],
                    event_type='data_exfiltration_attempt',
                    source='container_process',
                    destination='external',
                    protocol='process',
                    data=command,
                    suspicious=True,
                    exfiltration_method=exfil_indicators['method']
                )
                self.network_events.append(event)
                self.logger.warning(f"Data exfiltration attempt detected: {command}")
            
        except Exception as e:
            self.logger.debug(f"Process analysis error: {e}")
    
    async def _analyze_file_operation(self, operation: Dict[str, Any]):
        """Analyze file operation for data staging."""
        try:
            op_text = operation.get('operation', '')
            
            # Check for suspicious file access patterns
            if self._is_data_staging_operation(op_text):
                self.data_transfers.append({
                    **operation,
                    'type': 'data_staging',
                    'confidence': 0.6
                })
        
        except Exception as e:
            self.logger.debug(f"File operation analysis error: {e}")
    
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
        
        # Add suspicious DNS queries
        for query in self.dns_queries:
            if query.get('suspicious'):
                activities.append({
                    'type': 'dns_query',
                    'timestamp': query['timestamp'],
                    'description': f"Suspicious DNS query: {query['query']}",
                    'severity': 'medium',
                    'data': query['query']
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
    
    def _detect_dns_tunneling(self, query: str) -> bool:
        """Detect DNS tunneling patterns."""
        # DNS tunneling typically involves:
        # 1. Long subdomain names
        # 2. Base64-encoded data in subdomains
        # 3. High frequency of queries to same domain
        
        subdomains = query.split('.')
        for subdomain in subdomains:
            if len(subdomain) > 20:  # Unusually long subdomain
                import re
                if re.match(r'^[A-Za-z0-9+/]+=*$', subdomain):  # Base64 pattern
                    return True
        
        return False
    
    def _detect_exfiltration_commands(self, command: str) -> Dict[str, Any]:
        """Detect data exfiltration commands."""
        import re
        exfiltration_patterns = {
            ExfiltrationMethod.HTTP: [
                r'curl.*-X POST.*-d',  # HTTP POST with data
                r'wget.*--post-data',  # wget POST
                r'python.*requests\.post',  # Python requests
            ],
            ExfiltrationMethod.DNS: [
                r'nslookup.*\$\(',  # DNS with command substitution
                r'dig.*@.*\$\(',  # dig with data
            ],
            ExfiltrationMethod.EMAIL: [
                r'mail.*-s.*<',  # mail command with file
                r'sendmail.*<',  # sendmail with file
            ],
            ExfiltrationMethod.FTP: [
                r'ftp.*put',  # FTP upload
                r'sftp.*put',  # SFTP upload
            ]
        }
        
        for method, patterns in exfiltration_patterns.items():
            for pattern in patterns:
                if re.search(pattern, command, re.IGNORECASE):
                    return {
                        'method': method,
                        'confidence': 0.9,
                        'pattern': pattern
                    }
        
        return None
    
    def _is_data_staging_operation(self, operation: str) -> bool:
        """Check if operation indicates data staging for exfiltration."""
        import re
        staging_patterns = [
            r'cp.*/(etc|home|var).*tmp',  # Copying sensitive files to temp
            r'tar.*/(etc|home|var)',  # Archiving sensitive directories
            r'find.*passwd.*-exec',  # Finding and processing password files
            r'grep.*-r.*password',  # Searching for passwords
        ]
        
        return any(re.search(pattern, operation, re.IGNORECASE) for pattern in staging_patterns)
    
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