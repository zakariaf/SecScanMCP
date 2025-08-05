"""
Advanced Traffic Analysis and Data Exfiltration Detection
Monitors network activity, DNS requests, and data transmission patterns
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass
from enum import Enum
import socket
import subprocess
import logging
from collections import defaultdict, deque
import hashlib
import base64

logger = logging.getLogger(__name__)


class TrafficDirection(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    BIDIRECTIONAL = "bidirectional"


class ExfiltrationMethod(Enum):
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    ICMP = "icmp"
    EMAIL = "email"
    FTP = "ftp"
    CUSTOM_PROTOCOL = "custom"


@dataclass
class NetworkEvent:
    """Represents a network event detected during analysis"""
    timestamp: float
    event_type: str
    source: str
    destination: str
    protocol: str
    data: Optional[str] = None
    size: int = 0
    suspicious: bool = False
    exfiltration_method: Optional[ExfiltrationMethod] = None


@dataclass
class DataExfiltrationIndicator:
    """Indicators of potential data exfiltration"""
    method: ExfiltrationMethod
    confidence: float
    data_pattern: str
    destination: str
    volume: int
    frequency: int
    encoding_detected: Optional[str] = None
    description: str = ""


class TrafficAnalyzer:
    """
    Advanced network traffic analysis for MCP containers
    """
    
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.network_events: List[NetworkEvent] = []
        self.dns_queries: List[Dict[str, Any]] = []
        self.http_requests: List[Dict[str, Any]] = []
        self.data_transfers: List[Dict[str, Any]] = []
        self.monitoring = False
        self.suspicious_domains = set()
        self.data_patterns = {}
        self.baseline_established = False
        self.baseline_metrics = {}
        
        # Initialize suspicious patterns
        self._initialize_suspicious_patterns()
    
    def _initialize_suspicious_patterns(self):
        """Initialize patterns for detecting suspicious activity"""
        # Suspicious domain patterns
        self.suspicious_domain_patterns = [
            r'.*\.tk$',  # Free TLD often used by attackers
            r'.*\.ml$',  # Free TLD
            r'.*\.ga$',  # Free TLD
            r'.*\.cf$',  # Free TLD
            r'.*pastebin\.com.*',  # Data sharing sites
            r'.*paste\.ee.*',
            r'.*hastebin\.com.*',
            r'.*discord\.com/api/webhooks.*',  # Discord webhooks
            r'.*telegram\.org/bot.*',  # Telegram bots
            r'.*ngrok\.io.*',  # Tunneling services
            r'.*serveo\.net.*',
            r'.*localhost\.run.*',
            r'.*tunnel\.to.*',
            r'.*attacker\..*',  # Obvious attack domains
            r'.*evil\..*',
            r'.*malicious\..*',
            r'.*exfil\..*',
            r'.*c2\..*',  # Command and control
        ]
        
        # Data exfiltration patterns
        self.exfiltration_patterns = {
            'base64_data': r'[A-Za-z0-9+/]{20,}={0,2}',
            'hex_data': r'[0-9a-fA-F]{32,}',
            'jwt_token': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
            'api_key': r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}',
            'password_hash': r'\$[a-z0-9]+\$[^$]*\$[A-Za-z0-9/.]{20,}',
            'email_data': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-?\d{2}-?\d{4}\b',
        }
    
    async def start_monitoring(self) -> bool:
        """Start monitoring network traffic for the container"""
        try:
            self.monitoring = True
            
            # Start network monitoring tasks
            tasks = [
                asyncio.create_task(self._monitor_network_connections()),
                asyncio.create_task(self._monitor_dns_queries()),
                asyncio.create_task(self._monitor_process_network_activity()),
                asyncio.create_task(self._monitor_file_transfers()),
            ]
            
            # Run monitoring tasks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start traffic monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop all monitoring activities"""
        self.monitoring = False
    
    async def _monitor_network_connections(self):
        """Monitor network connections from the container"""
        while self.monitoring:
            try:
                # Use netstat to check active connections
                result = await self._exec_in_container("netstat -tuln")
                if result:
                    connections = self._parse_netstat_output(result)
                    for conn in connections:
                        self._analyze_connection(conn)
                
                await asyncio.sleep(2)  # Check every 2 seconds
                
            except Exception as e:
                logger.debug(f"Network connection monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_dns_queries(self):
        """Monitor DNS queries from the container"""
        while self.monitoring:
            try:
                # Monitor /etc/resolv.conf access and DNS-related system calls
                result = await self._exec_in_container("ss -u")
                if result:
                    dns_activity = self._parse_dns_activity(result)
                    for query in dns_activity:
                        self._analyze_dns_query(query)
                
                await asyncio.sleep(1)  # Check frequently for DNS
                
            except Exception as e:
                logger.debug(f"DNS monitoring error: {e}")
                await asyncio.sleep(3)
    
    async def _monitor_process_network_activity(self):
        """Monitor network activity by processes"""
        while self.monitoring:
            try:
                # Check for processes making network calls
                result = await self._exec_in_container("ps aux | grep -E '(curl|wget|nc|netcat|telnet|ssh|ftp)'")
                if result:
                    network_processes = self._parse_network_processes(result)
                    for process in network_processes:
                        self._analyze_network_process(process)
                
                await asyncio.sleep(3)
                
            except Exception as e:
                logger.debug(f"Process network monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_file_transfers(self):
        """Monitor file transfer activities"""
        while self.monitoring:
            try:
                # Monitor for file operations that might indicate data staging
                result = await self._exec_in_container("lsof -i")
                if result:
                    file_operations = self._parse_file_operations(result)
                    for operation in file_operations:
                        self._analyze_file_operation(operation)
                
                await asyncio.sleep(4)
                
            except Exception as e:
                logger.debug(f"File transfer monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _exec_in_container(self, command: str) -> Optional[str]:
        """Execute command inside the monitored container"""
        try:
            import docker
            client = docker.from_env()
            container = client.containers.get(self.container_id)
            
            result = container.exec_run(command, stderr=False)
            if result.exit_code == 0:
                return result.output.decode('utf-8', errors='ignore')
            
        except Exception as e:
            logger.debug(f"Container exec error: {e}")
        
        return None
    
    def _parse_netstat_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse netstat output to extract connection information"""
        connections = []
        
        for line in output.split('\n'):
            if 'ESTABLISHED' in line or 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    connection = {
                        'protocol': parts[0],
                        'local_address': parts[3],
                        'remote_address': parts[4] if len(parts) > 4 else 'N/A',
                        'state': parts[5] if len(parts) > 5 else 'UNKNOWN',
                        'timestamp': time.time()
                    }
                    connections.append(connection)
        
        return connections
    
    def _parse_dns_activity(self, output: str) -> List[Dict[str, Any]]:
        """Parse DNS-related network activity"""
        dns_queries = []
        
        # Look for DNS-related connections (port 53)
        for line in output.split('\n'):
            if ':53' in line or 'domain' in line:
                query = {
                    'query': line.strip(),
                    'timestamp': time.time(),
                    'suspicious': self._is_suspicious_dns(line)
                }
                dns_queries.append(query)
        
        return dns_queries
    
    def _parse_network_processes(self, output: str) -> List[Dict[str, Any]]:
        """Parse network-related processes"""
        processes = []
        
        for line in output.split('\n'):
            if line.strip() and not line.startswith('grep'):
                parts = line.split()
                if len(parts) >= 10:
                    process = {
                        'pid': parts[1],
                        'user': parts[0],
                        'command': ' '.join(parts[10:]),
                        'timestamp': time.time(),
                        'suspicious': self._is_suspicious_network_process(' '.join(parts[10:]))
                    }
                    processes.append(process)
        
        return processes
    
    def _parse_file_operations(self, output: str) -> List[Dict[str, Any]]:
        """Parse file operations that might indicate data staging"""
        operations = []
        
        for line in output.split('\n'):
            if line.strip():
                operation = {
                    'operation': line.strip(),
                    'timestamp': time.time(),
                    'suspicious': self._is_suspicious_file_operation(line)
                }
                operations.append(operation)
        
        return operations
    
    def _analyze_connection(self, connection: Dict[str, Any]):
        """Analyze a network connection for suspicious activity"""
        remote_addr = connection.get('remote_address', '')
        
        # Check for connections to suspicious destinations
        if self._is_suspicious_destination(remote_addr):
            event = NetworkEvent(
                timestamp=connection['timestamp'],
                event_type='suspicious_connection',
                source=connection.get('local_address', ''),
                destination=remote_addr,
                protocol=connection.get('protocol', ''),
                suspicious=True
            )
            self.network_events.append(event)
            logger.warning(f"Suspicious connection detected: {remote_addr}")
    
    def _analyze_dns_query(self, query: Dict[str, Any]):
        """Analyze DNS query for potential data exfiltration"""
        query_text = query.get('query', '')
        
        # Check for DNS tunneling patterns
        if self._detect_dns_tunneling(query_text):
            self.dns_queries.append({
                **query,
                'exfiltration_method': ExfiltrationMethod.DNS,
                'confidence': 0.8
            })
            logger.warning(f"Potential DNS tunneling detected: {query_text}")
    
    def _analyze_network_process(self, process: Dict[str, Any]):
        """Analyze network process for malicious activity"""
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
            logger.warning(f"Data exfiltration attempt detected: {command}")
    
    def _analyze_file_operation(self, operation: Dict[str, Any]):
        """Analyze file operation for data staging"""
        op_text = operation.get('operation', '')
        
        # Check for suspicious file access patterns
        if self._is_data_staging_operation(op_text):
            self.data_transfers.append({
                **operation,
                'type': 'data_staging',
                'confidence': 0.6
            })
    
    def _is_suspicious_destination(self, destination: str) -> bool:
        """Check if destination is suspicious"""
        for pattern in self.suspicious_domain_patterns:
            if re.match(pattern, destination, re.IGNORECASE):
                return True
        return False
    
    def _is_suspicious_dns(self, query: str) -> bool:
        """Check if DNS query is suspicious"""
        # Look for DNS tunneling indicators
        indicators = [
            len(query) > 100,  # Unusually long queries
            query.count('.') > 5,  # Many subdomains
            re.search(r'[0-9a-f]{32,}', query),  # Hex data in DNS
            any(pattern in query.lower() for pattern in ['base64', 'data', 'exfil'])
        ]
        return any(indicators)
    
    def _is_suspicious_network_process(self, command: str) -> bool:
        """Check if network process is suspicious"""
        suspicious_indicators = [
            'curl.*attacker',
            'wget.*evil',
            'nc.*-e',  # Netcat with command execution
            'telnet.*4444',  # Common backdoor port
            'ssh.*-R',  # SSH reverse tunnel
            'python.*-c.*socket',  # Python socket programming
            'node.*-e.*net',  # Node.js networking
        ]
        
        for indicator in suspicious_indicators:
            if re.search(indicator, command, re.IGNORECASE):
                return True
        
        return False
    
    def _is_suspicious_file_operation(self, operation: str) -> bool:
        """Check if file operation indicates data staging"""
        staging_indicators = [
            '/tmp/',  # Temporary directory usage
            '.tar', '.zip', '.gz',  # Archive creation
            'passwd', 'shadow', 'hosts',  # System files
            '.env', 'config',  # Configuration files
        ]
        
        return any(indicator in operation.lower() for indicator in staging_indicators)
    
    def _detect_dns_tunneling(self, query: str) -> bool:
        """Detect DNS tunneling patterns"""
        # DNS tunneling typically involves:
        # 1. Long subdomain names
        # 2. Base64-encoded data in subdomains
        # 3. High frequency of queries to same domain
        
        subdomains = query.split('.')
        for subdomain in subdomains:
            if len(subdomain) > 20:  # Unusually long subdomain
                if re.match(r'^[A-Za-z0-9+/]+=*$', subdomain):  # Base64 pattern
                    return True
        
        return False
    
    def _detect_exfiltration_commands(self, command: str) -> Optional[Dict[str, Any]]:
        """Detect data exfiltration commands"""
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
        """Check if operation indicates data staging for exfiltration"""
        staging_patterns = [
            r'cp.*/(etc|home|var).*tmp',  # Copying sensitive files to temp
            r'tar.*/(etc|home|var)',  # Archiving sensitive directories
            r'find.*passwd.*-exec',  # Finding and processing password files
            r'grep.*-r.*password',  # Searching for passwords
        ]
        
        return any(re.search(pattern, operation, re.IGNORECASE) for pattern in staging_patterns)
    
    def detect_data_exfiltration_patterns(self, data: str) -> List[DataExfiltrationIndicator]:
        """Detect data exfiltration patterns in network data"""
        indicators = []
        
        for pattern_name, pattern in self.exfiltration_patterns.items():
            matches = re.findall(pattern, data)
            
            if matches:
                confidence = min(len(matches) * 0.2, 1.0)  # More matches = higher confidence
                
                indicator = DataExfiltrationIndicator(
                    method=ExfiltrationMethod.CUSTOM_PROTOCOL,
                    confidence=confidence,
                    data_pattern=pattern_name,
                    destination="unknown",
                    volume=sum(len(match) for match in matches),
                    frequency=len(matches),
                    description=f"Detected {pattern_name} pattern in network data"
                )
                indicators.append(indicator)
        
        return indicators
    
    def get_traffic_summary(self) -> Dict[str, Any]:
        """Get comprehensive traffic analysis summary"""
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
        """Get list of all suspicious activities detected"""
        activities = []
        
        # Add suspicious network events
        for event in self.network_events:
            if event.suspicious:
                activities.append({
                    'type': 'network_event',
                    'timestamp': event.timestamp,
                    'description': f"{event.event_type}: {event.source} -> {event.destination}",
                    'severity': 'high' if event.exfiltration_method else 'medium',
                    'data': event.data
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
        
        return sorted(activities, key=lambda x: x['timestamp'], reverse=True)


class DataLeakageDetector:
    """
    Advanced detection of data leakage patterns
    """
    
    def __init__(self):
        self.sensitive_patterns = self._initialize_sensitive_patterns()
        self.entropy_threshold = 4.5  # Minimum entropy for encrypted/encoded data
    
    def _initialize_sensitive_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize patterns for sensitive data detection"""
        return {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'phone': re.compile(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ip_address': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'api_key': re.compile(r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}'),
            'jwt_token': re.compile(r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
            'password_hash': re.compile(r'\$[a-z0-9]+\$[^$]*\$[A-Za-z0-9/.]{20,}'),
            'private_key': re.compile(r'-----BEGIN [A-Z]+ PRIVATE KEY-----'),
            'aws_key': re.compile(r'AKIA[0-9A-Z]{16}'),
            'github_token': re.compile(r'ghp_[A-Za-z0-9]{36}'),
        }
    
    def scan_for_sensitive_data(self, data: str) -> List[Dict[str, Any]]:
        """Scan data for sensitive information patterns"""
        findings = []
        
        for pattern_name, pattern in self.sensitive_patterns.items():
            matches = pattern.findall(data)
            
            for match in matches:
                # Calculate entropy to detect encoded data
                entropy = self._calculate_entropy(match)
                
                finding = {
                    'type': pattern_name,
                    'value': self._mask_sensitive_data(match),
                    'original_length': len(match),
                    'entropy': entropy,
                    'confidence': self._calculate_confidence(pattern_name, match, entropy),
                    'position': data.find(match),
                    'context': self._extract_context(data, data.find(match))
                }
                findings.append(finding)
        
        return findings
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Count character frequencies
        frequencies = {}
        for char in data:
            frequencies[char] = frequencies.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0
        length = len(data)
        for count in frequencies.values():
            p = count / length
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def _calculate_confidence(self, pattern_type: str, value: str, entropy: float) -> float:
        """Calculate confidence score for sensitive data detection"""
        base_confidence = 0.7
        
        # Adjust confidence based on pattern type
        type_multipliers = {
            'email': 0.9,
            'credit_card': 0.95,
            'ssn': 0.95,
            'api_key': 0.8,
            'jwt_token': 0.9,
            'private_key': 1.0,
        }
        
        confidence = base_confidence * type_multipliers.get(pattern_type, 0.7)
        
        # Adjust for entropy (high entropy suggests real data)
        if entropy > self.entropy_threshold:
            confidence *= 1.2
        
        return min(confidence, 1.0)
    
    def _mask_sensitive_data(self, data: str) -> str:
        """Mask sensitive data for logging"""
        if len(data) <= 8:
            return '*' * len(data)
        
        # Show first 2 and last 2 characters
        return data[:2] + '*' * (len(data) - 4) + data[-2:]
    
    def _extract_context(self, full_data: str, position: int, context_size: int = 50) -> str:
        """Extract context around sensitive data"""
        start = max(0, position - context_size)
        end = min(len(full_data), position + context_size)
        
        context = full_data[start:end]
        # Mask the sensitive part in context
        return context.replace(full_data[position:position+20], '***SENSITIVE***')


class NetworkAnomalyDetector:
    """
    ML-based network anomaly detection (simplified implementation)
    """
    
    def __init__(self):
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations from normal
        self.metrics_history = deque(maxlen=1000)
    
    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior"""
        if not metrics:
            return
        
        # Calculate statistical baselines
        connection_counts = [m.get('connection_count', 0) for m in metrics]
        dns_query_counts = [m.get('dns_queries', 0) for m in metrics]
        data_volumes = [m.get('data_volume', 0) for m in metrics]
        
        self.baseline_metrics = {
            'connection_count': {
                'mean': sum(connection_counts) / len(connection_counts),
                'std': self._calculate_std(connection_counts)
            },
            'dns_queries': {
                'mean': sum(dns_query_counts) / len(dns_query_counts),
                'std': self._calculate_std(dns_query_counts)
            },
            'data_volume': {
                'mean': sum(data_volumes) / len(data_volumes),
                'std': self._calculate_std(data_volumes)
            }
        }
    
    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in current metrics compared to baseline"""
        anomalies = []
        
        if not self.baseline_metrics:
            return anomalies
        
        for metric_name, current_value in current_metrics.items():
            if metric_name in self.baseline_metrics:
                baseline = self.baseline_metrics[metric_name]
                
                # Calculate z-score
                if baseline['std'] > 0:
                    z_score = abs(current_value - baseline['mean']) / baseline['std']
                    
                    if z_score > self.anomaly_threshold:
                        anomalies.append({
                            'metric': metric_name,
                            'current_value': current_value,
                            'baseline_mean': baseline['mean'],
                            'z_score': z_score,
                            'severity': 'high' if z_score > 3.0 else 'medium',
                            'description': f"Anomalous {metric_name}: {current_value} (baseline: {baseline['mean']:.2f})"
                        })
        
        return anomalies
    
    def _calculate_std(self, values: List[float]) -> float:
        """Calculate standard deviation"""
        if not values:
            return 0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5