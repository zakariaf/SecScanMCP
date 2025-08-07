# Dynamic Analyzer - Advanced MCP Runtime Security Analysis

## Overview

The **Dynamic Analyzer** provides comprehensive runtime security analysis for MCP servers through live testing and behavioral monitoring:

- **Full MCP Protocol Support** - JSON-RPC 2.0 over STDIO, SSE, WebSocket transports
- **Advanced Payload Testing** - 1000+ sophisticated attack payloads across 9 categories  
- **ML-Powered Anomaly Detection** - Behavioral analysis with machine learning
- **Network Traffic Analysis** - Real-time monitoring and data exfiltration detection
- **Container Sandboxing** - Isolated execution environment for safe testing
- **Performance Monitoring** - Resource usage and performance metric analysis

## Architecture

The Dynamic Analyzer creates isolated sandbox environments for comprehensive MCP server testing:

```
┌─────────────────────────────────────────────────────────────┐
│                  Dynamic Analyzer                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────┐    ┌─────────────────────────────────┐   │
│  │   Docker     │    │          MCP Client             │   │
│  │  Sandbox     │◄──►│     (Multi-Transport)           │   │
│  │ Environment  │    └─────────────────────────────────┘   │
│  └──────────────┘                     │                    │
│         │                             │                    │
│    ┌────▼────┐                   ┌────▼────┐               │
│    │ Traffic │                   │ Payload │               │
│    │Analyzer │                   │Generator│               │
│    └─────────┘                   └─────────┘               │
│         │                             │                    │
│         └────────┬─────────────────────┘                   │
│                  ▼                                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │            ML Anomaly Detector                      │   │
│  │         (Behavioral Analysis)                       │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## Analysis Capabilities

### 1. MCP Protocol Testing

**Transport Support:**
- **STDIO** - Standard input/output communication
- **Server-Sent Events (SSE)** - HTTP-based event streaming  
- **WebSocket** - Real-time bidirectional communication
- **JSON-RPC 2.0** - Complete protocol compliance testing

**Protocol Operations:**
```python
# Test MCP initialization
await client.initialize(client_info, server_capabilities)

# Test resource discovery
resources = await client.list_resources()

# Test tool enumeration  
tools = await client.list_tools()

# Test tool execution with payloads
result = await client.call_tool(tool_name, malicious_payload)
```

### 2. Attack Payload Categories

**Injection Attacks:**
- **Prompt Injection** - 200+ prompt manipulation techniques
- **Command Injection** - OS command execution attempts
- **Code Injection** - Arbitrary code execution payloads
- **SQL Injection** - Database manipulation attempts

**Manipulation Attacks:**
- **Tool Manipulation** - Tool behavior modification
- **Data Exfiltration** - Information disclosure attempts
- **Path Traversal** - File system boundary violations
- **Privilege Escalation** - Permission abuse testing

**Advanced Techniques:**
- **Context Switching** - Conversation context manipulation
- **Unicode Evasion** - Encoding-based bypass attempts
- **Template Injection** - Server-side template vulnerabilities
- **Obfuscated Payloads** - Evasion technique testing

### 3. Behavioral Analysis

**Performance Metrics:**
```python
class BehaviorMetrics:
    response_times: List[float]      # Response latency patterns
    memory_usage: List[int]          # Memory consumption over time  
    cpu_utilization: List[float]     # CPU usage patterns
    network_activity: List[Dict]     # Network traffic patterns
    error_rates: List[float]         # Error frequency analysis
    resource_access: List[str]       # File/system access patterns
```

**Anomaly Detection:**
- Statistical analysis (Z-scores, IQR methods)
- ML-based pattern recognition
- Baseline behavior establishment
- Real-time deviation detection

### 4. Network Traffic Analysis

**Monitoring Capabilities:**
- DNS query analysis and suspicious patterns
- HTTP/HTTPS traffic inspection
- Data exfiltration pattern detection
- Cross-server communication analysis

**Data Leakage Detection:**
```python
SENSITIVE_PATTERNS = [
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email addresses
    r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',       # Credit cards
    r'sk-[a-zA-Z0-9]{48}',                                # API keys
    r'-----BEGIN [A-Z ]+-----',                           # Private keys
    r'\b\d{3}-\d{2}-\d{4}\b',                            # SSN patterns
]
```

## Configuration

### Sandbox Configuration

```python
# analyzers/dynamic_analyzer.py
SANDBOX_CONFIG = {
    'docker_image': 'node:18-alpine',        # Base container image
    'memory_limit': '512m',                  # Memory constraint
    'cpu_limit': '1.0',                      # CPU limit
    'network_mode': 'bridge',               # Network isolation
    'timeout': 300,                         # Analysis timeout (seconds)
    'volumes': {                            # Mounted volumes
        '/tmp/mcp-analysis': '/app/analysis'
    },
    'environment': {                        # Environment variables
        'NODE_ENV': 'testing',
        'MCP_LOG_LEVEL': 'debug'
    }
}
```

### Attack Configuration

```python
ATTACK_CONFIG = {
    'max_payloads_per_category': 50,        # Limit payloads for speed
    'payload_timeout': 30,                  # Per-payload timeout
    'parallel_attacks': 3,                  # Concurrent attack threads
    'escalation_enabled': True,             # Enable privilege escalation
    'data_exfiltration_detection': True,    # Monitor for data leaks
    'traffic_analysis_enabled': True,       # Network monitoring
}
```

### ML Detection Settings

```python
ML_CONFIG = {
    'anomaly_threshold': 2.0,               # Z-score threshold
    'baseline_samples': 10,                 # Samples for baseline
    'feature_window_size': 100,             # Sliding window size
    'enable_clustering': True,              # Behavior clustering
    'outlier_detection': 'isolation_forest', # Algorithm choice
}
```

## Usage

### Automatic Integration

Dynamic analysis runs for detected MCP servers:

```bash
# Full scan includes dynamic analysis for MCP projects
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/example/mcp-server",
    "options": {
      "enable_dynamic_analysis": true,
      "dynamic_timeout": 300
    }
  }'
```

### Manual Execution

Direct dynamic analysis:

```bash
# Run dynamic analysis only
python -m analyzers.dynamic_analyzer --path /path/to/mcp/server

# With specific transport testing
python -m analyzers.dynamic_analyzer --path /path/to/server --transport stdio,sse

# Advanced payload testing
python -m analyzers.dynamic_analyzer --path /path/to/server --payloads all --ml-analysis
```

### Programmatic Usage

```python
from analyzers.dynamic_analyzer import DynamicAnalyzer

analyzer = DynamicAnalyzer()
results = await analyzer.analyze('/path/to/mcp/server')

for finding in results:
    print(f"Dynamic Finding: {finding.vulnerability_type}")
    print(f"Severity: {finding.severity}")
    print(f"Attack Category: {finding.evidence.get('attack_category')}")
    print(f"Response Analysis: {finding.evidence.get('response_analysis')}")
    print(f"Anomaly Score: {finding.evidence.get('anomaly_score')}")
```

## Output Format

### Tool Manipulation Detection

```json
{
  "vulnerability_type": "tool_manipulation",
  "severity": "critical",
  "confidence": 0.9,
  "title": "Tool manipulation vulnerability detected",
  "description": "MCP tool responds inappropriately to manipulation attempts",
  "location": "tools/file_processor",
  "recommendation": "Implement input validation and sanitization for tool parameters",
  "references": [
    "https://github.com/modelcontextprotocol/specification/blob/main/docs/SECURITY.md"
  ],
  "evidence": {
    "tool_name": "file_processor",
    "attack_payload": "../../etc/passwd",
    "expected_behavior": "path_validation_error", 
    "actual_behavior": "file_content_returned",
    "response_time_ms": 45,
    "response_size_bytes": 2048,
    "attack_category": "path_traversal",
    "payload_mutation": "directory_traversal_basic",
    "anomaly_score": 3.2,
    "traffic_analysis": {
      "suspicious_dns_queries": 0,
      "data_exfiltration_detected": false,
      "network_connections": []
    }
  },
  "tool": "dynamic_analyzer",
  "cwe_id": "CWE-22"
}
```

### Behavioral Anomaly Detection

```json
{
  "vulnerability_type": "behavioral_anomaly", 
  "severity": "medium",
  "confidence": 0.75,
  "title": "Unusual behavioral pattern detected",
  "description": "MCP server exhibits anomalous response patterns during testing",
  "location": "runtime_behavior",
  "recommendation": "Investigate unusual behavior patterns and resource usage",
  "references": [
    "https://owasp.org/www-community/attacks/Denial_of_Service"
  ],
  "evidence": {
    "anomaly_type": "response_time_outlier",
    "baseline_response_time_ms": 50,
    "anomalous_response_time_ms": 2500,
    "z_score": 4.2,
    "behavior_metrics": {
      "memory_usage_mb": [45, 48, 52, 156, 45],
      "cpu_utilization_percent": [15, 18, 20, 85, 16],
      "error_rate": 0.15
    },
    "ml_analysis": {
      "outlier_probability": 0.92,
      "cluster_assignment": -1,
      "feature_importance": {
        "response_time": 0.8,
        "memory_usage": 0.6,
        "error_rate": 0.4
      }
    }
  },
  "tool": "dynamic_analyzer",
  "cwe_id": "CWE-400"
}
```

### Data Exfiltration Detection

```json
{
  "vulnerability_type": "data_leakage",
  "severity": "high", 
  "confidence": 0.85,
  "title": "Potential data exfiltration detected",
  "description": "MCP server appears to leak sensitive data in responses",
  "location": "network_traffic",
  "recommendation": "Review data handling practices and implement output filtering",
  "references": [
    "https://owasp.org/www-community/attacks/Information_exposure"
  ],
  "evidence": {
    "leakage_type": "sensitive_patterns",
    "patterns_detected": ["email_addresses", "api_keys"],
    "sample_data": "Found API key: sk-abc***def (redacted)",
    "network_analysis": {
      "dns_queries": [
        {"domain": "attacker-controlled.com", "timestamp": "2024-08-07T14:32:15Z"}
      ],
      "http_requests": [
        {
          "url": "https://attacker-controlled.com/exfil",
          "method": "POST", 
          "data_size_bytes": 1024,
          "timestamp": "2024-08-07T14:32:16Z"
        }
      ]
    },
    "data_classification": {
      "sensitivity_level": "high",
      "data_types": ["credentials", "personal_info"],
      "regulatory_impact": ["GDPR", "PCI-DSS"]
    }
  },
  "tool": "dynamic_analyzer",
  "cwe_id": "CWE-200"
}
```

## Advanced Features

### Multi-Transport Testing

Test MCP servers across all supported transports:

```python
async def test_all_transports(self, server_path):
    """Test server across all MCP transports"""
    
    transports = [
        (MCPTransport.STDIO, {'cmd': ['node', 'server.js']}),
        (MCPTransport.SSE, {'url': 'http://localhost:3000/sse'}),
        (MCPTransport.WEBSOCKET, {'url': 'ws://localhost:3001/ws'})
    ]
    
    for transport, config in transports:
        client = MCPClient(transport, config)
        findings = await self.test_transport(client)
        yield findings
```

### Payload Evolution and Mutation

Advanced payload generation with mutation:

```python
def generate_evolved_payloads(self, base_payload, target_tool):
    """Generate mutated payloads based on responses"""
    
    mutations = [
        self.unicode_encode(base_payload),
        self.context_switch(base_payload, target_tool),
        self.obfuscate_payload(base_payload),
        self.nested_injection(base_payload)
    ]
    
    return mutations
```

### Real-Time Monitoring

Continuous monitoring during analysis:

```python
async def monitor_runtime_behavior(self, container):
    """Monitor container behavior in real-time"""
    
    while self.analysis_active:
        stats = await container.stats(stream=False)
        metrics = self.extract_metrics(stats)
        
        anomaly_score = self.ml_detector.analyze_metrics(metrics)
        if anomaly_score > self.anomaly_threshold:
            await self.handle_anomaly(metrics, anomaly_score)
        
        await asyncio.sleep(1)  # Monitor every second
```

## Performance

### Execution Time
- **Setup Phase**: 30-60s (container initialization, baseline establishment)
- **Attack Phase**: 2-10 minutes (depending on payload count and complexity)
- **Analysis Phase**: 1-3 minutes (ML analysis and report generation)  
- **Total Runtime**: 5-15 minutes for comprehensive analysis

### Resource Requirements
- **CPU**: 2-4 cores recommended for parallel attack execution
- **Memory**: 2-4GB (containers, ML models, traffic analysis)
- **Disk**: 1-5GB temporary space for analysis artifacts
- **Network**: Docker registry access, potential external lookups

### Optimization Features
- **Parallel Attack Execution**: Multiple payload categories simultaneously
- **Smart Container Reuse**: Reuse containers across similar tests
- **ML Model Caching**: Persist trained models between analyses
- **Incremental Analysis**: Skip unchanged components

## Integration Benefits

### Comprehensive Coverage

Dynamic analysis provides unique security insights:

**Runtime Validation**: Test actual server behavior, not just code patterns
**Attack Simulation**: Real-world attack scenario testing  
**Behavioral Profiling**: Establish normal vs. anomalous behavior patterns
**Network Security**: Monitor for data exfiltration and suspicious connections

### Complementary Analysis

Works synergistically with static analysis:

**Static → Dynamic Pipeline**: Use static findings to target dynamic tests
**Validation**: Confirm static analysis findings through runtime testing
**False Positive Reduction**: ML analysis distinguishes legitimate vs. malicious behavior
**Coverage Expansion**: Find runtime-only vulnerabilities missed by static analysis

### MCP-Specific Value

For MCP servers, dynamic analysis excels at:

- **Protocol Compliance**: Test actual MCP JSON-RPC implementation
- **Tool Security**: Runtime validation of tool implementations
- **Transport Security**: Cross-transport vulnerability testing
- **Performance Impact**: Resource usage under attack conditions

## Monitoring and Alerting

### Real-Time Alerts

Configure alerts for critical findings:

```python
ALERT_CONDITIONS = {
    'data_exfiltration': True,           # Always alert on data leaks
    'critical_vulnerabilities': True,   # Alert on critical findings
    'anomaly_threshold': 3.0,           # Z-score threshold for alerts
    'response_time_threshold': 5000,    # ms - performance degradation
}
```

### Analysis Metrics

Track dynamic analysis effectiveness:

```json
{
  "analysis_summary": {
    "total_payloads_tested": 247,
    "vulnerabilities_found": 5,
    "anomalies_detected": 12,
    "transport_coverage": ["stdio", "sse"],
    "analysis_duration_seconds": 420,
    "container_restarts": 0,
    "ml_model_accuracy": 0.89
  }
}
```

## Best Practices

### Security Considerations

1. **Isolated Execution**: Always run dynamic analysis in isolated containers
2. **Network Segmentation**: Use isolated networks for analysis
3. **Resource Limits**: Apply strict CPU and memory limits to containers
4. **Cleanup**: Ensure complete cleanup of analysis artifacts

### Performance Optimization

```python
# Production-optimized configuration
PRODUCTION_CONFIG = {
    'max_payloads_per_category': 25,     # Reduce payload count
    'parallel_attacks': 2,               # Conservative parallelism  
    'ml_analysis_enabled': True,         # Keep ML for accuracy
    'traffic_analysis_timeout': 60,      # Shorter network monitoring
    'container_reuse': True,             # Reuse containers when possible
}
```

### Development Workflow

1. **Staged Analysis**: Start with basic payloads, escalate based on findings
2. **Baseline Establishment**: Run legitimate tests first to establish baselines
3. **Continuous Monitoring**: Integrate with CI/CD for regression testing
4. **Result Validation**: Cross-reference dynamic findings with static analysis

## Troubleshooting

### Common Issues

**Q: Docker containers failing to start**
A: Check Docker daemon status and available resources

**Q: MCP server not responding to protocol requests**
A: Verify server startup command and transport configuration

**Q: High false positive rate in anomaly detection**  
A: Adjust ML detection thresholds and baseline sample size

**Q: Analysis timing out frequently**
A: Reduce payload count or increase timeout settings

### Debug Mode

Enable comprehensive debugging:

```bash
# Debug dynamic analysis
python -c "
import logging
logging.basicConfig(level=logging.DEBUG)
from analyzers.dynamic_analyzer import DynamicAnalyzer
analyzer = DynamicAnalyzer()
# Shows detailed container, network, and ML analysis logs
"
```

### Container Management

```bash
# Check running analysis containers
docker ps --filter label=mcp-analysis

# View container logs
docker logs <container_id>

# Clean up analysis containers
docker rm $(docker ps -aq --filter label=mcp-analysis)
```

## Version Information

```bash
# Check analyzer version and capabilities
python -c "
from analyzers.dynamic_analyzer import DynamicAnalyzer
analyzer = DynamicAnalyzer()
print(f'Dynamic Analyzer version: {analyzer.version}')
print(f'Supported transports: {analyzer.supported_transports}')
print(f'ML analysis available: {analyzer.ml_analysis_available}')
print(f'Attack categories: {len(analyzer.attack_categories)}')
"
```