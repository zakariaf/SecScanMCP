# MCP Security Scanner - Complete Implementation

## Project Structure

```
mcp-security-scanner/
├── main.py                    # FastAPI application entry point
├── scanner.py                 # Core scanning orchestration
├── models.py                  # Pydantic models for API
├── scoring.py                 # Security scoring algorithm
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Container image
├── docker-compose.yml         # Easy deployment
├── README.md                  # Usage documentation
├── .gitignore                # Git ignore file
│
├── analyzers/                 # Security analysis modules
│   ├── __init__.py
│   ├── base.py               # Base analyzer class
│   ├── bandit_analyzer.py    # Python AST security
│   ├── semgrep_analyzer.py   # Pattern-based SAST
│   ├── safety_analyzer.py    # Python dependency audit
│   ├── trufflehog_analyzer.py # Secret scanning
│   ├── osv_scanner.py        # Google vulnerability DB
│   ├── pip_audit_analyzer.py # PyPA official audit
│   ├── mcp_analyzer.py       # MCP-specific checks
│   └── dynamic_analyzer.py   # Runtime behavior analysis
│
├── scripts/
│   └── install-tools.sh      # Install security tools locally
│
├── examples/
│   ├── scan_example.py       # How to use the API
│   └── vulnerable-mcp-server.py # Test vulnerable server
│
└── tests/
    └── test_scanner.py       # Example test cases
```

## Key Features

### 1. **Pure Scanner Focus**
- No authentication or user management
- No database or persistent storage
- Stateless operation
- Single responsibility: scan and return results

### 2. **Comprehensive Security Analysis**
- **Static Analysis**: Code scanning without execution
- **Dynamic Analysis**: Behavioral testing in sandboxes
- **Dependency Scanning**: Known vulnerabilities in packages
- **Secret Detection**: API keys, passwords, tokens
- **MCP-Specific**: Prompt injection, tool poisoning

### 3. **Industry-Standard Tools**
```python
# Universal security scanners
analyzers = {
    'syft': SyftAnalyzer(),           # SBOM generation
    'trivy': TrivyAnalyzer(),         # All-in-one scanner
    'grype': GrypeAnalyzer(),         # Fast vuln scanner
    'bandit': BanditAnalyzer(),       # Python linter
    'semgrep': SemgrepAnalyzer(),     # Multi-language SAST
    'trufflehog': TruffleHogAnalyzer(), # Secret scanner
    'mcp_specific': MCPSpecificAnalyzer(), # MCP checks
    'dynamic': DynamicAnalyzer()      # Runtime analysis
}
```

### 4. **Simple API**
```python
# Single endpoint
POST /scan
{
    "repository_url": "https://github.com/user/mcp-server"
}

# Comprehensive response
{
    "security_score": 78.5,
    "security_grade": "B+",
    "findings": [...],
    "summary": {...}
}
```

## Quick Start

### 1. **Deploy with Docker Compose**
```bash
# Clone and start
git clone <repo>
cd mcp-security-scanner
docker-compose up -d

# Verify health
curl http://localhost:8000/health
```

### 2. **Run a Scan**
```bash
# Using curl
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/mcp-server"}'

# Using the example script
python examples/scan_example.py https://github.com/example/mcp-server
```

### 3. **Interpret Results**
- **Score**: 0-100 (higher is better)
- **Grade**: A+ to F
- **Findings**: List of vulnerabilities with severity
- **Recommendations**: Actionable fixes

## Integration with Rails

In your Rails application, you can call this service:

```ruby
# app/services/security_scanner_service.rb
class SecurityScannerService
  SCANNER_URL = ENV['MCP_SCANNER_URL'] || 'http://scanner:8000'
  
  def self.scan_repository(repo_url)
    response = HTTParty.post(
      "#{SCANNER_URL}/scan",
      body: { repository_url: repo_url }.to_json,
      headers: { 'Content-Type' => 'application/json' },
      timeout: 600
    )
    
    if response.success?
      response.parsed_response
    else
      raise "Scan failed: #{response.code} - #{response.message}"
    end
  end
end

# Usage in controller
def security_scan
  @repo = Repository.find(params[:id])
  @scan_results = SecurityScannerService.scan_repository(@repo.url)
  @repo.update(
    security_score: @scan_results['security_score'],
    security_grade: @scan_results['security_grade'],
    last_scanned_at: Time.current
  )
end
```

## Security Vulnerabilities Detected

### MCP-Specific
1. **Prompt Injection** - Malicious instructions in tool descriptions
2. **Tool Poisoning** - Hidden directives to manipulate AI behavior
3. **Schema Injection** - Attacks via tool parameter schemas
4. **Permission Abuse** - Mismatch between declared and actual permissions

### General Security
1. **Command Injection** - os.system(), subprocess with shell=True
2. **Code Injection** - eval(), exec() usage
3. **Path Traversal** - Unrestricted file access
4. **Hardcoded Secrets** - API keys, passwords in code
5. **Vulnerable Dependencies** - Known CVEs in packages

## Scoring Algorithm

```python
# OWASP-style weighted scoring
score = 100 - (Σ(severity_weight × confidence × type_multiplier) / max_possible) × 100

# Severity weights
CRITICAL: 10, HIGH: 7, MEDIUM: 4, LOW: 1, INFO: 0

# Special deductions
- Critical prompt injection: -30%
- Hardcoded secrets: -15%
- Multiple high severity: -10%
```

## Production Deployment

### With Docker Compose
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  scanner:
    image: mcp-scanner:latest
    ports:
      - "127.0.0.1:8000:8000"  # Local only
    environment:
      - LOG_LEVEL=WARNING
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 2G
```

### Behind Nginx
```nginx
upstream scanner {
    server localhost:8000;
}

server {
    location /scanner/ {
        proxy_pass http://scanner/;
        proxy_read_timeout 600s;
    }
}
```

## Advantages of This Design

1. **Simplicity**
   - Single purpose service
   - No complex dependencies
   - Easy to understand and modify

2. **Scalability**
   - Stateless design
   - Horizontal scaling via replicas
   - No shared state between requests

3. **Security**
   - Runs in private network
   - No authentication complexity
   - Isolated scanning environment

4. **Maintainability**
   - Clear separation of concerns
   - Modular analyzer design
   - Standard Python tooling

5. **Extensibility**
   - Easy to add new analyzers
   - Plugin-based architecture
   - Language-agnostic design

## Future Enhancements

1. **Caching Layer**
   - Add Redis for scan result caching
   - Avoid re-scanning unchanged repos

2. **Async Job Queue**
   - Use Celery for long-running scans
   - Return job ID immediately

3. **More Languages**
   - Add ESLint for JavaScript
   - Add Gosec for Go
   - Add Cargo audit for Rust

4. **Enhanced Reporting**
   - PDF report generation
   - SARIF format support
   - Trend analysis

## Conclusion

This simplified MCP Security Scanner provides comprehensive security analysis without the complexity of user management, authentication, or data persistence. It's designed to be a focused microservice that does one thing well: analyze MCP servers for security vulnerabilities and return detailed, actionable results.

The service can be easily integrated into any existing application (Rails, Django, Node.js, etc.) via simple HTTP API calls, making it a versatile addition to your security infrastructure.
