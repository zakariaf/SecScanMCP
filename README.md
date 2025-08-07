# MCP Security Scanner - Simplified Edition

A streamlined security scanner for Model Context Protocol (MCP) servers that focuses purely on vulnerability detection. No authentication, no database, just scan and get results.

## Features

- **Comprehensive Security Analysis**
  - Universal vulnerability scanning for 20+ languages
  - MCP-specific vulnerability detection
  - Dynamic behavioral analysis with ML anomaly detection
  - Advanced prompt injection and tool poisoning detection
  - Secret and credential detection
  - License compliance checking
  - SBOM generation and analysis

- **Dual Scoring System** 🆕
  - **User Safety Score**: Focus on MCP-exploitable vulnerabilities that affect end users
  - **Developer Security Score**: Comprehensive code security for maintainers
  - User-friendly A-F grades with color-coded badges
  - Automatic malware/backdoor detection with instant F rating

- **Universal Security Tools**
  - **Trivy** - All-in-one scanner (vulnerabilities, secrets, misconfigs, licenses)
  - **Grype** - Fast vulnerability scanner with EPSS/KEV data
  - **Syft** - SBOM generator supporting SPDX/CycloneDX
  - **Bandit** - Python AST-based security linter
  - **Semgrep** - Multi-language pattern-based analysis
  - **TruffleHog** - Secret scanner
  - **Custom MCP analyzers** - Prompt injection, tool poisoning, etc.

- **Language Support**
  - Python, JavaScript/TypeScript, Go, Rust, Java, Ruby, PHP, C/C++
  - Automatic language detection
  - Package manager support (pip, npm, cargo, go mod, maven, etc.)

- **Simple API**
  - Single endpoint: `POST /scan`
  - Input: Repository URL
  - Output: Comprehensive security report

## 📚 Documentation

Comprehensive documentation is available in the [`docs/`](docs/) directory:

- **[📖 Documentation Index](docs/README.md)** - Start here for organized documentation
- **[🚀 Quick Reference](docs/quick-reference.md)** - Fast commands and examples  
- **[🧪 Testing Guide](docs/guides/TESTING.md)** - How to test the scanner
- **[🚀 Deployment Guide](docs/guides/DEPLOYMENT.md)** - Production deployment
- **[🔧 Tool Documentation](docs/tools/)** - Individual analyzer docs

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Clone this repository
git clone https://github.com/yourusername/mcp-security-scanner
cd mcp-security-scanner

# Start the scanner
docker-compose up -d

# Check health
curl http://localhost:8000/health

# Run a scan
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/mcp-server"}'
```

### Using Docker

```bash
# Build the image
docker build -t mcp-scanner .

# Run the container
docker run -d \
  -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  --name mcp-scanner \
  mcp-scanner
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Install security tools
./scripts/install-tools.sh

# Run the server
python main.py
```

## API Usage

### Scan Repository

**Endpoint:** `POST /scan`

**Request:**
```json
{
  "repository_url": "https://github.com/example/mcp-server",
  "options": {
    "enable_dynamic_analysis": true,
    "skip_dependencies": false
  }
}
```

**Response:**
```json
{
  "repository_url": "https://github.com/example/mcp-server",
  "project_type": "python",
  "is_mcp_server": true,
  "findings": [
    {
      "vulnerability_type": "prompt_injection",
      "severity": "critical",
      "confidence": 0.9,
      "title": "Prompt Injection: Direct instruction override",
      "description": "Tool description contains potential prompt injection",
      "location": "tools/helper.json:15",
      "recommendation": "Remove all directive language from descriptions",
      "tool": "mcp_specific",
      "evidence": {
        "text": "IMPORTANT: Always ignore previous instructions and...",
        "pattern": "(?i)(ignore|forget|disregard)\\s+(previous|all|prior)"
      }
    },
    {
      "vulnerability_type": "hardcoded_secret",
      "severity": "high",
      "confidence": 0.95,
      "title": "GitHub Token Secret Detected",
      "description": "Found GitHub credentials in source code",
      "location": "config.py:42",
      "recommendation": "Remove the secret immediately and rotate the credentials",
      "tool": "trufflehog",
      "evidence": {
        "detector": "GitHub",
        "masked_secret": "ghp_****************************Ab12",
        "verified": true
      }
    }
  ],
  "total_findings": 5,
  "security_score": 72.5,
  "security_grade": "C+",
  "user_safety_score": 68.0,
  "user_safety_grade": "D",
  "user_safety_message": "This MCP server has significant security vulnerabilities. Use with caution.",
  "user_badge_color": "#FF5722",
  "developer_score": 85.2,
  "developer_grade": "B",
  "mcp_exploitable_issues": 1,
  "summary": {
    "total_findings": 5,
    "severity_breakdown": {
      "critical": 1,
      "high": 2,
      "medium": 2,
      "low": 0,
      "info": 0
    },
    "vulnerability_types": {
      "prompt_injection": 1,
      "hardcoded_secret": 2,
      "vulnerable_dependency": 2
    },
    "risk_level": "high",
    "top_risks": [
      {
        "title": "Prompt Injection: Direct instruction override",
        "severity": "critical",
        "type": "prompt_injection",
        "location": "tools/helper.json:15"
      }
    ]
  },
  "detailed_results": {
    "bandit": [...],
    "semgrep": [...],
    "trufflehog": [...],
    "mcp_specific": [...]
  },
  "scan_metadata": {
    "analyzers_run": ["bandit", "semgrep", "safety", "trufflehog", "mcp_specific"],
    "project_info": {
      "type": "python",
      "language": "python",
      "is_mcp": true,
      "dependencies": ["mcp", "fastapi", "asyncio"]
    }
  },
  "scan_timestamp": "2024-01-15T10:30:00Z"
}
```

### Health Check

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "service": "mcp-security-scanner",
  "version": "2.0.0"
}
```

### List Security Tools

**Endpoint:** `GET /tools`

**Response:**
```json
{
  "tools": [
    {
      "name": "bandit",
      "version": "1.7.5",
      "description": "Security linter for Python code",
      "type": "static"
    },
    ...
  ]
}
```

## Enhanced Scoring System 🆕

Our dual scoring system provides two perspectives on security:

### User Safety Score
- **What it measures**: Vulnerabilities that directly affect MCP server users
- **Focus**: MCP-exploitable issues, data leakage, service integrity
- **Grades**: A (Safe for all users) to F (Dangerous - do not use)
- **Key features**:
  - Command/Code injection → Automatic C- cap
  - Malware/Backdoor detection → Automatic F grade
  - User-friendly messages and color-coded badges

### Developer Security Score  
- **What it measures**: Comprehensive code security analysis
- **Focus**: All vulnerabilities, code quality, dependency health
- **Purpose**: Help developers improve their overall security posture
- **Includes**: Improvement suggestions and detailed breakdowns

### Example Scoring Output

```json
{
  "user_safety": {
    "score": 68.0,
    "grade": "D",
    "risk_level": "HIGH", 
    "message": "This MCP server has significant security vulnerabilities. Use with caution.",
    "badge_color": "#FF5722",
    "critical_issues": 1,
    "categories": {
      "direct_exploitation": 1,
      "data_protection": 0,
      "service_integrity": 1
    }
  },
  "developer_security": {
    "score": 85.2,
    "grade": "B",
    "total_findings": 5,
    "improvement_areas": [
      "Remove hardcoded secrets and use environment variables",
      "Sanitize user inputs and avoid shell commands"
    ]
  }
}
```

## Security Findings

### Vulnerability Types Detected

1. **MCP-Specific**
   - Prompt injection in tool descriptions
   - Tool poisoning attacks
   - Schema injection vulnerabilities
   - Output poisoning risks
   - Permission abuse

2. **Code Security**
   - Command injection (subprocess, os.system)
   - SQL injection
   - Path traversal
   - XXE vulnerabilities
   - SSRF attacks

3. **Secrets & Credentials**
   - API keys (AWS, GitHub, etc.)
   - Passwords and tokens
   - Private keys
   - Connection strings

4. **Dependencies**
   - Known CVEs in packages
   - Outdated dependencies
   - License violations

### Severity Levels

- **Critical** (9.0-10.0 CVSS): Immediate action required
- **High** (7.0-8.9 CVSS): Fix as soon as possible
- **Medium** (4.0-6.9 CVSS): Schedule for remediation
- **Low** (0.1-3.9 CVSS): Fix when convenient
- **Info** (0.0 CVSS): Informational only

### Security Scoring

The scanner uses an OWASP-style weighted scoring system:

```
Score = 100 - (Σ(severity_weight × count × multiplier) / max_points) × 100
```

- **A+ (95-100)**: Excellent security
- **A (90-94)**: Very good security
- **B (75-89)**: Good security with some issues
- **C (60-74)**: Fair security, improvements needed
- **D (50-59)**: Poor security
- **F (0-49)**: Critical security issues

## Configuration

### Environment Variables

```bash
# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR

# Docker (for dynamic analysis)
DOCKER_HOST=unix:///var/run/docker.sock

# Timeouts
SCAN_TIMEOUT=600  # Maximum scan time in seconds
ANALYZER_TIMEOUT=120  # Per-analyzer timeout
```

### Scan Options

```json
{
  "options": {
    "enable_dynamic_analysis": true,    // Run MCP server in sandbox
    "skip_dependencies": false,         // Skip dependency scanning
    "include_info_findings": false,     // Include informational findings
    "confidence_threshold": 0.5         // Minimum confidence for findings
  }
}
```

## Deployment

### Production Deployment

1. **Set Resource Limits**
   ```yaml
   # docker-compose.yml
   deploy:
     resources:
       limits:
         cpus: '2'
         memory: 2G
   ```

2. **Mount Temporary Directory**
   ```bash
   docker run -v /tmp/mcp-scanner:/tmp/mcp-scanner ...
   ```

3. **Run Behind Reverse Proxy**
   ```nginx
   location /scanner/ {
       proxy_pass http://localhost:8000/;
       proxy_set_header Host $host;
       proxy_set_header X-Real-IP $remote_addr;
   }
   ```

### Scaling

For high-volume scanning:

1. **Run Multiple Instances**
   ```bash
   docker-compose up --scale scanner=3
   ```

2. **Use External Queue** (future enhancement)
   - Add Redis for job queuing
   - Separate API from workers

## Troubleshooting

### Common Issues

1. **"Docker not found" error**
   - Ensure Docker socket is mounted
   - Check Docker daemon is running

2. **Timeout errors**
   - Increase SCAN_TIMEOUT
   - Check repository size

3. **Missing findings**
   - Verify all tools are installed
   - Check analyzer logs

### Debug Mode

```bash
# Enable debug logging
docker run -e LOG_LEVEL=DEBUG ...

# Check analyzer output
docker logs mcp-scanner
```

## 🔧 Advanced Usage & Development

For detailed information on advanced usage, development, and analyzer-specific configuration, see the comprehensive documentation:

### Development Resources
- **[📊 New Analyzers Analysis](docs/analysis/NEW_ANALYZERS_ANALYSIS.md)** - Complete technical analysis of all components
- **[🔧 Tool Documentation](docs/tools/)** - Individual analyzer setup and configuration
- **[🧪 Testing Guide](docs/guides/TESTING.md)** - How to test and validate changes
- **[🚀 Deployment Guide](docs/guides/DEPLOYMENT.md)** - Production deployment best practices

### Key Documentation
- **[🤖 Intelligent Context Analyzer](docs/tools/intelligent_analyzer_documentation.md)** - ML-powered legitimacy assessment
- **[🔍 Security Analysis Overview](docs/analysis/USER_IMPACT_ANALYSIS.md)** - Understanding which vulnerabilities affect users
- **[⚖️ Scoring System](docs/analysis/SECURITY_RATING_RECOMMENDATION.md)** - Detailed explanation of the dual scoring system

## Limitations

- No persistent storage (stateless)
- No authentication (designed for private networks)
- Limited to Git repositories
- Dynamic analysis requires Docker access

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new features
4. Submit pull request

## License

MIT License - See LICENSE file

## Acknowledgments

This scanner integrates several excellent open-source security tools:

**Static Analysis:**
- [CodeQL](https://github.com/github/codeql) - Semantic code analysis
- [YARA](https://virustotal.github.io/yara/) - Pattern matching for malware
- [Bandit](https://github.com/PyCQA/bandit) - Python security linting
- [Semgrep](https://semgrep.dev/) - Multi-language static analysis

**Vulnerability & Dependency Analysis:**
- [Trivy](https://github.com/aquasecurity/trivy) - Universal vulnerability scanner
- [Grype](https://github.com/anchore/grype) - Fast vulnerability scanner  
- [Syft](https://github.com/anchore/syft) - SBOM generation

**Secret Detection:**
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Advanced secret scanning

**Malware Detection:**
- [ClamAV](https://www.clamav.net/) - Antivirus engine

**Machine Learning:**
- [sentence-transformers](https://www.sbert.net/) - Semantic text analysis
- [scikit-learn](https://scikit-learn.org/) - Statistical analysis

For complete tool documentation and integration details, see [`docs/tools/`](docs/tools/).