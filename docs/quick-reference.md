# MCP Security Scanner - Quick Reference

## 🚀 Quick Start

```bash
# Using Docker Compose
docker-compose up -d

# Direct Docker run
docker run -d -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  mcp-scanner:latest

# Scan a repository
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/user/repo"}'
```

## 🛠️ Universal Scanners

| Tool | Purpose | Languages | Speed |
|------|---------|-----------|-------|
| **Trivy** | All-in-one scanner | 20+ languages | ~5s |
| **Grype** | Fast vuln scanner | All via SBOM | ~2s |
| **Syft** | SBOM generator | All packages | ~3s |

## 📊 Key Features

### What's Scanned
- ✅ **Vulnerabilities** - CVEs in dependencies and OS packages
- ✅ **Secrets** - API keys, passwords, tokens
- ✅ **Licenses** - Compliance and compatibility
- ✅ **Misconfigurations** - Security issues in configs
- ✅ **MCP-Specific** - Prompt injection, tool poisoning

### Risk Prioritization
- **EPSS Score** - Exploit Prediction (0-1)
- **KEV Data** - Known Exploited Vulnerabilities
- **CVSS Score** - Common Vulnerability Scoring

## 🔍 Scan Options

```json
{
  "repository_url": "https://github.com/user/repo",
  "options": {
    "enable_dynamic_analysis": true,  // Run MCP servers
    "comprehensive": true,            // Use all scanners
    "fast_mode": false,              // Quick scan only
    "skip_dependencies": false       // Skip dependency checks
  }
}
```

## 📈 Understanding Results

### Security Grades
- **A+ (95-100)**: Excellent, production-ready
- **A (90-94)**: Very good, minor issues
- **B (75-89)**: Good, some concerns
- **C (60-74)**: Fair, needs improvement
- **D (50-59)**: Poor, significant issues
- **F (0-49)**: Critical issues, do not deploy

### Finding Priority
1. **🚨 Known Exploited** (is_known_exploited = true)
2. **📊 High EPSS** (epss_score > 0.7)
3. **🔴 Critical Severity** + High CVSS
4. **🟠 High Severity** vulnerabilities
5. **🔑 Exposed Secrets**

## 🌐 Language Support

### Fully Supported
- Python (`.py`, `requirements.txt`, `pyproject.toml`)
- JavaScript/TypeScript (`package.json`, `yarn.lock`)
- Go (`go.mod`, `go.sum`)
- Rust (`Cargo.toml`, `Cargo.lock`)
- Java (`pom.xml`, `build.gradle`)
- Ruby (`Gemfile`, `Gemfile.lock`)
- PHP (`composer.json`, `composer.lock`)
- .NET (`*.csproj`, `packages.config`)

### Package Managers
- pip, poetry, pipenv (Python)
- npm, yarn, pnpm (JavaScript)
- cargo (Rust)
- go mod (Go)
- maven, gradle (Java)
- gem, bundler (Ruby)
- composer (PHP)
- nuget (.NET)

## ⚡ Performance Tips

### Enable Caching
```yaml
# docker-compose.yml
volumes:
  - scanner-trivy-cache:/tmp/.trivy_cache
  - scanner-grype-cache:/tmp/.grype_cache
```

### Fast Mode
```json
{"options": {"fast_mode": true}}  // Skips comprehensive Trivy scan
```

### SBOM Reuse
1. Generate SBOM once with Syft
2. Scan SBOM multiple times with Grype
3. 10x faster for repeated scans

## 🔧 Troubleshooting

### Common Issues

**Slow first scan**
- Normal - downloading vulnerability databases
- Solution: Use cache volumes

**Out of memory**
- Large repositories need more RAM
- Solution: Increase Docker memory limit

**Network timeouts**
- Database updates blocked
- Solution: Configure proxy or use offline mode

### Debug Mode
```bash
docker run -e LOG_LEVEL=DEBUG ...
```

## 📦 Output Formats

### Default (JSON)
```json
{
  "security_score": 85.5,
  "findings": [...],
  "summary": {...}
}
```

### Key Fields
- `findings[].evidence.epss_score` - Exploit likelihood
- `findings[].evidence.is_known_exploited` - Active exploitation
- `findings[].evidence.fixed_versions` - Available fixes
- `scan_metadata.sbom_summary` - Package composition

## 🔗 Integration Examples

### CI/CD Pipeline
```yaml
# GitHub Actions
- name: Security Scan
  run: |
    response=$(curl -s -X POST http://scanner:8000/scan \
      -d '{"repository_url": "${{ github.event.repository.url }}"}')
    score=$(echo $response | jq '.security_score')
    if (( $(echo "$score < 75" | bc -l) )); then
      echo "Security score too low: $score"
      exit 1
    fi
```

### Python Client
```python
import requests

def scan_repo(url):
    response = requests.post(
        "http://scanner:8000/scan",
        json={"repository_url": url}
    )
    result = response.json()
    
    # Priority findings
    critical = [
        f for f in result['findings']
        if f['severity'] == 'critical' or
        f.get('evidence', {}).get('is_known_exploited')
    ]
    
    return result['security_score'], critical
```

## 📚 More Information

- [Universal Scanner Guide](UNIVERSAL_SCANNER_GUIDE.md)
- [Migration Guide](MIGRATION_GUIDE.md)
- [Full README](README.md)
