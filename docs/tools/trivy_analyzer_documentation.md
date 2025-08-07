# Trivy Integration - All-in-One Security Scanner

## Overview

**Trivy** is a comprehensive security scanner by Aqua Security that provides multi-faceted vulnerability detection:

- **Universal Coverage** - 20+ programming languages and package managers
- **Multiple Scan Types** - Vulnerabilities, secrets, misconfigurations, licenses
- **High Performance** - Fast scanning with cached vulnerability databases
- **Container Native** - Optimized for modern containerized applications
- **Enterprise Ready** - Used by major organizations worldwide

## Architecture

Trivy runs as a native binary within the scanner container with multiple scan modes:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │    Trivy    │ │
│ │   Scanner   │ │
│ └─────────────┘ │
└─────────────────┘
         │
    ┌────┼────┐
    │    │    │
    ▼    ▼    ▼
┌──────┬──────┬────────┐
│ Vuln │Secret│Misconf │
│ DB   │Rules │Rules   │
│ 24M+ │ 800+ │ 2000+  │
└──────┴──────┴────────┘
```

## Detection Capabilities

### Scan Types

**1. Vulnerability Scanning:**
- OS packages (Alpine, Debian, RedHat, etc.)
- Language dependencies (npm, pip, cargo, go mod, etc.)
- Known CVEs with CVSS scores
- EPSS (Exploit Prediction Scoring System) data

**2. Secret Detection:**
- API keys (AWS, GitHub, Slack, etc.)
- Private keys and certificates
- Database credentials
- Authentication tokens

**3. Misconfiguration Detection:**
- Dockerfile security best practices
- Kubernetes manifest security
- Terraform/CloudFormation issues
- CI/CD configuration problems

**4. License Scanning:**
- License compatibility checks
- GPL/AGPL detection
- Commercial license violations
- SPDX license identification

### Supported Languages & Ecosystems

**Package Managers:**
```
Python     → pip, pipenv, poetry
JavaScript → npm, yarn, pnpm
Go         → go.mod, Gopkg.lock
Rust       → Cargo.toml
Java       → Maven, Gradle
Ruby       → Bundler
PHP        → Composer
.NET       → NuGet
```

**Configuration Formats:**
- Docker/Containerfile
- Kubernetes YAML
- Terraform (.tf)
- CloudFormation (JSON/YAML)
- Helm charts

### Example Detections

**Vulnerable Dependency:**
```json
{
  "library": "requests",
  "version": "2.25.1", 
  "cve": "CVE-2023-32681",
  "severity": "MEDIUM",
  "fixed_version": "2.31.0"
}
```

**Secret Detection:**
```python
# DETECTED: GitHub token
GITHUB_TOKEN = "ghp_1234567890abcdef..."

# DETECTED: AWS credentials  
aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Misconfiguration:**
```dockerfile
# DETECTED: Running as root user
FROM ubuntu
RUN apt-get update && apt-get install -y curl
# Missing: USER non-root-user
```

## Configuration

### Scan Options

Trivy runs with comprehensive scanning enabled:

```python
# analyzers/trivy_analyzer.py
TRIVY_CONFIG = {
    'scanners': 'vuln,secret,config,license',  # All scan types
    'severity': 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',  # All severities
    'format': 'json',                          # Machine-readable output  
    'timeout': '300s',                         # 5-minute timeout
    'cache_dir': '/tmp/trivy-cache',          # Persistent cache
    'skip_update': False,                      # Always update databases
}
```

### Scanner Configuration

Individual scanners can be tuned:

```python
SCANNER_SETTINGS = {
    'vulnerability': {
        'skip_dirs': ['node_modules', '__pycache__', '.git'],
        'skip_files': ['*.min.js', '*.map'],
        'offline_scan': False,  # Use online CVE database
    },
    'secret': {
        'skip_dirs': ['tests', 'test', '.git'],
        'skip_files': ['*.example.*', '*.template.*'],
        'enable_builtin_rules': True,
    },
    'config': {
        'include_non_failures': False,  # Only report actual issues
        'trace': False,                 # Minimal output
    },
    'license': {
        'forbidden': ['GPL-3.0', 'AGPL-3.0'],  # Problematic licenses
        'restricted': ['LGPL-2.1', 'MPL-2.0'], # Review required
    }
}
```

## Usage

### Automatic Integration

Trivy runs automatically for all scanned repositories:

```bash
# Comprehensive scan including all Trivy capabilities
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/project"}'
```

### Manual Execution

Direct Trivy scanning:

```bash
# All-in-one scan
trivy fs --scanners vuln,secret,config,license --format json /path/to/code

# Vulnerability scan only
trivy fs --scanners vuln --severity HIGH,CRITICAL /path/to/project

# Secret scanning
trivy fs --scanners secret --format table /path/to/repo

# Configuration analysis
trivy config /path/to/kubernetes/manifests
```

### Programmatic Usage

```python
from analyzers.trivy_analyzer import TrivyAnalyzer

analyzer = TrivyAnalyzer()
results = await analyzer.analyze('/path/to/project')

for finding in results:
    print(f"Type: {finding.vulnerability_type}")
    print(f"Severity: {finding.severity}")
    print(f"Package: {finding.evidence.get('package_name', 'N/A')}")
    print(f"CVE: {finding.evidence.get('cve_id', 'N/A')}")
```

## Output Format

### Vulnerability Finding

```json
{
  "vulnerability_type": "vulnerable_dependency",
  "severity": "high",
  "confidence": 1.0,
  "title": "lodash: Prototype Pollution vulnerability",
  "description": "lodash prior to 4.17.19 is vulnerable to Prototype Pollution",
  "location": "package.json",
  "recommendation": "Update lodash to version 4.17.19 or higher",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2020-8203",
    "https://github.com/advisories/GHSA-p6mc-m468-83gw"
  ],
  "evidence": {
    "package_name": "lodash",
    "installed_version": "4.17.15",
    "fixed_version": "4.17.19",
    "cve_id": "CVE-2020-8203",
    "cvss_score": 7.4,
    "epss_score": 0.004,
    "vulnerability_id": "GHSA-p6mc-m468-83gw",
    "data_source": "ghsa",
    "published_date": "2020-07-15T19:15:00Z",
    "last_modified": "2021-07-21T11:39:00Z"
  },
  "tool": "trivy",
  "cwe_id": "CWE-1321"
}
```

### Secret Finding

```json
{
  "vulnerability_type": "hardcoded_secret", 
  "severity": "high",
  "confidence": 0.9,
  "title": "GitHub Personal Access Token detected",
  "description": "GitHub token found in configuration file",
  "location": "config/settings.py:15",
  "recommendation": "Remove hardcoded token and use environment variables",
  "references": [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure"
  ],
  "evidence": {
    "rule_id": "github-pat",
    "category": "GitHub",
    "matched_string": "ghp_xxxxxxxxxxxxxxxxxxxx",
    "start_line": 15,
    "end_line": 15,
    "code_snippet": "GITHUB_TOKEN = 'ghp_xxxxxxxxxxxxxxxxxxxx'",
    "entropy": 4.2
  },
  "tool": "trivy",
  "cwe_id": "CWE-798"
}
```

### Misconfiguration Finding

```json
{
  "vulnerability_type": "insecure_configuration",
  "severity": "medium",
  "confidence": 1.0,
  "title": "Container running as root user",
  "description": "Container is configured to run as root user",
  "location": "Dockerfile:5",
  "recommendation": "Add USER instruction to run as non-root user",
  "references": [
    "https://docs.docker.com/develop/dev-best-practices/#dont-run-as-root"
  ],
  "evidence": {
    "policy_id": "DS002",
    "policy_title": "Root user",
    "policy_description": "Container running as root",
    "resolution": "Add 'USER <non root user name>' line to the Dockerfile",
    "severity": "MEDIUM",
    "primary_url": "https://avd.aquasec.com/misconfig/ds002"
  },
  "tool": "trivy", 
  "cwe_id": "CWE-250"
}
```

## Performance

### Execution Speed
- **Small projects** (< 100 files): 2-5s
- **Medium projects** (100-1000 files): 5-15s  
- **Large projects** (> 1000 files): 15-60s

*Initial scans are slower due to database downloads*

### Resource Usage
- **CPU**: Moderate usage, multi-threaded scanning
- **Memory**: ~200-500MB depending on project size
- **Network**: Downloads vulnerability databases (~400MB)
- **Disk**: ~1GB cache for vulnerability databases

### Database Updates
- **Vulnerability DB**: Updated daily from multiple sources
- **Secret Rules**: Community-maintained patterns
- **Config Policies**: Security best practices database
- **License DB**: SPDX license information

## Integration Benefits

### Comprehensive Coverage

Trivy provides unique value through:

**Universal Language Support**: Single tool covers 20+ ecosystems
**Multiple Scan Types**: Vulnerabilities, secrets, configs, licenses in one pass
**High Accuracy**: Low false positive rates with curated databases
**Performance**: Optimized for CI/CD integration

### MCP-Specific Value  

For MCP servers, Trivy is essential for:

- **Dependency vulnerabilities** in MCP SDK and tool libraries
- **Container security** for containerized MCP deployments
- **Secret detection** in MCP server configuration files
- **License compliance** for MCP server distributions
- **Configuration security** for deployment manifests

### Complementary Analysis

Works especially well with:

**Grype**: Trivy provides broad coverage, Grype offers focused vulnerability scanning
**Syft**: Trivy scans SBOMs generated by Syft for comprehensive analysis
**TruffleHog**: Trivy finds secret patterns, TruffleHog validates credentials
**CodeQL**: Trivy finds dependencies issues, CodeQL analyzes source code logic

## Advanced Configuration

### Custom Policies

Create custom misconfiguration policies:

```yaml
# custom-policy.rego
package trivy.mcp

deny[msg] {
  input.kind == "ConfigMap"
  input.metadata.name
  contains(input.data[_], "password")
  msg := "ConfigMap contains potential password"
}
```

### License Policy

Configure license restrictions:

```yaml
# .trivy-license.yaml
license:
  forbidden:
    - GPL-3.0-only
    - GPL-3.0-or-later  
    - AGPL-3.0-only
    - AGPL-3.0-or-later
  restricted:
    - LGPL-2.1-only
    - LGPL-2.1-or-later
    - MPL-2.0
  allowed:
    - MIT
    - Apache-2.0
    - BSD-3-Clause
    - ISC
```

### Vulnerability Filtering

Filter vulnerabilities by criteria:

```yaml
# .trivyignore
# Ignore specific CVEs
CVE-2022-12345

# Ignore vulnerabilities in test files  
tests/**

# Ignore low severity in development dependencies
package.json:devDependencies:MEDIUM,LOW
```

## Monitoring and Metrics

### Scan Metrics

Track important scanning metrics:

```json
{
  "scan_duration_seconds": 45.2,
  "vulnerabilities_found": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "unknown": 1
  },
  "secrets_found": 3,
  "misconfigurations_found": 7,
  "licenses_checked": 245,
  "database_version": "2024-08-07T10:30:00Z",
  "cache_hit_ratio": 0.85
}
```

### Database Freshness

Monitor vulnerability database updates:

```python
DATABASE_CHECKS = {
    'max_age_hours': 24,        # Alert if DB older than 24h
    'update_frequency': 'daily', # Expected update frequency
    'sources': [                 # Monitor data sources
        'nvd', 'ghsa', 'glad', 'redhat', 'alpine'
    ]
}
```

## Troubleshooting

### Common Issues

**Q: Trivy taking too long to scan**
A: Enable persistent caching and skip unnecessary scan types

**Q: Network timeouts during database updates**
A: Increase timeout settings or use offline databases

**Q: Too many false positives in secret scanning**
A: Configure exclusion patterns for test/example files

**Q: Missing vulnerabilities for specific packages**
A: Ensure vulnerability database is up to date

### Performance Optimization

```python
# Optimize for CI/CD environments
CI_CONFIG = {
    'cache_dir': '/persistent-cache/trivy',  # Persistent across builds
    'timeout': '120s',                       # Shorter timeout for CI
    'skip_update': True,                     # Skip DB update in CI
    'parallel': 4,                           # Parallel scanning  
    'severity': 'HIGH,CRITICAL',             # Focus on critical issues
}

# Production scanning configuration
PRODUCTION_CONFIG = {
    'scanners': 'vuln,secret,config',        # Skip license scan
    'skip_dirs': ['node_modules', '.git'],   # Exclude large directories
    'format': 'json',                        # Machine readable
    'list_all_pkgs': False,                  # Only vulnerable packages
}
```

### Debug Mode

Enable detailed debugging:

```bash
# Debug Trivy execution
trivy --debug fs /path/to/code

# Check database status
trivy --cache-dir /tmp/trivy-cache image --download-db-only

# Validate configuration
trivy --config trivy.yaml fs --dry-run /path/to/code
```

### Cache Management

```bash
# Clear cache
trivy clean --all

# Check cache size
du -sh /tmp/trivy-cache

# Manual database update
trivy --cache-dir /tmp/trivy-cache image --download-db-only
```

## Best Practices

### Development Workflow

1. **Local Development**: Run Trivy on commit to catch issues early
2. **CI/CD Integration**: Block builds with critical vulnerabilities
3. **Regular Updates**: Keep vulnerability databases current  
4. **Policy as Code**: Version control Trivy configurations

### Remediation Strategy

**Priority Order**:
1. **Critical vulnerabilities** in direct dependencies
2. **Secrets** in production code paths
3. **High misconfigurations** in deployment configs
4. **License violations** blocking distribution

### Configuration Management

```python
# Environment-specific configs
ENVIRONMENTS = {
    'development': {
        'severity': 'HIGH,CRITICAL',
        'skip_update': False,
        'timeout': '600s',
    },
    'ci': {
        'severity': 'CRITICAL',
        'skip_update': True,
        'timeout': '120s',
    },
    'production': {
        'severity': 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL',
        'skip_update': False,
        'timeout': '300s',
    }
}
```

## Version Information

```bash
# Check Trivy version
trivy version

# List supported scanners
trivy --help | grep -A 10 "Available Commands"

# Check database versions
trivy --cache-dir /tmp/trivy-cache db --list
```