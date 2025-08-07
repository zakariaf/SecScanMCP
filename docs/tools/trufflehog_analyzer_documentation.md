# TruffleHog Integration - Advanced Secret Detection

## Overview

**TruffleHog** is an enterprise-grade secret scanning tool that searches for credentials and sensitive data across multiple sources:

- **800+ built-in detectors** for various secret types
- **Git history scanning** including deleted files and commits
- **High accuracy** with entropy-based detection algorithms
- **Multiple data sources** (git repos, filesystems, cloud storage)
- **Real-time verification** of discovered credentials

## Architecture  

TruffleHog runs as a native binary analyzer within the scanner container:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │ TruffleHog  │ │
│ │  Analyzer   │ │ 
│ └─────────────┘ │
└─────────────────┘
         │
         ▼
  ┌─────────────────┐
  │ Git Repository  │
  │ + File System   │
  │ + Full History  │
  └─────────────────┘
```

## Detection Capabilities

### Secret Types Detected

**Cloud Provider Credentials:**
- AWS Access Keys (IAM, S3, EC2)
- Azure Service Principal credentials
- Google Cloud Platform API keys
- DigitalOcean tokens

**Database Credentials:**  
- PostgreSQL connection strings
- MySQL passwords
- MongoDB credentials
- Redis authentication tokens

**API Keys & Tokens:**
- GitHub personal access tokens
- Slack bot tokens
- Stripe API keys
- JWT tokens with secrets

**Cryptographic Materials:**
- RSA private keys
- SSH private keys  
- TLS certificates and keys
- GPG private keys

**Application Secrets:**
- Hardcoded passwords
- Session secrets
- Encryption keys
- OAuth client secrets

### Detection Methods

**Entropy Analysis:**
- Statistical analysis of string randomness
- Identifies high-entropy strings likely to be secrets
- Configurable entropy thresholds

**Pattern Matching:**
- Regex patterns for known secret formats
- Context-aware detection (variable names, comments)
- Format-specific validators

**Credential Verification:**
- Real-time testing of discovered credentials
- Validates if secrets are active/working
- Reduces false positives significantly

## Configuration

### Scanner Integration

TruffleHog runs with optimized settings for MCP security scanning:

```python
# analyzers/security_tools/trufflehog_analyzer.py
TRUFFLEHOG_CONFIG = {
    'scan_depth': 100,           # Scan last 100 commits
    'only_verified': False,      # Include unverified secrets
    'include_detectors': 'all',  # Use all 800+ detectors
    'archive_timeout': '10m',    # Timeout for large repos
    'concurrency': 4,            # Parallel scanning threads
}
```

### Detection Filters

The analyzer applies intelligent filtering:

```python
EXCLUDE_PATTERNS = [
    r'test[_/].*',              # Test files
    r'.*\.example\..*',         # Example configurations
    r'.*\.template\..*',        # Template files
    r'docs?[/].*',             # Documentation
    r'.*[/]fixtures[/].*',     # Test fixtures
]

# High-confidence detectors prioritized for MCP scanning
PRIORITY_DETECTORS = [
    'github',
    'aws',
    'slack',
    'stripe',
    'jwt',
    'private_key',
]
```

## Usage

### Automatic Integration

TruffleHog runs automatically for all scanned repositories:

```bash
# Scan repository including full git history
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/project"}'
```

### Manual Execution

Direct TruffleHog analysis:

```bash
# Scan local repository
docker run --rm -v $(pwd):/workspace \
  trufflesecurity/trufflehog:latest \
  git file:///workspace --json

# Scan with verification enabled
trufflehog git https://github.com/example/repo --only-verified
```

### Programmatic Usage

```python
from analyzers.security_tools.trufflehog_analyzer import TruffleHogAnalyzer

analyzer = TruffleHogAnalyzer()
results = await analyzer.analyze('/path/to/repository')

for finding in results:
    print(f"Secret Type: {finding.vulnerability_type}")
    print(f"Location: {finding.location}")
    print(f"Verified: {finding.evidence.get('verified', False)}")
    print(f"Entropy: {finding.evidence.get('entropy_score', 'N/A')}")
```

## Output Format

### Finding Structure

```json
{
  "vulnerability_type": "hardcoded_secret",
  "severity": "high",
  "confidence": 0.9,
  "title": "GitHub Personal Access Token detected",
  "description": "GitHub token found in configuration file",
  "location": "config/settings.py:23",
  "recommendation": "Remove hardcoded token and use environment variables",
  "references": [
    "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"
  ],
  "evidence": {
    "detector_name": "github",
    "detector_type": "PrivateKey",
    "verified": true,
    "raw_secret": "ghp_xxxxxxxxxxxxxxxxxxxx",
    "redacted_secret": "ghp_*********************",
    "entropy_score": 4.8,
    "commit_hash": "abc123def456",
    "commit_author": "developer@company.com",
    "commit_date": "2024-08-07T10:30:00Z",
    "file_path": "config/settings.py",
    "line_number": 23
  },
  "tool": "trufflehog",
  "cwe_id": "CWE-798"
}
```

### Verification Status

Secrets are marked with verification status:

| Status | Description | Action |
|--------|-------------|--------|
| **Verified** | Secret tested and confirmed active | **Immediate remediation required** |
| **Unverified** | Pattern detected but not verified | Investigate and validate |
| **Inactive** | Secret tested and found inactive | Consider rotation for safety |

### Severity Mapping

TruffleHog findings are mapped by impact:

| Secret Type | Severity | Reasoning |
|------------|----------|-----------|
| Cloud Provider Keys | CRITICAL | Full infrastructure access |
| Database Credentials | CRITICAL | Data breach potential |
| API Tokens (verified) | HIGH | Service access compromise |
| Private Keys | HIGH | Authentication bypass |
| JWT Secrets | MEDIUM | Session hijacking risk |
| Generic Secrets | MEDIUM | Context-dependent risk |

## Performance

### Execution Speed
- **Small repos** (< 100 commits): 500ms-2s
- **Medium repos** (100-1000 commits): 2-10s  
- **Large repos** (> 1000 commits): 10-60s

### Resource Usage
- **CPU**: Moderate (multi-threaded scanning)
- **Memory**: ~200-500MB depending on repo size
- **Network**: Used for credential verification
- **Disk**: Temporary clone storage

### Optimization Features
- **Parallel processing**: Multi-threaded secret detection
- **Incremental scanning**: Focus on recent commits
- **Smart filtering**: Skip binary files and known safe paths
- **Caching**: Reuse results for unchanged repositories

## Integration Benefits

### Comprehensive Coverage

TruffleHog provides unique capabilities:

**Git History Analysis**: Unlike other tools, scans entire commit history
**Real-time Verification**: Tests if discovered credentials actually work
**Multiple Formats**: Detects secrets in code, configs, documentation

### MCP-Specific Value

For MCP servers, TruffleHog is crucial for detecting:

- **API keys** hardcoded in tool implementations
- **Database credentials** for MCP data storage
- **Service tokens** for external integrations
- **Private keys** used for authentication
- **Client secrets** for OAuth implementations

### Complementary Analysis

Works particularly well with:

**Bandit**: TruffleHog finds hardcoded secrets, Bandit analyzes usage patterns
**CodeQL**: TruffleHog detects credentials, CodeQL finds injection vulnerabilities
**Intelligent Analyzer**: TruffleHog identifies secrets, Intelligent assesses legitimacy

## Common Issues and Solutions

### False Positives

**Issue**: High entropy strings that aren't secrets
**Solution**: Use verification to filter active credentials

**Issue**: Example/template secrets flagged
**Solution**: Exclude template files and documentation

**Issue**: Test fixtures with dummy credentials  
**Solution**: Apply exclude patterns for test directories

### Performance Optimization

```python
# Limit scan depth for faster results
MAX_SCAN_DEPTH = 50  # Last 50 commits only

# Focus on high-value detectors
PRIORITY_ONLY = True  # Skip low-confidence detectors

# Increase timeout for large repos
ARCHIVE_TIMEOUT = '15m'  # Extended timeout
```

### Rate Limiting

```python
# Avoid hitting API rate limits during verification
VERIFICATION_CONFIG = {
    'rate_limit': 10,      # Max 10 verifications per second
    'timeout': 30,         # 30s timeout per verification
    'retry_count': 3,      # Retry failed verifications
}
```

## Best Practices

### Development Workflow

1. **Pre-commit scanning**: Run TruffleHog before commits
2. **CI/CD integration**: Block deployments with verified secrets
3. **Regular audits**: Periodic full history scans
4. **Incident response**: Immediate rotation of verified secrets

### Remediation Priority

**Critical (Immediate Action)**:
- Verified cloud provider credentials
- Active database passwords  
- Working API tokens

**High (Within 24 hours)**:
- Private keys and certificates
- Unverified but high-entropy secrets
- OAuth client credentials

**Medium (Within week)**:
- Inactive/expired credentials
- Low-confidence pattern matches
- Development environment secrets

### Secret Management

**Best Practices**:
- Use environment variables for all secrets
- Implement secret rotation policies
- Use dedicated secret management services
- Apply principle of least privilege

## Monitoring and Alerting

### Security Metrics

Track important security indicators:

```json
{
  "total_secrets_found": 12,
  "verified_secrets": 3,
  "critical_findings": 2,
  "remediation_required": true,
  "scan_coverage": {
    "commits_scanned": 150,
    "files_analyzed": 1247,
    "detectors_used": 800
  }
}
```

### Alerting Integration

Configure alerts for critical findings:

```python
ALERT_CONDITIONS = {
    'verified_secrets': True,      # Always alert on verified secrets
    'critical_severity': True,     # Alert on critical findings
    'high_entropy': True,         # Alert on high-entropy strings
    'new_secrets': True,          # Alert on newly introduced secrets
}
```

## Troubleshooting

### Common Problems

**Q: TruffleHog taking too long on large repositories**
A: Reduce scan depth or use `--since` to limit time range

**Q: Too many false positives from entropy detection**
A: Enable `--only-verified` to focus on working credentials

**Q: Missing secrets in recent commits**
A: Ensure git history is fully available and accessible

### Debug Mode

Enable detailed logging:

```bash
# Verbose TruffleHog execution
trufflehog git /path/to/repo --debug --json

# Check detector status
trufflehog --list-detectors
```

### Version Information

```bash
# Check TruffleHog version
trufflehog --version

# Verify container version  
docker run trufflesecurity/trufflehog:latest --version
```