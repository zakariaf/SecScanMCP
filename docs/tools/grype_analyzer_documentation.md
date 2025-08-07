# Grype Integration - Fast Vulnerability Scanner

## Overview

**Grype** is a high-performance vulnerability scanner by Anchore designed for speed and accuracy:

- **Blazing Fast** - Optimized for CI/CD with sub-second scan times
- **Low False Positives** - Curated vulnerability database with high accuracy
- **SBOM Integration** - Works seamlessly with Syft-generated SBOMs  
- **Risk Prioritization** - Includes EPSS and KEV data for threat intelligence
- **Multiple Formats** - Supports JSON, SARIF, table, and custom outputs

## Architecture

Grype operates in two modes - direct filesystem scanning or SBOM analysis:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │    Grype    │ │
│ │   Scanner   │ │
│ └─────────────┘ │
└─────────────────┘
         │
    ┌────┴─────┐
    │          │
    ▼          ▼
┌─────────┐ ┌──────────┐
│ Direct  │ │   SBOM   │
│FileScan │ │  Scan    │
└─────────┘ └──────────┘
    │            │
    ▼            ▼
┌─────────────────────┐
│   Vulnerability     │
│     Database        │
│   (24M+ entries)    │ 
└─────────────────────┘
```

## Detection Capabilities

### Vulnerability Sources

**Primary Databases:**
- **NVD (National Vulnerability Database)** - NIST-maintained CVE database
- **GitHub Security Advisories (GHSA)** - Community-reported vulnerabilities
- **Alpine SecDB** - Alpine Linux security database
- **RHEL/CentOS Security** - Red Hat Enterprise Linux advisories
- **Debian Security Tracker** - Debian package vulnerabilities

**Advanced Risk Data:**
- **EPSS (Exploit Prediction Scoring System)** - ML-based exploit likelihood
- **KEV (Known Exploited Vulnerabilities)** - CISA catalog of active exploits
- **VEX (Vulnerability Exchange)** - Supplier vulnerability assessments

### Supported Ecosystems

**Package Managers:**
```
Python     → pip, pipenv, poetry, conda
JavaScript → npm, yarn, pnpm  
Go         → go.mod, Gopkg
Rust       → Cargo.toml
Java       → Maven, Gradle, JAR analysis
Ruby       → Bundler, gemspec
PHP        → Composer  
.NET       → NuGet, packages.config
```

**Operating Systems:**
- Alpine Linux, Debian/Ubuntu
- RHEL/CentOS/Fedora, Amazon Linux
- SUSE/openSUSE, Oracle Linux
- Windows (limited support)

### Example Vulnerabilities Detected

**High-Risk Package Vulnerability:**
```json
{
  "package": "lodash@4.17.15",
  "cve": "CVE-2020-8203", 
  "severity": "High",
  "cvss_score": 7.4,
  "epss_score": 0.004,
  "kev_catalog": false,
  "fixed_version": "4.17.19"
}
```

**Critical System Library Issue:**
```json
{
  "package": "openssl@1.1.1d", 
  "cve": "CVE-2022-0778",
  "severity": "Critical",
  "cvss_score": 9.8,
  "epss_score": 0.754,
  "kev_catalog": true,
  "fixed_version": "1.1.1n"
}
```

## Configuration

### Scan Configuration

Grype runs with optimized settings for comprehensive coverage:

```python
# analyzers/grype_analyzer.py
GRYPE_CONFIG = {
    'output': 'json',                    # Machine-readable output
    'scope': 'all-layers',              # Scan all container layers
    'fail_on': 'high',                  # Exit code on high+ severity
    'only_fixed': False,                # Include vulnerabilities without fixes
    'add_cpes_if_none': True,           # Generate CPEs for unmatched packages
    'by_cve': False,                    # Group by package, not CVE
}
```

### Database Configuration

```python
DATABASE_CONFIG = {
    'auto_update': True,                # Keep vulnerability DB current
    'update_url': 'https://toolbox-data.anchore.io/grype/databases/',
    'cache_dir': '/tmp/grype-cache',    # Persistent cache location
    'max_allowed_built_age': '120h',    # Max DB age before update required
}
```

### Performance Tuning

```python
PERFORMANCE_CONFIG = {
    'registry_timeout': '30s',          # Container registry timeout
    'request_timeout': '60s',           # HTTP request timeout
    'parallelism': 1,                   # Concurrent scans (CPU bound)
    'platform': 'linux/amd64',         # Target platform for analysis
}
```

## Usage

### Automatic Integration

Grype runs automatically in the scanning pipeline:

```bash
# Standard repository scan includes Grype analysis
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/project"}'
```

### SBOM-Based Scanning

Grype works optimally with Syft-generated SBOMs:

```bash
# Generate SBOM with Syft, then scan with Grype
syft /path/to/project -o spdx-json=/tmp/project.spdx.json
grype sbom:/tmp/project.spdx.json --output json
```

### Manual Execution

Direct Grype usage:

```bash
# Scan filesystem directly
grype dir:/path/to/project --output json

# Scan with specific severity filter
grype /path/to/project --fail-on high --output table

# Scan container image
grype alpine:latest --output sarif
```

### Programmatic Usage

```python
from analyzers.grype_analyzer import GrypeAnalyzer

analyzer = GrypeAnalyzer()
results = await analyzer.analyze('/path/to/project')

for finding in results:
    print(f"Package: {finding.evidence.get('package_name')}")
    print(f"CVE: {finding.evidence.get('cve_id')}")
    print(f"Severity: {finding.severity}")
    print(f"EPSS Score: {finding.evidence.get('epss_score', 'N/A')}")
    print(f"In KEV: {finding.evidence.get('kev_catalog', False)}")
```

## Output Format

### Vulnerability Finding

```json
{
  "vulnerability_type": "vulnerable_dependency",
  "severity": "high",
  "confidence": 1.0,
  "title": "express: Open Redirect vulnerability",
  "description": "express before 4.17.1 is vulnerable to open redirect",
  "location": "package.json",
  "recommendation": "Update express to version 4.17.1 or higher",
  "references": [
    "https://nvd.nist.gov/vuln/detail/CVE-2021-44906",
    "https://github.com/advisories/GHSA-rv95-896h-c2vc"
  ],
  "evidence": {
    "package_name": "express",
    "package_version": "4.16.4", 
    "package_type": "npm",
    "cve_id": "CVE-2021-44906",
    "vulnerability_id": "GHSA-rv95-896h-c2vc",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    "cvss_score": 6.1,
    "epss_score": 0.0043,
    "epss_percentile": 0.6891,
    "kev_catalog": false,
    "fixed_version": "4.17.1",
    "data_source": "ghsa",
    "namespace": "github:language:javascript",
    "related_vulnerabilities": ["CVE-2021-44906"],
    "match_details": {
      "type": "exact-direct-match",
      "matcher": "javascript-matcher",
      "search_key": "express@4.16.4"
    }
  },
  "tool": "grype",
  "cwe_id": "CWE-601"
}
```

### Risk Assessment Data

```json
{
  "risk_assessment": {
    "epss_data": {
      "score": 0.0043,
      "percentile": 0.6891,
      "date": "2024-08-07"
    },
    "kev_data": {
      "in_catalog": false,
      "date_added": null,
      "due_date": null,
      "notes": null
    },
    "cvss_data": {
      "version": "3.1",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
      "base_score": 6.1,
      "exploitability_score": 2.8,
      "impact_score": 2.7
    }
  }
}
```

## Performance

### Execution Speed
- **SBOM Scanning**: 100-500ms (pre-generated SBOM)
- **Direct Filesystem**: 1-5s (small projects)
- **Large Projects**: 5-30s (1000+ packages)
- **Container Images**: 2-10s (depending on layers)

### Resource Usage
- **CPU**: Low impact, mostly I/O bound
- **Memory**: ~50-200MB depending on project size  
- **Network**: Database updates (~200MB initially)
- **Disk**: ~500MB for vulnerability database cache

### Optimization Features
- **SBOM Caching**: Reuse Syft SBOMs across scans
- **Database Caching**: Persistent vulnerability database
- **Incremental Updates**: Delta updates for database
- **Parallel Processing**: Concurrent package analysis

## Integration Benefits

### Speed Optimization

Grype is designed for CI/CD performance:

**Fast Cold Start**: Pre-cached databases in container
**SBOM Integration**: Skip package discovery phase with Syft
**Minimal I/O**: Efficient database queries and caching
**Incremental Updates**: Only download database changes

### Accuracy Focus

**Low False Positives**: Curated vulnerability matching
**Version Matching**: Precise package version analysis
**Context Awareness**: Considers package installation method
**Quality Metrics**: EPSS and KEV provide exploit likelihood

### MCP-Specific Value

For MCP servers, Grype excels at:

- **Dependency Risk Assessment** - Prioritize fixes based on EPSS/KEV data
- **Supply Chain Security** - Identify compromised packages in MCP tools
- **Compliance Scanning** - Meet security requirements for MCP deployments
- **CI/CD Integration** - Fast feedback loop for MCP development

### Complementary Analysis

Works optimally with:

**Syft**: Generates SBOMs that Grype analyzes for maximum speed
**Trivy**: Grype focuses on vulnerabilities, Trivy adds secrets/configs
**TruffleHog**: Grype finds package issues, TruffleHog finds credential issues
**CodeQL**: Grype handles dependencies, CodeQL analyzes source code

## Advanced Features

### VEX Integration

Filter out false positives using VEX documents:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://example.com/vex/project-v1.0.0",
  "author": "MCP Security Team",
  "statements": [{
    "vulnerability": "CVE-2023-12345",
    "products": ["pkg:npm/lodash@4.17.15"],
    "status": "not_affected",
    "justification": "vulnerable_code_not_in_execute_path"
  }]
}
```

### Custom Matching Rules

Configure vulnerability matching behavior:

```yaml
# grype.yaml
match:
  java:
    using-cpes: true
    use-network: true
  javascript:
    using-cpes: false
    use-network: false
  python:
    using-cpes: true
    use-network: true

ignore:
  - vulnerability: CVE-2023-12345
    fix-state: wont-fix
  - package:
      name: lodash
      version: 4.17.15
    vulnerability: CVE-2020-8203
```

### Output Templating

Custom output formats:

```bash
# Custom template for security reports
grype /path/to/project --output template \
  --template-file custom-security-report.tmpl
```

## Monitoring and Alerting

### Vulnerability Metrics

Track key security indicators:

```json
{
  "scan_summary": {
    "total_vulnerabilities": 15,
    "by_severity": {
      "critical": 1,
      "high": 4, 
      "medium": 7,
      "low": 3
    },
    "epss_high_risk": 2,
    "kev_catalog_matches": 1,
    "packages_scanned": 234,
    "scan_duration_seconds": 3.2
  }
}
```

### Alerting Thresholds

Configure alerts based on risk factors:

```python
ALERT_CONDITIONS = {
    'critical_vulnerabilities': 0,      # Alert on any critical
    'kev_catalog_matches': 0,          # Alert on known exploits
    'epss_threshold': 0.7,             # Alert on high EPSS scores
    'cvss_threshold': 8.0,             # Alert on CVSS 8.0+
    'unfixed_vulnerabilities': 5,      # Alert on many unfixed issues
}
```

## Troubleshooting

### Common Issues

**Q: Grype not detecting vulnerabilities in dependencies**
A: Ensure package manifest files (package.json, requirements.txt) are present

**Q: Scan taking too long**
A: Use SBOM-based scanning with Syft for faster results

**Q: Database update failures**
A: Check network connectivity and disk space for cache directory

**Q: False positives in vulnerability matches**
A: Configure VEX documents or custom ignore rules

### Performance Optimization

```python
# CI/CD optimized configuration
CI_CONFIG = {
    'cache_dir': '/persistent-cache/grype',  # Persistent across builds
    'fail_on': 'critical',                   # Only fail on critical
    'only_fixed': True,                      # Skip unfixed vulnerabilities
    'scope': 'squashed',                     # Faster container scanning
}

# Development configuration
DEV_CONFIG = {
    'output': 'table',                       # Human readable output
    'fail_on': 'high',                       # Fail on high+ severity
    'show_suppressed': True,                 # Show ignored vulnerabilities
    'only_fixed': False,                     # Include all vulnerabilities
}
```

### Debug Mode

Enable detailed debugging:

```bash
# Verbose Grype execution
grype /path/to/project --output json --verbose

# Debug database operations
grype db status --verbose

# Test specific vulnerability matching
grype /path/to/project --only-fixed=false --show-suppressed
```

### Database Management

```bash
# Update vulnerability database
grype db update

# Check database status and age
grype db status

# Clean database cache
grype db delete
```

## Best Practices

### CI/CD Integration

1. **Cache Database**: Persist Grype cache across builds
2. **SBOM Pipeline**: Generate SBOM with Syft, scan with Grype
3. **Fail Fast**: Configure appropriate failure thresholds
4. **Reporting**: Export results in SARIF format for security dashboards

### Vulnerability Management

**Prioritization Strategy**:
1. **KEV Catalog matches** (actively exploited)
2. **High EPSS scores** (likely to be exploited)
3. **Critical CVSS scores** (high impact)
4. **Fixed vulnerabilities** (patches available)

### Configuration Management

```python
# Environment-specific scanning
CONFIGS = {
    'production': {
        'fail_on': 'high',
        'only_fixed': True,
        'include_epss': True,
    },
    'development': {
        'fail_on': 'critical', 
        'only_fixed': False,
        'show_suppressed': True,
    },
    'ci': {
        'fail_on': 'high',
        'only_fixed': True,
        'cache_dir': '/ci-cache/grype',
    }
}
```

## Version Information

```bash
# Check Grype version
grype version

# Check database version and age  
grype db status

# List supported formats
grype --help | grep -A 5 "output formats"
```