# Syft Integration - SBOM Generation and Analysis

## Overview

**Syft** is a comprehensive Software Bill of Materials (SBOM) generator by Anchore that provides deep visibility into software components:

- **Universal Package Discovery** - Detects packages across 20+ ecosystems
- **Binary Analysis** - Identifies embedded libraries and components
- **Multiple SBOM Formats** - SPDX, CycloneDX, GitHub dependency snapshots
- **License Detection** - Comprehensive license identification and compliance
- **Supply Chain Visibility** - Complete component inventory for security analysis

## Architecture

Syft operates as a component discovery engine that feeds other security tools:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │    Syft     │ │
│ │  Analyzer   │ │
│ └─────────────┘ │
└─────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│        SBOM Generation          │
├─────────────────────────────────┤
│ • Package Discovery (20+ langs) │
│ • Binary Analysis & Cataloging  │
│ • License Detection & Mapping   │ 
│ • Dependency Graph Construction │
└─────────────────────────────────┘
         │
    ┌────┼────┐
    │    │    │
    ▼    ▼    ▼
┌─────┬─────┬──────┐
│Grype│Trivy│Other │
│Vuln │Scan │Tools │
└─────┴─────┴──────┘
```

## Detection Capabilities

### Package Discovery

**Language Ecosystems:**
```
Python     → pip, pipenv, poetry, conda, wheel
JavaScript → npm, yarn, pnpm, bower
Go         → go.mod, Gopkg.lock, binaries
Rust       → Cargo.toml, binaries  
Java       → Maven, Gradle, JAR/WAR analysis
Ruby       → Bundler, gemspec
PHP        → Composer
.NET       → NuGet, packages.config
C/C++      → Conan, vcpkg
```

**Binary Analysis:**
- Statically linked libraries
- Embedded package managers
- Native dependencies
- System libraries

**Container Layers:**
- Multi-stage build analysis
- Layer-by-layer component discovery  
- Base image component identification
- Application layer isolation

### License Detection

**License Sources:**
- Package manifest declarations
- LICENSE files and headers
- SPDX license identifiers
- Custom license text analysis

**License Categories:**
```
Permissive:  MIT, Apache-2.0, BSD-3-Clause
Copyleft:    GPL-2.0, GPL-3.0, AGPL-3.0
Weak:        LGPL-2.1, MPL-2.0
Commercial:  Custom commercial licenses
Unknown:     Unidentified license text
```

### Example Discovery Results

**Package Discovery:**
```json
{
  "name": "lodash",
  "version": "4.17.21",
  "type": "npm",
  "foundBy": "javascript-package-cataloger", 
  "locations": ["/package.json", "/package-lock.json"],
  "licenses": ["MIT"],
  "purl": "pkg:npm/lodash@4.17.21"
}
```

**Binary Component:**
```json
{
  "name": "openssl",
  "version": "1.1.1k", 
  "type": "binary",
  "foundBy": "binary-cataloger",
  "locations": ["/usr/bin/openssl"],
  "licenses": ["OpenSSL"],
  "cpes": ["cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"]
}
```

## Configuration

### SBOM Generation Settings

Syft runs with comprehensive discovery enabled:

```python
# analyzers/syft_analyzer.py
SYFT_CONFIG = {
    'output_format': 'spdx-json',       # SPDX 2.3 JSON format
    'scope': 'all-layers',              # Scan all container layers
    'catalogers': 'all',                # Use all package catalogers
    'exclude_binary_overlap_by_ownership': True,  # Reduce noise
    'select_catalogers': [              # Optional: specific catalogers
        'javascript-package-cataloger',
        'python-package-cataloger', 
        'go-module-binary-cataloger',
        'java-archive-cataloger',
    ]
}
```

### Output Format Selection

```python
SUPPORTED_FORMATS = {
    'spdx-json': 'SPDX 2.3 JSON format (recommended)',
    'spdx-tag-value': 'SPDX 2.3 tag-value format',
    'cyclonedx-json': 'CycloneDX 1.4 JSON format',
    'cyclonedx-xml': 'CycloneDX 1.4 XML format', 
    'github-json': 'GitHub dependency snapshot',
    'syft-json': 'Syft native JSON format',
    'table': 'Human-readable table format',
}
```

### Performance Configuration

```python
PERFORMANCE_CONFIG = {
    'parallelism': 1,                   # Cataloger parallelism
    'registry_timeout': '30s',          # Container registry timeout
    'platform': 'linux/amd64',         # Target platform
    'from_unpack_dir': True,            # Use unpacked directory analysis
    'exclude_patterns': [               # Skip noisy directories
        '**/node_modules/**',
        '**/.git/**',
        '**/test/**',
        '**/tests/**',
    ]
}
```

## Usage

### Automatic Integration

Syft runs automatically to generate SBOMs for vulnerability analysis:

```bash
# Standard scan includes SBOM generation
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/project"}'
```

### Manual SBOM Generation

Direct Syft usage for SBOM creation:

```bash
# Generate SPDX JSON SBOM
syft /path/to/project -o spdx-json=project.spdx.json

# Generate CycloneDX SBOM
syft /path/to/project -o cyclonedx-json=project.cyclonedx.json

# Analyze container image
syft alpine:latest -o spdx-json=alpine.spdx.json

# Human-readable output
syft /path/to/project -o table
```

### Programmatic Usage

```python
from analyzers.syft_analyzer import SyftAnalyzer

analyzer = SyftAnalyzer()
results = await analyzer.analyze('/path/to/project')

# Syft findings focus on licensing and component visibility
for finding in results:
    if finding.vulnerability_type == VulnerabilityType.LICENSE_VIOLATION:
        print(f"License Issue: {finding.title}")
        print(f"Package: {finding.evidence.get('package_name')}")
        print(f"License: {finding.evidence.get('license')}")
        print(f"Location: {finding.location}")
```

## Output Format

### SBOM Structure (SPDX)

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "project-sbom",
  "documentNamespace": "https://scanner.local/project-sbom-uuid",
  "creationInfo": {
    "created": "2024-08-07T14:32:11Z",
    "creators": ["Tool: syft-v0.90.0"]
  },
  "packages": [
    {
      "SPDXID": "SPDXRef-Package-npm-lodash-4.17.21",
      "name": "lodash",
      "versionInfo": "4.17.21",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "packageVerificationCode": {
        "packageVerificationCodeValue": "0000000000000000000000000000000000000000"
      },
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl", 
          "referenceLocator": "pkg:npm/lodash@4.17.21"
        }
      ],
      "licenseConcluded": "MIT",
      "licenseDeclared": "MIT"
    }
  ]
}
```

### License Violation Finding

```json
{
  "vulnerability_type": "license_violation",
  "severity": "medium",
  "confidence": 1.0,
  "title": "GPL-3.0 license detected in proprietary project",
  "description": "Package 'readline-sync' uses GPL-3.0 license which may conflict with proprietary licensing",
  "location": "node_modules/readline-sync/package.json",
  "recommendation": "Review GPL-3.0 licensing implications or replace with compatible alternative",
  "references": [
    "https://www.gnu.org/licenses/gpl-3.0.en.html",
    "https://choosealicense.com/licenses/gpl-3.0/"
  ],
  "evidence": {
    "package_name": "readline-sync",
    "package_version": "1.4.10",
    "package_type": "npm",
    "license": "GPL-3.0",
    "license_source": "package.json",
    "purl": "pkg:npm/readline-sync@1.4.10",
    "locations": ["/node_modules/readline-sync/package.json"],
    "license_compatibility": {
      "category": "copyleft",
      "requires_source_disclosure": true,
      "viral_license": true
    }
  },
  "tool": "syft",
  "cwe_id": null
}
```

### Component Discovery Finding

```json
{
  "vulnerability_type": "vulnerable_dependency", 
  "severity": "info",
  "confidence": 1.0,
  "title": "Binary component discovered: OpenSSL",
  "description": "OpenSSL library detected in binary analysis",
  "location": "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
  "recommendation": "Verify OpenSSL version for known vulnerabilities",
  "references": ["https://www.openssl.org/"],
  "evidence": {
    "package_name": "openssl",
    "package_version": "1.1.1k",
    "package_type": "binary",
    "cataloger": "binary-cataloger",
    "cpes": ["cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"],
    "purl": "pkg:generic/openssl@1.1.1k",
    "locations": ["/usr/lib/x86_64-linux-gnu/libssl.so.1.1"],
    "binary_metadata": {
      "architecture": "x86_64",
      "go_compiled": false,
      "has_symbols": true
    }
  },
  "tool": "syft"
}
```

## Performance

### Execution Speed
- **Small projects** (< 100 files): 500ms-2s
- **Medium projects** (100-1000 files): 2-8s  
- **Large projects** (> 1000 files): 8-30s
- **Container images**: 3-15s (depending on layers)

### Resource Usage
- **CPU**: Moderate usage during cataloging phase
- **Memory**: ~100-400MB depending on project complexity
- **Disk**: Temporary SBOM files (~1-50MB per project)
- **Network**: Container registry access for image analysis

### Optimization Features
- **Parallel cataloging**: Multiple catalogers run concurrently
- **Smart exclusions**: Skip binary files and irrelevant directories
- **Incremental discovery**: Cache results for unchanged components
- **Layer optimization**: Efficient container layer analysis

## Integration Benefits

### Supply Chain Visibility

Syft provides comprehensive software supply chain mapping:

**Complete Inventory**: Discover all components, including transitive dependencies
**Binary Analysis**: Find components not tracked by package managers  
**License Compliance**: Identify licensing conflicts and requirements
**Vulnerability Surface**: Map all components that could contain vulnerabilities

### SBOM Standards Compliance

**Industry Standards**: Generate SBOMs in SPDX 2.3 and CycloneDX formats
**Government Requirements**: Meet emerging SBOM regulatory requirements
**Supply Chain Security**: Enable downstream vulnerability analysis
**Audit Trails**: Provide evidence of component analysis and review

### MCP-Specific Value

For MCP servers, Syft is crucial for:

- **Dependency Transparency** - Complete visibility into MCP tool dependencies
- **License Compliance** - Ensure MCP server distributions meet licensing requirements  
- **Supply Chain Security** - Identify all components that could introduce vulnerabilities
- **Container Analysis** - Analyze containerized MCP deployments for embedded components
- **Binary Component Discovery** - Find native libraries used by MCP tools

### Ecosystem Integration

Works optimally with other security tools:

**Grype**: Analyzes Syft SBOMs for fast vulnerability scanning
**Trivy**: Can consume Syft SBOMs for targeted vulnerability analysis
**OSS Review Tools**: SBOM enables automated license compliance checking
**Security Dashboards**: SBOM data feeds vulnerability management platforms

## Advanced Features

### Custom Catalogers

Configure specific component discovery:

```bash
# Only run specific catalogers
syft /path/to/project \
  --catalogers python-package-cataloger,javascript-package-cataloger \
  -o spdx-json

# Exclude problematic catalogers
syft /path/to/project \
  --catalogers all \
  --exclude-catalogers binary-cataloger \
  -o cyclonedx-json
```

### SBOM Attestation

Generate cryptographically signed SBOMs:

```bash
# Generate SBOM with attestation (requires cosign)
syft /path/to/project -o spdx-json=project.spdx.json
cosign attest --predicate project.spdx.json --key cosign.key project.tar
```

### Multi-Format Output

Generate multiple SBOM formats simultaneously:

```bash
# Generate both SPDX and CycloneDX formats
syft /path/to/project \
  -o spdx-json=project.spdx.json \
  -o cyclonedx-json=project.cyclonedx.json \
  -o table
```

## License Analysis

### License Categories

Syft categorizes licenses for compliance analysis:

```python
LICENSE_CATEGORIES = {
    'permissive': [
        'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC'
    ],
    'weak_copyleft': [
        'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'EPL-2.0'
    ],
    'strong_copyleft': [
        'GPL-2.0', 'GPL-3.0', 'AGPL-3.0'
    ],
    'commercial': [
        'Commercial', 'Proprietary', 'Custom'
    ]
}
```

### License Compatibility Matrix

```python
COMPATIBILITY_RULES = {
    'commercial_product': {
        'allowed': ['MIT', 'Apache-2.0', 'BSD-3-Clause'],
        'restricted': ['LGPL-2.1', 'MPL-2.0'],  # Review required
        'forbidden': ['GPL-3.0', 'AGPL-3.0']    # Viral licenses
    },
    'open_source_product': {
        'allowed': ['MIT', 'Apache-2.0', 'GPL-3.0', 'AGPL-3.0'],
        'restricted': ['Commercial', 'Proprietary'],
        'forbidden': []
    }
}
```

## Monitoring and Reporting

### SBOM Metrics

Track important supply chain metrics:

```json
{
  "sbom_summary": {
    "total_packages": 234,
    "by_ecosystem": {
      "npm": 156,
      "python": 45,  
      "go": 23,
      "system": 10
    },
    "by_license": {
      "MIT": 134,
      "Apache-2.0": 67,
      "GPL-3.0": 5,
      "Unknown": 28
    },
    "license_violations": 2,
    "binary_components": 15,
    "generation_time_seconds": 4.2
  }
}
```

### Supply Chain Health

Monitor component health indicators:

```python
HEALTH_METRICS = {
    'license_compliance': 0.95,    # % of components with known licenses
    'package_coverage': 0.98,      # % of dependencies discovered  
    'binary_analysis': 0.87,       # % of binaries successfully analyzed
    'sbom_freshness_hours': 2,     # Hours since last SBOM generation
}
```

## Troubleshooting

### Common Issues

**Q: Syft not discovering expected packages**
A: Ensure package manifest files are present and use all catalogers

**Q: Binary analysis missing components**  
A: Enable binary cataloger and ensure binaries have debug symbols

**Q: License information missing for packages**
A: Check if packages declare licenses in manifests or LICENSE files

**Q: SBOM generation timing out**
A: Exclude large directories or increase timeout settings

### Performance Optimization

```python
# Fast SBOM generation for CI/CD
CI_CONFIG = {
    'catalogers': 'javascript-package,python-package,go-module',
    'exclude_binary_overlap_by_ownership': True,
    'exclude_patterns': ['**/test/**', '**/node_modules/**/.cache/**'],
    'registry_timeout': '10s',
}

# Comprehensive analysis for security review
SECURITY_CONFIG = {
    'catalogers': 'all',
    'scope': 'all-layers', 
    'exclude_binary_overlap_by_ownership': False,
    'registry_timeout': '60s',
}
```

### Debug Mode

Enable detailed component discovery logging:

```bash
# Debug Syft execution
syft /path/to/project --verbose -o json

# Show cataloger details
syft /path/to/project --catalogers --verbose

# Test specific cataloger
syft /path/to/project --catalogers python-package-cataloger --verbose
```

## Best Practices

### SBOM Generation Strategy

1. **Automated Generation**: Include SBOM generation in CI/CD pipelines
2. **Version Control**: Store SBOMs alongside source code for auditability
3. **Format Selection**: Use SPDX for government compliance, CycloneDX for tooling
4. **Regular Updates**: Regenerate SBOMs when dependencies change

### Supply Chain Security

**Dependency Management**:
- Review all discovered components for security and licensing
- Maintain approved component lists
- Monitor for new vulnerable or problematic components

**License Compliance**:
- Establish clear license policies before component selection
- Automate license compliance checking in CI/CD
- Regular legal review of license compatibility

### Integration Architecture

```python
# Recommended tool chain
SBOM_PIPELINE = {
    '1_generation': 'syft',          # Generate comprehensive SBOM
    '2_vulnerability': 'grype',       # Scan SBOM for vulnerabilities  
    '3_secrets': 'trivy',            # Additional secret/config scanning
    '4_analysis': 'custom_rules',    # Custom business logic
    '5_reporting': 'security_dashboard'  # Centralized reporting
}
```

## Version Information

```bash
# Check Syft version
syft version

# List available catalogers
syft catalogers

# Show supported output formats
syft --help | grep -A 10 "output formats"
```