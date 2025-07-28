# Universal Scanner Implementation Guide

## Why Universal Scanners?

The MCP Security Scanner now uses **universal security scanners** that work across all programming languages, replacing multiple language-specific tools with powerful, comprehensive solutions.

### Benefits of This Approach

1. **Simplified Architecture**
   - 3 main scanners replace 6+ language-specific tools
   - Consistent output format across all languages
   - Easier maintenance and updates

2. **Better Coverage**
   - Automatically supports 20+ languages
   - No need to add new tools for new languages
   - Unified vulnerability databases

3. **Enhanced Detection**
   - Trivy: Vulnerabilities + Secrets + Misconfigs + Licenses
   - Grype: Fast scanning with EPSS/KEV risk data
   - Syft: Complete SBOM generation for all ecosystems

## Tool Capabilities

### Trivy (All-in-One Scanner)

**Supported Languages:**
- Python, JavaScript/TypeScript, Go, Rust, Java, Ruby, PHP
- C/C++, .NET, Swift, Kotlin, Scala, Elixir, Dart
- And more...

**What it detects:**
```yaml
Vulnerabilities:
  - OS packages (apt, yum, apk, etc.)
  - Language packages (pip, npm, cargo, maven, etc.)
  - Known CVEs with severity ratings

Secrets:
  - API keys (AWS, GCP, Azure, GitHub, etc.)
  - Passwords and tokens
  - Private keys
  - Database credentials

Misconfigurations:
  - Dockerfile security issues
  - Kubernetes manifests
  - Terraform/CloudFormation
  - CI/CD configs

Licenses:
  - All package licenses
  - Compliance checking
  - Copyleft detection
```

### Grype (Vulnerability Focus)

**Key Features:**
- Fastest vulnerability scanner
- Works with Syft SBOMs for speed
- Includes EPSS scores (exploit prediction)
- Includes KEV data (known exploited vulns)
- Smart matching reduces false positives

**Example Output:**
```json
{
  "vulnerability": {
    "id": "CVE-2024-1234",
    "severity": "High",
    "cvss": 7.5,
    "epss": {
      "score": 0.89,
      "percentile": 0.95
    },
    "kev": {
      "known_exploited": true,
      "date_added": "2024-12-01"
    }
  }
}
```

### Syft (SBOM Generation)

**Capabilities:**
- Generates SBOMs in SPDX, CycloneDX, JSON
- Detects packages without package managers
- Identifies binaries and their versions
- Complete dependency trees
- License extraction

## Language-Specific Examples

### Python MCP Server

```python
# Example vulnerable Python MCP server
import os
import requests
import pickle  # Vulnerability: Unsafe deserialization

API_KEY = "sk-vulnerable123"  # Secret exposed

def process_data(user_input):
    os.system(f"echo {user_input}")  # Command injection
```

**Scanner Output:**
- **Trivy**: Detects hardcoded API key, command injection pattern
- **Grype**: Finds vulnerable requests version (if outdated)
- **Bandit**: AST analysis finds os.system and pickle usage
- **Semgrep**: Pattern matching for injection vulnerabilities

### JavaScript/TypeScript MCP Server

```javascript
// Example vulnerable Node.js MCP server
const express = require('express');
const { exec } = require('child_process');

const app = express();
const DB_PASSWORD = "admin123"; // Secret exposed

app.post('/execute', (req, res) => {
    // Command injection vulnerability
    exec(`ls ${req.body.path}`, (err, stdout) => {
        res.send(stdout);
    });
});
```

**Scanner Output:**
- **Trivy**: Detects DB_PASSWORD, exec vulnerability, outdated Express
- **Grype**: Checks all npm dependencies for CVEs
- **Semgrep**: JavaScript rules catch command injection
- **TruffleHog**: Finds the hardcoded password

### Go MCP Server

```go
package main

import (
    "os/exec"
    "net/http"
)

const apiToken = "ghp_vulnerable123" // Exposed token

func handler(w http.ResponseWriter, r *http.Request) {
    cmd := r.URL.Query().Get("cmd")
    // Command injection
    out, _ := exec.Command("sh", "-c", cmd).Output()
    w.Write(out)
}
```

**Scanner Output:**
- **Trivy**: Detects GitHub token, command injection
- **Grype**: Scans go.mod dependencies
- **Semgrep**: Go security rules find exec usage
- **Syft**: Complete SBOM of all Go modules

### Rust MCP Server

```rust
use std::process::Command;

const SECRET_KEY: &str = "secret_key_12345"; // Hardcoded secret

fn execute_command(input: &str) -> String {
    // Command injection vulnerability
    let output = Command::new("sh")
        .arg("-c")
        .arg(input)
        .output()
        .expect("Failed to execute");
    
    String::from_utf8_lossy(&output.stdout).to_string()
}
```

**Scanner Output:**
- **Trivy**: Finds hardcoded secret, unsafe command execution
- **Grype**: Checks Cargo.lock for vulnerable crates
- **Semgrep**: Rust patterns detect command injection
- **Syft**: Full SBOM including all Rust dependencies

## Scan Performance

### Speed Comparison

```
Traditional Approach (6 tools):
- Python: bandit (5s) + safety (3s) + pip-audit (4s) = 12s
- Node.js: eslint-security (6s) + npm-audit (4s) = 10s
- Go: gosec (5s) + nancy (3s) = 8s
Total: 30s+ sequential

Universal Approach (3 tools):
- Syft: 3s (SBOM generation)
- Trivy: 5s (all checks)
- Grype: 2s (using SBOM)
Total: 10s parallel = ~5s total
```

### Accuracy Improvements

1. **Unified Vulnerability Database**
   - Trivy aggregates from 15+ sources
   - Grype uses Anchore's curated DB
   - Better coverage than individual tools

2. **Cross-Language Intelligence**
   - Patterns learned from one language apply to others
   - Consistent severity scoring
   - Unified false positive reduction

3. **Risk-Based Prioritization**
   - EPSS scores predict exploitation likelihood
   - KEV data shows real-world exploits
   - Better than just CVSS scores

## Configuration Examples

### Optimized for Speed

```python
# In scanner.py - Fast mode
if scan_options.get('fast_mode'):
    analyzers_to_run = ['syft', 'grype']  # Skip comprehensive Trivy
```

### Maximum Coverage

```python
# In scanner.py - Comprehensive mode
if scan_options.get('comprehensive'):
    analyzers_to_run = ['syft', 'trivy', 'grype', 'semgrep', 
                       'trufflehog', 'bandit', 'mcp_specific']
```

### Language-Specific Focus

```python
# Still supports language-specific tools when needed
if project_info['language'] == 'python' and scan_options.get('deep_python'):
    analyzers_to_run.extend(['bandit', 'mypy', 'pylint'])
```

## Best Practices

1. **SBOM First**
   - Always run Syft first to generate SBOM
   - Other tools can use SBOM for faster scanning
   - Store SBOM for future rescans

2. **Cache Management**
   - Mount cache volumes for Trivy/Grype databases
   - Reduces scan time from 10s to 2s
   - Automatic database updates

3. **Incremental Scanning**
   - Use stored SBOMs for quick rescans
   - Only regenerate on dependency changes
   - Focus on changed files with Semgrep

4. **Result Aggregation**
   - Deduplicate findings across tools
   - Prioritize by EPSS/KEV data
   - Group by fix availability

## Integration Patterns

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Security Scan
  run: |
    # Fast mode for PRs
    curl -X POST http://scanner:8000/scan \
      -d '{"repository_url": "${{ github.repository }}", 
           "options": {"fast_mode": true}}'
```

### Scheduled Deep Scans

```python
# Nightly comprehensive scan
async def nightly_scan(repo_url):
    result = await scanner.scan_repository(
        repo_url,
        options={'comprehensive': True}
    )
    
    # Focus on new critical issues
    new_criticals = filter_new_findings(
        result['findings'],
        severity='critical'
    )
```

### Multi-Repository Management

```python
# Scan multiple repos efficiently
async def scan_organization(org_repos):
    # First pass: Generate all SBOMs
    sboms = await asyncio.gather(*[
        generate_sbom(repo) for repo in org_repos
    ])
    
    # Second pass: Scan SBOMs for vulnerabilities
    results = await asyncio.gather(*[
        scan_sbom(sbom) for sbom in sboms
    ])
```

## Conclusion

The universal scanner approach provides:

1. **Simplicity**: Fewer tools to manage
2. **Coverage**: Automatic support for new languages
3. **Performance**: Faster scanning with caching
4. **Accuracy**: Better vulnerability detection
5. **Intelligence**: Risk-based prioritization

This makes the MCP Security Scanner more powerful while being easier to maintain and extend.
