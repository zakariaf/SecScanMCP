# Bandit Integration - Python Security Linting

## Overview

**Bandit** is a security linter specifically designed for Python code that identifies common security issues:

- **AST-based analysis** of Python source code
- **120+ built-in security tests** covering OWASP Top 10
- **Low false positive rate** with confidence scoring
- **Industry standard** used by major Python projects
- **Fast execution** with minimal resource requirements

## Architecture

Bandit runs as a native Python analyzer within the main scanner process:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │   Bandit    │ │
│ │  Analyzer   │ │
│ └─────────────┘ │
└─────────────────┘
         │
         ▼
   Python AST Analysis
    (Security Issues)
```

## Detection Capabilities

### Security Issues Detected

**Injection Vulnerabilities:**
- SQL injection via string formatting
- Command injection through subprocess calls
- Code injection via eval() and exec()

**Cryptographic Issues:**
- Weak cryptographic algorithms (MD5, SHA1)
- Insecure random number generation
- Hardcoded cryptographic keys

**Input/Output Security:**
- Path traversal vulnerabilities
- Insecure file permissions
- Unsafe YAML loading

**Web Application Security:**
- XSS vulnerabilities in templates
- CSRF protection bypasses
- Insecure SSL/TLS configurations

**Authentication & Authorization:**
- Hardcoded passwords and secrets
- Insecure password hashing
- Missing authentication checks

### Example Detections

```python
# B101: Test for use of assert
assert False, "This should never happen"  # DETECTED

# B102: Test for exec use
exec("print('hello world')")  # DETECTED

# B103: Test for setting a bad file permission
os.chmod('/path/to/file', 0o777)  # DETECTED

# B501: Test for requests calls with verify disabled
requests.get('https://example.com', verify=False)  # DETECTED
```

## Configuration

### Built-in Configuration

Bandit runs with optimized settings for MCP security scanning:

```python
# analyzers/security_tools/bandit_analyzer.py
BANDIT_CONFIG = {
    'format': 'json',
    'confidence_level': 'low',  # Catch all potential issues
    'severity_level': 'low',    # Include informational findings
    'recursive': True,          # Scan subdirectories
    'exclude_dirs': ['.git', '__pycache__', 'venv', 'node_modules']
}
```

### Custom Exclusions

The analyzer excludes common false positives:

```python
EXCLUDE_PATTERNS = [
    '*/tests/*',           # Test files often have intentional vulnerabilities
    '*/test_*.py',         # Test patterns
    '*/conftest.py',       # Pytest configuration
    '*/setup.py',          # Installation scripts
]
```

## Usage

### Automatic Integration

Bandit runs automatically for all Python projects:

```bash
# Scan any repository containing Python files
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/python-project"}'
```

### Manual Execution

Test Bandit analyzer directly:

```bash
# Run Bandit on a local directory
python -m analyzers.security_tools.bandit_analyzer --path /path/to/python/code

# With specific confidence level
python -m analyzers.security_tools.bandit_analyzer --path /path/to/code --confidence-level medium
```

### Programmatic Usage

```python
from analyzers.security_tools.bandit_analyzer import BanditAnalyzer

analyzer = BanditAnalyzer()
results = await analyzer.analyze('/path/to/python/project')

for finding in results:
    print(f"Issue: {finding.title}")
    print(f"Severity: {finding.severity}")
    print(f"File: {finding.location}")
    print(f"Confidence: {finding.confidence}")
```

## Output Format

### Finding Structure

```json
{
  "vulnerability_type": "hardcoded_secret",
  "severity": "medium", 
  "confidence": 0.8,
  "title": "Hardcoded password in source code",
  "description": "Hardcoded password: 'secret123' found in source code",
  "location": "src/config.py:15",
  "recommendation": "Use environment variables for sensitive credentials",
  "references": ["https://cwe.mitre.org/data/definitions/798.html"],
  "evidence": {
    "bandit_test_id": "B106",
    "bandit_test_name": "hardcoded_password_funcarg",
    "code_snippet": "password = 'secret123'",
    "line_number": 15,
    "line_range": [15, 15]
  },
  "tool": "bandit",
  "cwe_id": "CWE-798"
}
```

### Severity Mapping

Bandit severity levels are mapped to standard levels:

| Bandit Level | Mapped Severity | Description |
|-------------|----------------|-------------|
| HIGH        | CRITICAL       | Immediate security risk |
| MEDIUM      | HIGH           | Significant security concern |
| LOW         | MEDIUM         | Potential security issue |

### Confidence Scoring

Bandit confidence levels indicate likelihood of true positive:

| Confidence | Score | Description |
|-----------|-------|-------------|
| HIGH      | 0.9   | Very likely a real issue |
| MEDIUM    | 0.7   | Likely a real issue |
| LOW       | 0.5   | Possible issue, may be false positive |

## Performance

### Execution Speed
- **Small projects** (< 1000 lines): 100-300ms
- **Medium projects** (1000-10000 lines): 500ms-2s
- **Large projects** (> 10000 lines): 2-10s

### Resource Usage
- **CPU**: Low impact, single-threaded AST parsing
- **Memory**: ~50-100MB depending on project size
- **Disk**: No temporary files created

### Optimization Features
- **Incremental scanning**: Only analyzes changed Python files
- **Smart exclusions**: Skips non-Python and test files
- **Parallel processing**: Can run alongside other analyzers

## Integration Benefits

### Complementary Analysis

Bandit works especially well with:

**CodeQL**: Bandit catches Python-specific issues, CodeQL provides cross-language analysis
**TruffleHog**: Bandit finds hardcoded secrets in code logic, TruffleHog scans git history
**Intelligent Analyzer**: Bandit identifies potential issues, Intelligent Analyzer assesses legitimacy

### MCP-Specific Value

For MCP servers, Bandit is particularly valuable for detecting:

- **Hardcoded API keys** that could be exploited
- **Insecure file operations** in tool implementations  
- **Command injection** vulnerabilities in system tools
- **Weak cryptography** in authentication mechanisms

## Common Issues and Solutions

### False Positives

**Issue**: Test files flagged for intentional vulnerabilities
**Solution**: Tests are automatically excluded via path patterns

**Issue**: Configuration files flagged for hardcoded values
**Solution**: Use confidence scoring to filter low-confidence findings

### Configuration Tuning

```python
# Adjust confidence threshold for fewer false positives
CONFIDENCE_THRESHOLD = 0.7  # Default: 0.5

# Exclude additional paths
CUSTOM_EXCLUDES = [
    '*/examples/*',    # Example code
    '*/docs/*',        # Documentation
    '*/migrations/*'   # Database migrations
]
```

### Performance Optimization

```python
# Skip large files that are unlikely to contain security issues
MAX_FILE_SIZE = 1024 * 1024  # 1MB limit

# Limit scan depth for very deep directory structures  
MAX_SCAN_DEPTH = 10
```

## Best Practices

### Development Workflow

1. **Pre-commit hooks**: Run Bandit before code commits
2. **CI/CD integration**: Include Bandit in automated testing
3. **Regular scans**: Periodic security audits with Bandit
4. **Developer training**: Educate on common Python security patterns

### Remediation Guidelines

**High Priority** (Fix immediately):
- Hardcoded secrets and passwords
- SQL injection vulnerabilities  
- Command injection flaws

**Medium Priority** (Fix in next release):
- Weak cryptographic algorithms
- Insecure random number generation
- Path traversal issues

**Low Priority** (Address during refactoring):
- Assert statements in production code
- Insecure file permissions
- Minor configuration issues

## Troubleshooting

### Common Problems

**Q: Bandit not detecting Python files**
A: Ensure files have .py extension and are in included paths

**Q: Too many false positives**  
A: Increase confidence threshold or add specific exclusions

**Q: Missing security issues**
A: Lower confidence threshold, check if files are being excluded

### Debug Mode

Enable detailed logging:

```bash
# Set debug logging for Bandit analyzer
LOG_LEVEL=DEBUG python -c "
from analyzers.security_tools.bandit_analyzer import BanditAnalyzer
analyzer = BanditAnalyzer()
# Will show detailed analysis steps
"
```

### Version Information

```bash
# Check Bandit version
python -c "import bandit; print(bandit.__version__)"

# Verify installation
bandit --version
```