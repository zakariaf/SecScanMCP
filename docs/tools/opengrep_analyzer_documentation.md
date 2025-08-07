# OpenGrep Integration - Open-Source Pattern-Based Analysis

## Overview

**OpenGrep** is an open-source static analysis engine that provides pattern-based vulnerability detection across multiple programming languages:

- **LGPL 2.1 Licensed** - Fully open-source fork of Semgrep Community Edition
- **Multi-language Support** - 20+ languages with consistent rule format
- **Extensive Rule Library** - 2000+ security rules from the community
- **Custom Rule Support** - YAML-based custom rules for MCP-specific patterns
- **High Performance** - Fast analysis with incremental scanning capabilities

## Architecture

OpenGrep runs as a native binary analyzer within the scanner container:

```
┌─────────────────┐
│   MCP Scanner   │
│                 │
│ ┌─────────────┐ │
│ │  OpenGrep   │ │
│ │  Analyzer   │ │
│ └─────────────┘ │
└─────────────────┘
         │
         ▼
┌─────────────────────────────────┐
│        Rule Sources             │
├─────────────────────────────────┤
│ • Community Rules (2000+)       │
│ • MCP-Specific Custom Rules     │
│ • Language-Specific Rulesets    │
│ • Security Audit Rules          │
└─────────────────────────────────┘
```

## Detection Capabilities

### Supported Languages

**Web Technologies:**
- JavaScript/TypeScript
- HTML/CSS
- PHP, Ruby, Python

**Systems Languages:**
- Go, Rust, C/C++
- Java, Kotlin, Scala
- C#/.NET

**Others:**
- Shell scripts, Dockerfile
- YAML, JSON, XML
- Terraform, CloudFormation

### Vulnerability Types Detected

**Injection Attacks:**
- SQL injection patterns
- Command injection via system calls
- Code injection through eval/exec
- LDAP injection vulnerabilities

**Web Application Security:**
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- Server-side request forgery (SSRF)
- Path traversal vulnerabilities

**Cryptographic Issues:**
- Weak encryption algorithms
- Insecure random number generation
- Hardcoded cryptographic keys
- Certificate validation bypasses

**MCP-Specific Patterns:**
- Prompt injection attempts in tool descriptions
- Tool manipulation patterns
- Schema injection vulnerabilities
- Output poisoning risks

### Example Detections

```python
# SQL Injection - DETECTED
query = f"SELECT * FROM users WHERE id = {user_id}"

# Command Injection - DETECTED  
os.system(f"ls {user_input}")

# XSS Vulnerability - DETECTED
return f"<div>{user_content}</div>"  # Without escaping

# Hardcoded Secret - DETECTED
API_KEY = "sk-1234567890abcdef"
```

## Configuration

### Rule Selection

OpenGrep runs with optimized rulesets for MCP security scanning:

```python
# analyzers/opengrep_analyzer.py
RULESETS = [
    'auto',                          # Auto-detect relevant rules
    'r/security-audit',              # General security patterns
    'r/python.lang.security',        # Python security rules
    'r/javascript.lang.security',    # JavaScript security rules
    'r/typescript.lang.security',    # TypeScript security rules
    'r/generic.secrets',             # Secret detection patterns
]
```

### Custom MCP Rules

The analyzer includes MCP-specific detection rules:

```yaml
# MCP Prompt Injection Detection
rules:
  - id: mcp-prompt-injection-basic
    patterns:
      - pattern-either:
          - pattern: "ignore all previous"
          - pattern: "disregard all prior" 
          - pattern: "forget everything"
          - pattern: "system mode"
    message: "Potential prompt injection attempt detected"
    severity: HIGH
    languages: [python, javascript, typescript]

  - id: mcp-tool-manipulation
    patterns:
      - pattern: |
          def $FUNC(...):
            ...
            $TOOL.call($MALICIOUS_INPUT)
    message: "Potential tool manipulation vulnerability"
    severity: CRITICAL
    languages: [python]
```

### Performance Optimization

```python
OPENGREP_CONFIG = {
    'timeout': 120,                  # Per-file timeout
    'max_target_bytes': 1000000,     # Skip files > 1MB
    'exclude_dirs': ['.git', 'node_modules', '__pycache__'],
    'jobs': 4,                       # Parallel processing
    'enable_metrics': True,          # Performance tracking
}
```

## Usage

### Automatic Integration

OpenGrep runs automatically for all supported file types:

```bash
# Scan any repository with supported languages
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "https://github.com/example/project"}'
```

### Manual Execution

Direct OpenGrep analysis:

```bash
# Run OpenGrep with security rules
opengrep --config=auto --json /path/to/code

# Run with specific ruleset
opengrep --config=r/security-audit --output=findings.json /path/to/code

# Run with custom MCP rules
opengrep --config=/app/rules/mcp-security.yaml /path/to/mcp/server
```

### Programmatic Usage

```python
from analyzers.opengrep_analyzer import OpenGrepAnalyzer

analyzer = OpenGrepAnalyzer()
results = await analyzer.analyze('/path/to/project')

for finding in results:
    print(f"Rule: {finding.evidence.get('rule_id')}")
    print(f"Severity: {finding.severity}")
    print(f"Location: {finding.location}")
    print(f"Message: {finding.title}")
```

## Output Format

### Finding Structure

```json
{
  "vulnerability_type": "code_injection",
  "severity": "high",
  "confidence": 0.9,
  "title": "Use of eval() enables arbitrary code execution",
  "description": "Found eval() usage which can execute arbitrary code",
  "location": "src/parser.py:42",
  "recommendation": "Replace eval() with ast.literal_eval() or JSON parsing",
  "references": [
    "https://owasp.org/www-community/attacks/Code_Injection",
    "https://docs.python.org/3/library/ast.html#ast.literal_eval"
  ],
  "evidence": {
    "rule_id": "python.lang.security.audit.dangerous-eval-use",
    "rule_message": "eval() allows execution of arbitrary code",
    "matched_code": "result = eval(user_input)",
    "line_number": 42,
    "column_start": 10,
    "column_end": 27,
    "fix_suggestion": "Use ast.literal_eval() instead"
  },
  "tool": "opengrep",
  "cwe_id": "CWE-94"
}
```

### Rule Categories

OpenGrep findings are categorized by rule source:

| Category | Description | Example Rules |
|----------|-------------|---------------|
| **security-audit** | General security patterns | SQL injection, XSS, CSRF |
| **lang.security** | Language-specific issues | Python eval(), JS innerHTML |
| **secrets** | Hardcoded credentials | API keys, passwords, tokens |
| **mcp-custom** | MCP-specific patterns | Prompt injection, tool manipulation |

### Severity Mapping

OpenGrep severity levels map to standard categories:

| OpenGrep Level | Mapped Severity | Usage |
|---------------|----------------|--------|
| ERROR         | CRITICAL       | Exploitable vulnerabilities |
| WARNING       | HIGH           | Significant security concerns |
| INFO          | MEDIUM         | Potential issues requiring review |

## Performance

### Execution Speed
- **Small projects** (< 1000 files): 500ms-2s
- **Medium projects** (1000-5000 files): 2-10s
- **Large projects** (> 5000 files): 10-30s

### Resource Usage
- **CPU**: Multi-threaded analysis with configurable job count
- **Memory**: ~100-300MB depending on project size and rules
- **Disk**: Temporary rule caching, no persistent storage

### Optimization Features
- **Incremental analysis**: Skip unchanged files
- **Smart exclusions**: Ignore binary files, dependencies
- **Parallel processing**: Multi-core rule execution
- **Rule caching**: Reuse compiled rule patterns

## Integration Benefits

### Rule Ecosystem

OpenGrep provides access to extensive rule libraries:

**Community Rules**: 2000+ battle-tested security patterns
**Language Coverage**: Consistent rules across 20+ languages  
**Regular Updates**: Community-driven rule improvements
**Custom Extensions**: Easy to add MCP-specific patterns

### MCP-Specific Value

For MCP servers, OpenGrep excels at detecting:

- **Prompt injection patterns** in tool descriptions and handling code
- **Tool manipulation** vulnerabilities in MCP implementations
- **Schema injection** through dynamic schema generation
- **Output poisoning** in result formatting and display
- **Permission abuse** patterns in tool execution logic

### Complementary Analysis

Works particularly well with:

**CodeQL**: OpenGrep finds patterns, CodeQL provides deep semantic analysis
**Bandit**: OpenGrep covers multiple languages, Bandit specializes in Python
**TruffleHog**: OpenGrep detects secret patterns, TruffleHog validates credentials
**Intelligent Analyzer**: OpenGrep identifies issues, Intelligent assesses context

## Rule Development

### Creating Custom Rules

Add MCP-specific detection patterns:

```yaml
rules:
  - id: mcp-unsafe-tool-execution
    pattern: |
      def $FUNC(...):
        ...
        subprocess.run($USER_INPUT, shell=True)
    message: "MCP tool executing user input without sanitization"
    severity: ERROR
    languages: [python]
    metadata:
      category: security
      cwe: "CWE-78: Command Injection"
      confidence: HIGH
```

### Rule Testing

Validate custom rules:

```bash
# Test rule against sample code
opengrep --config=custom-rules.yaml --test

# Dry run to check rule syntax
opengrep --validate-config=custom-rules.yaml

# Test specific rule by ID  
opengrep --config=custom-rules.yaml --include="mcp-unsafe-tool-execution"
```

### Rule Contribution

Contribute rules to the community:

1. Fork the OpenGrep rules repository
2. Add rules following the style guide
3. Include test cases and documentation
4. Submit pull request for review

## Common Issues and Solutions

### False Positives

**Issue**: Generic patterns triggering on legitimate code
**Solution**: Add context patterns and exclude safe usage

**Issue**: Test files flagged for intentional vulnerabilities  
**Solution**: Use path-based exclusions in rule metadata

**Issue**: Third-party library code flagged
**Solution**: Exclude vendor/dependency directories

### Performance Optimization

```python
# Skip large generated files
MAX_FILE_SIZE = 500000  # 500KB limit

# Exclude resource-intensive patterns
EXCLUDE_RULES = [
    'generic.secrets.security.detected-aws-account-id',  # High false positive
    'javascript.express.security.audit.xss.direct-response-write',  # Noisy
]

# Optimize for MCP scanning
FOCUS_RULES = [
    'python.lang.security',
    'javascript.lang.security', 
    'generic.secrets',
    'custom.mcp-security',
]
```

### Rule Debugging

Enable detailed rule execution info:

```bash
# Debug rule matching
opengrep --config=rules.yaml --debug /path/to/code

# Verbose output with rule metrics
opengrep --config=auto --metrics --time /path/to/code

# Test specific pattern
opengrep --pattern='eval($X)' --lang=python /path/to/code
```

## Best Practices

### Development Workflow

1. **Pre-commit scanning**: Run OpenGrep on changed files
2. **CI/CD integration**: Block commits with critical findings  
3. **Rule customization**: Develop MCP-specific detection rules
4. **Regular updates**: Keep rule database current

### Rule Management

**Prioritization**:
- Focus on high-confidence, high-impact rules
- Customize rule severity based on MCP context
- Disable noisy rules that don't apply to MCP servers

**Custom Rule Strategy**:
- Develop MCP-specific prompt injection patterns
- Create tool manipulation detection rules
- Add schema validation security patterns

### Performance Tuning

```python
# Production configuration
PRODUCTION_CONFIG = {
    'timeout': 60,              # Faster timeout for CI/CD
    'max_target_bytes': 100000, # Skip very large files
    'jobs': 2,                  # Conservative CPU usage
    'exclude_dirs': ['.git', 'node_modules', 'venv', '.venv', '__pycache__'],
    'include_rules': ['security-audit', 'secrets', 'mcp-custom'],
}
```

## Troubleshooting

### Common Problems

**Q: OpenGrep not finding expected vulnerabilities**
A: Check if appropriate rulesets are enabled for your languages

**Q: Too many false positives from secret detection**
A: Adjust confidence thresholds and exclude test/example files

**Q: Analysis timing out on large repositories**  
A: Increase timeout or exclude large generated files

### Debug Mode

Enable detailed analysis logging:

```bash
# Debug rule execution
opengrep --config=auto --debug --json /path/to/code

# Profile performance bottlenecks  
opengrep --config=auto --time --metrics /path/to/code

# Test rule syntax and patterns
opengrep --validate-config=rules.yaml
```

### Version Information

```bash
# Check OpenGrep version
opengrep --version

# List available rulesets
opengrep --list-configs

# Show rule details
opengrep --show-config=r/security-audit
```