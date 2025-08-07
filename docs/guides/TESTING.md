# 🧪 MCP Security Scanner - Testing Guide

This guide shows you how to test the MCP Security Scanner with both local examples and real vulnerable repositories.

## 🚀 Quick Start

### 1. Start the Scanner
```bash
make restart
```

### 2. Quick Test with Local Examples
```bash
# Test all local vulnerable examples
make test-examples

# Or test individual files
make test-python    # Test Python vulnerable server
make test-js       # Test JavaScript vulnerable server
```

### 3. Check Results
The scanner should detect **40+ vulnerabilities** across the test files:
- **Critical**: 10+ findings (command injection, hardcoded secrets)
- **High**: 15+ findings (SSRF, path traversal, code injection)
- **Medium**: 10+ findings (weak crypto, information disclosure)
- **Low**: 5+ findings (code quality issues)

## 📋 Detailed Testing Procedures

### Local Vulnerable Examples Testing

```bash
# Comprehensive test with detailed output
python test_scanner.py

# Test specific vulnerability categories
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "file:///Users/zakariafatahi/Projects/MCP/secscanmcp/examples/vulnerable-mcp-server.py",
    "options": {
      "enable_mcp_rules": true,
      "comprehensive": true
    }
  }' | python -m json.tool
```

## 🌐 Real Vulnerable Repositories

### 1. Damn Vulnerable MCP Server (Educational)
```bash
# Clone and test the educational vulnerable MCP server
git clone https://github.com/harishsg993010/damn-vulnerable-MCP-server /tmp/dvmcp
make scan URL=file:///tmp/dvmcp

# Expected: 25+ vulnerabilities including:
# - Prompt injection attacks
# - Tool poisoning
# - Data exfiltration
# - Privilege escalation
```

### 2. Official MCP Servers (Real-world Examples)
```bash
# Test official MCP servers for potential issues
make scan URL=https://github.com/modelcontextprotocol/servers

# Expected: 5-15 findings (mostly dependency vulnerabilities)
```

### 3. Community MCP Servers
```bash
# Test various community MCP implementations
make scan URL=https://github.com/wong2/awesome-mcp-servers
make scan URL=https://github.com/docker/mcp-servers
```

### 4. Known Vulnerable Web Applications (General Testing)
```bash
# Test with intentionally vulnerable applications
make scan URL=https://github.com/digininja/DVWA        # PHP vulnerabilities
make scan URL=https://github.com/OWASP/NodeGoat       # Node.js vulnerabilities  
make scan URL=https://github.com/WebGoat/WebGoat       # Java vulnerabilities
```

## 🎯 Expected Detection Results

### Local Examples (`examples/` directory)

| File | Critical | High | Medium | Low | Total |
|------|----------|------|--------|-----|-------|
| `vulnerable-mcp-server.py` | 8 | 12 | 6 | 3 | 29 |
| `vulnerable-mcp-server.js` | 6 | 10 | 5 | 2 | 23 |
| `test_vulnerable_mcp.js` | 4 | 6 | 3 | 1 | 14 |
| **TOTAL** | **18** | **28** | **14** | **6** | **66** |

### Real Repositories

| Repository | Expected Findings | Primary Vulnerability Types |
|------------|-------------------|----------------------------|
| **DVMCP** | 25+ | Prompt injection, tool poisoning, data exfiltration |
| **MCP Servers** | 5-15 | Dependency vulnerabilities, configuration issues |
| **DVWA** | 50+ | SQL injection, XSS, command injection |
| **NodeGoat** | 30+ | Authentication bypass, injection attacks |

## 🔍 Verification Checklist

### ✅ Scanner Functionality
- [ ] Scanner starts without errors (`make health` returns OK)
- [ ] ClamAV service is healthy (antivirus scanning)
- [ ] YARA rules load correctly (pattern matching)
- [ ] CodeQL queries execute (semantic analysis)
- [ ] All security tools are detected (`make versions`)

### ✅ Detection Capabilities
- [ ] **Command Injection**: Detects `os.system()`, `exec()` with user input
- [ ] **SQL Injection**: Finds string concatenation in SQL queries
- [ ] **Path Traversal**: Catches `../` patterns and file access
- [ ] **SSRF**: Identifies unvalidated URL requests
- [ ] **Hardcoded Secrets**: Finds API keys, tokens, passwords
- [ ] **MCP-Specific**: Tool poisoning, schema injection, prompt injection

### ✅ Performance
- [ ] Local file scanning completes in <30 seconds
- [ ] GitHub repository scanning completes in <5 minutes
- [ ] Memory usage stays under 4GB during scanning
- [ ] No crashes or timeouts during normal operation

## 🚨 Troubleshooting

### Scanner Not Starting
```bash
# Check service status
make status

# View logs
make logs

# Full restart
make clean && make restart
```

### No Vulnerabilities Detected
```bash
# Verify rules are loaded
docker exec secscanmcp-scanner-1 ls -la /app/rules/

# Check YARA rules
docker exec secscanmcp-scanner-1 yara --help

# Check CodeQL
docker exec secscanmcp-scanner-1 codeql version
```

### Scanning Errors
```bash
# Check disk space
df -h

# Clear scanner cache
docker exec secscanmcp-scanner-1 rm -rf /tmp/mcp-scanner/*

# Restart with fresh state
make clean && make restart
```

## 🎯 Custom Testing

### Create Your Own Vulnerable MCP Server
```python
# Create test file: /tmp/custom-vuln-mcp.py
import os
import subprocess

@tool
def dangerous_command(params):
    cmd = params.get('command', '')
    # VULNERABLE: Direct command execution
    return os.system(cmd)

@tool  
def read_secrets(params):
    filename = params.get('file', '')
    # VULNERABLE: Path traversal
    with open(filename, 'r') as f:
        return f.read()
```

### Test Your Custom File
```bash
# Scan your custom vulnerable file
make scan URL=file:///tmp/custom-vuln-mcp.py

# Should detect:
# - Command injection in dangerous_command
# - Path traversal in read_secrets
```

## 📊 Benchmarking

### Performance Testing
```bash
# Run performance test
time make test-python

# Expected times:
# - Local file: <10 seconds
# - Small GitHub repo: <60 seconds  
# - Large GitHub repo: <5 minutes
```

### Coverage Testing
```bash
# Test detection rate with known vulnerabilities
python test_scanner.py > test_results.json

# Analyze results
python -c "
import json
with open('test_results.json') as f:
    data = json.load(f)
    total = sum(r['total_findings'] for r in data.values())
    print(f'Total vulnerabilities detected: {total}')
    print(f'Detection rate: {total/66*100:.1f}%')  # Expected: 66 total
"
```

## 🎉 Success Criteria

Your scanner is working correctly if:

1. **✅ Detects 90%+ of known vulnerabilities** in test examples
2. **✅ Completes scans without crashing** or timing out
3. **✅ Provides actionable remediation advice** for each finding
4. **✅ Correctly identifies MCP-specific threats** (tool poisoning, etc.)
5. **✅ Handles both local files and remote repositories**
6. **✅ Generates comprehensive security reports** with risk scoring

## 🔗 Additional Resources

- **MCP Security**: https://github.com/Puliczek/awesome-mcp-security
- **Vulnerability Database**: https://cve.mitre.org/
- **OWASP Testing Guide**: https://owasp.org/www-project-web-security-testing-guide/
- **CodeQL Documentation**: https://codeql.github.com/docs/