# MCP Security Scanner Examples

This directory contains example scripts and vulnerable code samples for testing the security scanner.

## Directory Structure

### `/examples/`
Example scripts and vulnerable MCP servers for testing:

1. **`scan_example.py`**
   - Purpose: Example client script showing how to use the scanner API
   - Type: Safe utility script
   - Usage: `python scan_example.py <repository_url>`

2. **`vulnerable-mcp-server.py`**
   - Purpose: Python MCP server with intentional vulnerabilities
   - Contains: Command injection, path traversal, SQL injection, SSRF, hardcoded secrets, etc.

3. **`vulnerable-mcp-server.js`**
   - Purpose: JavaScript MCP server with advanced vulnerabilities
   - Contains: Template injection, race conditions, XXE, prototype pollution, ReDoS, etc.

4. **`test_vulnerable_mcp.js`**
   - Purpose: Basic JavaScript test cases for CodeQL rules
   - Contains: Simple examples of each vulnerability type

### `/vulnerability_samples/`
Comprehensive vulnerability code examples organized by type:

- **`complex_vulnerabilities.py`** - Complex multi-layered vulnerability patterns
- **`VulnerablePythonScript.py`** - General vulnerable Python patterns
- **`malicious_mcp_samples/`** - MCP-specific malicious server examples
  - `apt_mcp_server.py` - APT-style persistent threat patterns
  - `backdoor_mcp_server.py` - Backdoor implementation examples
- **`yara_patterns/`** - YARA detection pattern test cases
  - `apt_behavioral_patterns.py` - APT behavior patterns
  - `container_privilege_escalation.py` - Container escape patterns
  - `data_exfiltration.py` - Data exfiltration techniques
  - `polymorphic_obfuscation.py` - Code obfuscation patterns
  - `schema_injection_mcp.py` - MCP schema injection
  - `tool_poisoning_unicode.py` - Unicode-based tool poisoning

⚠️ **WARNING: DO NOT USE THESE FILES IN PRODUCTION** ⚠️

## Vulnerability Categories Covered

### Code Injection
- ✅ Command injection via `exec()`, `os.system()`
- ✅ SQL injection via string concatenation
- ✅ Code injection via `eval()`
- ✅ Template literal injection
- ✅ XXE injection

### Path Traversal
- ✅ File system access without validation
- ✅ Directory traversal patterns (`../`)
- ✅ Default parameter path traversal

### Network Security
- ✅ SSRF via unvalidated URLs
- ✅ Insecure HTTP requests
- ✅ Network access despite "none" permissions

### Authentication & Authorization
- ✅ Hardcoded API keys and tokens
- ✅ Weak session ID generation
- ✅ Timing attack vulnerabilities
- ✅ Permission model bypass

### MCP-Specific Threats
- ✅ Tool poisoning via descriptions
- ✅ Schema injection
- ✅ Prompt injection patterns
- ✅ OAuth token exposure
- ✅ Permission declaration lies

### Application Logic
- ✅ Race conditions in async operations
- ✅ Memory leaks from unbounded collections
- ✅ ReDoS (Regular Expression DoS)
- ✅ Prototype pollution
- ✅ Information disclosure in errors

## Testing the Scanner

To test if your scanner correctly detects these vulnerabilities:

```bash
# Test the Python vulnerable server
python scan_example.py /path/to/vulnerable-mcp-server.py

# Test the JavaScript vulnerable server  
python scan_example.py /path/to/vulnerable-mcp-server.js

# Test via API
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repository_url": "file:///path/to/examples/vulnerable-mcp-server.py"}'
```

## Expected Detections

A properly configured scanner should detect:

- **Critical**: 15+ findings (command injection, hardcoded secrets, etc.)
- **High**: 10+ findings (SSRF, path traversal, etc.)  
- **Medium**: 5+ findings (information disclosure, weak crypto, etc.)
- **Low**: 2+ findings (code quality issues)

## Creating New Test Cases

When adding new vulnerable examples:

1. **Document the vulnerability type** in comments
2. **Include realistic MCP context** (tools, decorators, schemas)
3. **Add multiple variants** of the same vulnerability type
4. **Test against both YARA and CodeQL rules**
5. **Update this README** with the new patterns

## Security Note

These files are designed to trigger security scanners and may be flagged by antivirus software or security tools. This is expected behavior - they contain patterns that mimic real malware and vulnerabilities for testing purposes.