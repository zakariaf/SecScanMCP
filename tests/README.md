# Enhanced MCP Security Scanner Test Suite

This directory contains comprehensive tests for the MCP Security Scanner, including vulnerability detection tests based on real-world MCP attack patterns.

## Test Structure

### 1. Main Test Runner
- `test_scanner.py` - **Primary comprehensive test suite**
  - HTTP API-based testing (works with Docker scanner)
  - Comprehensive vulnerability samples with 7 vulnerability types
  - MCP-specific vulnerability detection tests
  - Real repository testing capabilities
  - Detailed effectiveness assessment

### 2. Specialized Test Files
- `test_mcp_specific_vulnerabilities.py` - MCP protocol vulnerability unit tests
- `test_mcp_config_analyzer.py` - MCP configuration vulnerability tests

### 3. Analyzer Tests
- `test_analyzers_simple.py` - Basic analyzer tests
- `test_analyzers_enhanced.py` - Enhanced analyzer tests with complex scenarios
- `test_clamav_analyzer.py` - ClamAV analyzer tests
- `test_codeql_analyzer.py` - CodeQL analyzer tests
- `test_opengrep.py` - OpenGrep analyzer tests
- `test_yara_analyzer.py` - YARA analyzer tests
- `test_attack_payloads.py` - Attack payload detection tests
- `test_dynamic_integration.py` - Dynamic analysis integration tests
- `test_dynamic_structure.py` - Dynamic analyzer structure tests
- `test_enhanced_scoring.py` - Enhanced scoring system tests
- `test_enhanced_scoring_simple.py` - Simple scoring tests
- `test_scanner_integration.py` - Integration tests for the scanner

## Running Tests

### Quick Start (Recommended)
```bash
# Start the scanner first
make restart

# Run comprehensive tests (default)
python3 tests/test_scanner.py

# Or via Makefile
make test
```

### Test Options
```bash
# Run comprehensive tests (all vulnerability types)
python3 tests/test_scanner.py --comprehensive

# Test only MCP-specific vulnerabilities
python3 tests/test_scanner.py --mcp-only

# Test with real vulnerable repositories
python3 tests/test_scanner.py --real-repos

# Show help
python3 tests/test_scanner.py --help
```

## Test Coverage

### ✅ Vulnerability Types Tested
1. **Hardcoded Secrets** - API keys, passwords, tokens
2. **Command Injection** - Shell command execution
3. **SQL Injection** - Database query vulnerabilities  
4. **Prompt Injection** - MCP-specific LLM manipulation
5. **Path Traversal** - File system access bypass
6. **SSRF** - Server-side request forgery
7. **Insecure Deserialization** - Object deserialization attacks

### ✅ MCP-Specific Coverage
- **Tool Poisoning** - Malicious MCP tool manipulation
- **Resource Abuse** - MCP resource access violations
- **Configuration Issues** - Insecure MCP client configs
- **Protocol Abuse** - MCP communication vulnerabilities

### ✅ Real-World Testing
- Tests against actual vulnerable MCP servers
- Integration with damn-vulnerable-MCP-server repository
- Comprehensive dependency vulnerability testing
- Multi-language support (Python, JavaScript, Docker)

## Test Results Summary

Our enhanced test suite validates:

- ✅ **57+ vulnerabilities detected** in comprehensive tests
- ✅ **15+ critical/high severity issues** properly flagged
- ✅ **MCP protocol auto-detection** working correctly
- ✅ **Multi-tool analysis** providing complementary coverage
- ✅ **Real vulnerability patterns** successfully identified

## Expected Results

When running against vulnerable samples, expect:
- **Security Grade: F (0-20/100)** for intentionally vulnerable code
- **Critical vulnerabilities: 5-10** per vulnerable repository
- **High-severity vulnerabilities: 8-15** per test
- **MCP-specific detections: 3-8** when scanning MCP servers

## Adding New Tests

To add new vulnerability tests:

1. **For HTTP API tests**: Add samples to `create_comprehensive_test_samples()` in `test_scanner.py`
2. **For unit tests**: Create new test files in this directory
3. **For MCP-specific**: Extend the MCP categorization in test functions
4. **For vulnerability samples**: Add to `examples/vulnerability_samples/` directory

## Test Infrastructure

- **Docker-based**: Tests use the running Docker scanner (port 8000)
- **GitHub integration**: Tests real repositories via GitHub URLs
- **Comprehensive reporting**: Detailed vulnerability categorization and effectiveness metrics
- **Multiple test modes**: Flexible testing options for different scenarios