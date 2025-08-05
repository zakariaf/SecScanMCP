# Military-Grade CodeQL Security Suite for MCP Servers

## Overview

This comprehensive security suite provides military-grade vulnerability detection for Model Context Protocol (MCP) servers using CodeQL static analysis. The suite is designed to detect MCP-specific vulnerabilities that traditional security scanners might miss.

## Architecture

The suite is organized into language-specific packs to avoid dbscheme conflicts:
- **JavaScript/TypeScript Pack**: `/rules/codeql/mcp-security-queries/`
- **Python Pack**: `/rules/codeql/mcp-security-queries/python/`

## Vulnerability Coverage

### 1. Command Injection (CWE-78)
- **Query IDs**: `js/mcp-command-injection`, `py/mcp-command-injection`
- **Severity**: 9.8 (Critical)
- **Description**: Detects when MCP tool parameters are used to construct shell commands without proper sanitization.

### 2. Code Injection (CWE-94)
- **Query IDs**: `js/mcp-code-injection`, `py/mcp-code-injection`
- **Severity**: 9.3 (Critical)
- **Description**: Identifies when MCP tool parameters are evaluated as code through eval(), exec(), or similar functions.

### 3. Path Traversal (CWE-22)
- **Query IDs**: `js/mcp-path-traversal`, `py/mcp-path-traversal`
- **Severity**: 8.6 (High)
- **Description**: Detects file system access using MCP tool parameters without proper path validation.

### 4. SQL Injection (CWE-89)
- **Query IDs**: `js/mcp-sql-injection`, `py/mcp-sql-injection`
- **Severity**: 8.8 (High)
- **Description**: Identifies SQL query construction using unsanitized MCP tool parameters.

### 5. Server-Side Request Forgery (CWE-918)
- **Query IDs**: `js/mcp-ssrf`, `py/mcp-ssrf`
- **Severity**: 9.1 (Critical)
- **Description**: Detects HTTP requests made using MCP tool parameters that could target internal services.

### 6. Prompt Injection (CWE-352)
- **Query IDs**: `js/mcp-prompt-injection`, `py/mcp-prompt-injection`
- **Severity**: 8.5 (High)
- **Description**: Identifies tool descriptions and outputs that could manipulate AI behavior through hidden instructions.

### 7. OAuth Token Theft (CWE-256, CWE-522)
- **Query IDs**: `js/mcp-oauth-token-theft`, `py/mcp-oauth-token-theft`
- **Severity**: 9.1 (Critical)
- **Description**: Detects insecure storage and transmission of OAuth tokens in MCP servers.

### 8. Data Exfiltration (CWE-200)
- **Query IDs**: `js/mcp-data-exfiltration`, `py/mcp-data-exfiltration`
- **Severity**: 8.8 (High)
- **Description**: Tracks sensitive data flow to external services without proper validation.

### 9. Untrusted Tool Descriptions (CWE-20)
- **Query IDs**: `js/mcp-untrusted-tool-description`, `py/mcp-untrusted-tool-description`
- **Severity**: 7.5 (High)
- **Description**: Identifies dynamic or suspicious tool descriptions that could be exploited.

## Detection Patterns

### JavaScript/TypeScript
- Decorator patterns: `@mcp.tool()`, `@fastmcp.tool()`
- Class/method patterns: Methods in MCP-related classes
- Function registration: `registerTool()`, `addTool()`
- Tool object patterns: Objects with `tools` property containing handlers

### Python
- Decorator patterns: `@mcp.tool()`, `@app.tool()`, `@server.tool()`
- Class methods: Methods in MCP server classes
- Function decorators: Direct tool decorators

## Advanced Features

### 1. Context-Aware Detection
- Identifies MCP-specific patterns and frameworks
- Tracks data flow through MCP tool parameters
- Detects both direct and indirect vulnerabilities

### 2. Sanitizer Recognition
- Shell escape functions: `shlex.quote`, `escape_shell`
- SQL parameterization: `prepare`, `prepareStatement`
- Path validation: `path.normalize`, `path.basename`
- URL validation: `validateURL`, `checkAllowlist`

### 3. Taint Tracking
- Tracks user input through complex data flows
- Handles string interpolation and concatenation
- Follows data through object construction

### 4. AI-Specific Security
- Prompt injection detection
- Hidden instruction patterns
- Tool description manipulation
- Output validation for AI consumption

## Usage

### Running Scans

```bash
# Scan an MCP server repository
make scan URL=https://github.com/example/mcp-server

# With specific options
docker-compose run scanner python main.py scan-repo https://github.com/example/mcp-server
```

### Integration with CI/CD

```yaml
- name: MCP Security Scan
  run: |
    docker-compose run scanner python main.py scan-repo ${{ github.repository }}
```

## Best Practices for MCP Server Development

1. **Input Validation**: Always validate and sanitize tool parameters
2. **Use Parameterized Queries**: Prevent SQL injection with prepared statements
3. **Path Validation**: Use `path.resolve()` and validate against allowed directories
4. **Secure Token Storage**: Use encryption and secure storage libraries
5. **URL Allowlisting**: Validate URLs against an allowlist for SSRF prevention
6. **Tool Description Safety**: Keep descriptions static and free of user input
7. **Output Sanitization**: Ensure tool outputs don't contain prompt injection patterns

## Performance Optimization

- Language-specific packs reduce analysis time
- Efficient query design with proper indexing
- Parallel analysis for multi-language projects
- Smart caching of CodeQL databases

## Future Enhancements

1. **Additional Vulnerability Types**
   - XML External Entity (XXE) injection
   - Deserialization vulnerabilities
   - Race conditions in tool execution

2. **Framework-Specific Rules**
   - FastMCP-specific patterns
   - Anthropic SDK patterns
   - Custom MCP implementations

3. **Machine Learning Integration**
   - Anomaly detection for unusual tool patterns
   - Behavioral analysis of tool interactions

## Contributing

To add new queries:
1. Follow the existing query structure
2. Use appropriate CWE references
3. Include comprehensive documentation
4. Test against known vulnerable patterns
5. Ensure compatibility with latest CodeQL APIs

## License

This security suite is part of the SecScanMCP project and follows the project's licensing terms.