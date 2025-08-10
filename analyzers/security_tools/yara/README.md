# YARA Analyzer Module

Advanced pattern matching engine for malware and threat detection using YARA rules.

## Architecture

This module follows clean architecture principles with clear separation of concerns:

```
yara/
├── __init__.py              # Module exports
├── main_analyzer.py         # Orchestrator (95 lines)
└── services/
    ├── rule_service.py      # Rule loading & compilation (79 lines)
    ├── scan_service.py      # File scanning operations (59 lines)
    └── finding_service.py   # Match to finding conversion (199 lines)
```

## Components

### Main Analyzer (`main_analyzer.py`)
- **Responsibility**: Orchestrates YARA analysis workflow
- **Key Features**:
  - Parallel file scanning with thread pool
  - Timeout management for large repositories
  - File filtering and validation

### Rule Service (`rule_service.py`)
- **Responsibility**: Manages YARA rule loading and compilation
- **Key Features**:
  - Automatic rule directory discovery
  - Multiple fallback paths for rules
  - Rule compilation and validation

### Scan Service (`scan_service.py`)
- **Responsibility**: Handles individual file scanning
- **Key Features**:
  - File size limits (50MB max)
  - Per-file timeout (30 seconds)
  - Match processing pipeline

### Finding Service (`finding_service.py`)
- **Responsibility**: Converts YARA matches to standardized findings
- **Key Features**:
  - Line number extraction for matches
  - Severity determination from metadata
  - Evidence collection with match details
  - Vulnerability type mapping

## Features

- **Complex Pattern Matching**: Wildcards, regex, and hex patterns
- **APT Detection**: Advanced Persistent Threat patterns
- **Polymorphic Malware Detection**: Obfuscation-resistant rules
- **MCP-Specific Patterns**: Tool poisoning, prompt injection
- **Performance Optimized**: Parallel scanning with timeouts
- **Line-Level Precision**: Exact line numbers for matches

## Configuration

### Rule Paths
The analyzer searches for rules in these locations (in order):
1. `/app/rules/yara/` (Docker default)
2. `./rules/yara/` (Local development)
3. Relative to module location

### Limits
- **Max File Size**: 50MB per file
- **Scan Timeout**: 30 seconds per file
- **Total Timeout**: 5 minutes for repository
- **Max Workers**: 4 parallel scan threads

## Vulnerability Types Detected

- Malware and trojans
- Backdoors and rootkits
- Command injection patterns
- SQL injection patterns
- Cross-site scripting (XSS)
- Hardcoded credentials
- Weak cryptography
- Path traversal
- MCP-specific threats
- Prompt injection patterns

## Clean Architecture Benefits

1. **Testability**: Each service can be tested independently
2. **Maintainability**: Clear responsibilities, easy to modify
3. **Scalability**: Easy to add new rule types or processing logic
4. **Performance**: Optimized parallel processing
5. **Reliability**: Proper error handling at each layer