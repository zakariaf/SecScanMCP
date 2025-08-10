# Bandit Analyzer Module

AST-based security linter for Python code by PyCQA.

## Architecture

This module follows clean architecture principles with clear separation of concerns:

```
bandit/
├── __init__.py              # Module exports
├── main_analyzer.py         # Orchestrator (61 lines)
└── services/
    ├── scan_service.py      # Bandit execution (55 lines)
    └── finding_service.py   # Result conversion (139 lines)
```

## Components

### Main Analyzer (`main_analyzer.py`)
- **Responsibility**: Orchestrates Bandit Python security analysis
- **Key Features**:
  - Python project detection
  - Ignore file management
  - Result processing coordination
  - Cleanup handling

### Scan Service (`scan_service.py`)
- **Responsibility**: Handles Bandit command execution
- **Key Features**:
  - Bandit module execution via Python
  - JSON output parsing
  - Command building with ignore patterns
  - Error handling for scan failures

### Finding Service (`finding_service.py`)
- **Responsibility**: Converts Bandit results to standardized findings
- **Key Features**:
  - Comprehensive test ID to vulnerability type mapping
  - Severity and confidence conversion
  - Code snippet preservation
  - Reference and recommendation building

## Features

- **Python-Specific**: Only runs on Python projects
- **AST-Based Analysis**: Static analysis of Python syntax trees
- **Comprehensive Coverage**: 40+ security test patterns
- **Medium/High Focus**: Filters out low-severity issues (-ll flag)
- **Ignore Support**: Integrates with ignore file patterns

## Vulnerability Type Mapping

### Command Injection
- **B201**: Flask debug mode
- **B307**: Use of eval()
- **B322**: Use of input()
- **B601-B609**: Process and shell execution issues

### SQL Injection
- **B608**: Hardcoded SQL expressions
- **B610**: Django extra() usage
- **B611**: Django RawSQL usage
- **B703**: Django mark_safe()

### XXE (XML External Entities)
- **B313-B320**: Various XML parsing vulnerabilities

### Insecure Configuration
- **B301-B306**: Pickle, marshal, crypto issues
- **B308-B325**: Various configuration problems
- **B701-B702**: Template engine issues

### Path Traversal
- **B310**: urllib.urlopen usage

## Confidence Mapping

- **HIGH**: 0.9 confidence
- **MEDIUM**: 0.7 confidence  
- **LOW**: 0.5 confidence

## Command Options

- **Recursive**: `-r` scans all subdirectories
- **JSON Output**: `-f json` for structured results
- **Medium/High Only**: `-ll` filters severity
- **Quiet Mode**: `--quiet` reduces noise
- **Ignore Patterns**: `--exclude` for file exclusions

## Clean Architecture Benefits

1. **Language-Specific**: Efficient Python-only execution
2. **Comprehensive Mapping**: Detailed vulnerability categorization
3. **Maintainability**: Clear service separation
4. **Testability**: Independent component testing
5. **Extensibility**: Easy to add new test ID mappings