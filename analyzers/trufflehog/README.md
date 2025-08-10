# TruffleHog Analyzer Module

Searches for secrets in code repositories using TruffleHog.

## Architecture

This module follows clean architecture principles with clear separation of concerns:

```
trufflehog/
├── __init__.py              # Module exports
├── main_analyzer.py         # Orchestrator (42 lines)
└── services/
    ├── scan_service.py      # TruffleHog execution (66 lines)
    └── finding_service.py   # Result conversion & masking (133 lines)
```

## Components

### Main Analyzer (`main_analyzer.py`)
- **Responsibility**: Orchestrates TruffleHog secret scanning
- **Key Features**:
  - Scan coordination and result processing
  - Error handling and logging
  - Clean finding aggregation

### Scan Service (`scan_service.py`)
- **Responsibility**: Handles TruffleHog command execution
- **Key Features**:
  - Streaming JSON line processing (TruffleHog outputs JSON lines)
  - Filesystem-based scanning (not git history)
  - Concurrent execution with controlled parallelism
  - Robust JSON parsing with error handling

### Finding Service (`finding_service.py`)
- **Responsibility**: Converts TruffleHog results to standardized findings
- **Key Features**:
  - Secret type detection and mapping
  - Smart severity assignment (test/example secrets get lower severity)
  - Secret masking for security (shows first/last 4 chars)
  - Verification-based confidence scoring
  - Location extraction with relative paths

## Features

- **Filesystem Scanning**: Scans current files, not git history (faster)
- **Secret Masking**: Protects actual secrets in evidence
- **Verification Support**: Higher confidence for verified secrets
- **Smart Severity**: Lower severity for test/example credentials
- **Streaming Processing**: Handles TruffleHog's JSON line output
- **Concurrent Execution**: 4 parallel workers for performance

## Secret Type Detection

### API Key Exposure
- **AWS**: Amazon Web Services credentials
- **GitHub**: GitHub tokens and keys
- **GitLab**: GitLab access tokens
- **Slack**: Slack API tokens

### Hardcoded Secrets
- **PrivateKey**: SSH and TLS private keys
- **JWT**: JSON Web Tokens
- **Password**: Database and application passwords
- **Generic**: Other secret patterns

## Severity Assignment

- **HIGH**: Production secrets and API keys
- **MEDIUM**: Test/example credentials (detected by name patterns)

## Confidence Scoring

- **0.95**: Verified secrets (TruffleHog confirmed validity)
- **0.7**: Unverified secrets (pattern matches only)

## Command Options

- **filesystem**: Scan current files (not git history)
- **--json**: JSON line output format
- **--no-update**: Skip detector updates for speed
- **--concurrency 4**: Parallel scanning
- **--exclude-paths .git**: Skip git metadata

## Secret Masking

Secrets are masked in evidence for security:
- **Long secrets**: Show first 4 and last 4 characters (`abcd****wxyz`)
- **Short secrets**: Completely masked (`********`)

## Clean Architecture Benefits

1. **Security**: Proper secret masking prevents leakage
2. **Performance**: Streaming processing and concurrency
3. **Reliability**: Robust JSON parsing and error handling
4. **Maintainability**: Clear service separation
5. **Extensibility**: Easy to add new secret types