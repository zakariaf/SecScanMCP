# Grype Analyzer Module

Fast vulnerability scanner for container images and filesystems by Anchore.

## Architecture

This module follows clean architecture principles with clear separation of concerns:

```
grype/
├── __init__.py              # Module exports
├── main_analyzer.py         # Orchestrator (64 lines)
└── services/
    ├── scan_service.py      # Grype scan execution (77 lines)
    ├── sbom_service.py      # SBOM management (74 lines)
    └── finding_service.py   # Match to finding conversion (217 lines)
```

## Components

### Main Analyzer (`main_analyzer.py`)
- **Responsibility**: Orchestrates Grype vulnerability scanning
- **Key Features**:
  - SBOM optimization for faster scans
  - Result processing and finding creation
  - Error handling and logging

### Scan Service (`scan_service.py`)
- **Responsibility**: Handles Grype command execution
- **Key Features**:
  - SBOM-based scanning (faster)
  - Direct filesystem scanning with exclusions
  - Command building and result parsing
  - JSON output processing

### SBOM Service (`sbom_service.py`)
- **Responsibility**: Manages SBOM files for optimization
- **Key Features**:
  - Existing SBOM discovery (multiple formats)
  - Syft integration for SBOM generation
  - Temporary file management and cleanup
  - Pattern-based SBOM detection

### Finding Service (`finding_service.py`)
- **Responsibility**: Converts Grype matches to standardized findings
- **Key Features**:
  - Vulnerability severity mapping
  - Fix version extraction (multiple formats)
  - CVSS score processing
  - EPSS risk scoring integration
  - KEV (Known Exploited Vulnerabilities) detection
  - Confidence calculation based on match quality

## Features

- **Fast Scanning**: SBOM optimization when available
- **Comprehensive Coverage**: Container images and filesystems
- **Risk Prioritization**: EPSS scores and KEV data integration
- **Multiple Formats**: Supports various SBOM formats (JSON, SPDX, CycloneDX)
- **Smart Exclusions**: Skips common non-vulnerable paths
- **Fix Information**: Extracts available fix versions
- **Match Quality**: Confidence scoring based on match type

## Scanning Strategies

### 1. SBOM-Based Scanning (Preferred)
- Uses existing SBOM files if found
- Generates SBOM with Syft if available
- Much faster than filesystem scanning
- More accurate package detection

### 2. Direct Filesystem Scanning (Fallback)
- Scans repository directly
- Excludes common non-vulnerable paths:
  - `.git/**`
  - `**/node_modules/**`
  - `**/__pycache__/**`

## Severity Enhancement

- **KEV Detection**: Increases severity for known exploited vulnerabilities
  - Medium → High
  - Low → Medium
- **EPSS Integration**: Adds exploitation probability scores
- **CVSS Processing**: Extracts all CVSS versions and scores

## Match Confidence

- **Exact Direct Match**: 0.95 confidence
- **Exact Indirect Match**: 0.85 confidence  
- **Default Match**: 0.9 confidence

## Clean Architecture Benefits

1. **Performance**: Optimized SBOM-first scanning strategy
2. **Reliability**: Robust error handling and fallback mechanisms
3. **Maintainability**: Clear service separation
4. **Testability**: Independent service testing
5. **Extensibility**: Easy to add new scan options or formats