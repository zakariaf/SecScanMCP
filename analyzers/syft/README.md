# Syft Analyzer Module

Software Bill of Materials (SBOM) generation and analysis for package and license compliance.

## Architecture

This module follows clean architecture principles with clear separation of concerns:

```
syft/
├── __init__.py              # Module exports
├── main_analyzer.py         # Orchestrator (65 lines)
└── services/
    ├── sbom_service.py      # SBOM generation (82 lines)
    ├── license_service.py   # License analysis (162 lines)  
    ├── component_service.py # Component analysis (155 lines)
    └── metadata_service.py  # Metadata & summaries (130 lines)
```

## Components

### Main Analyzer (`main_analyzer.py`)
- **Responsibility**: Orchestrates Syft SBOM analysis workflow
- **Key Features**:
  - SBOM generation coordination
  - Multi-aspect analysis (licenses, components, metadata)
  - Integration with project metadata

### SBOM Service (`sbom_service.py`)
- **Responsibility**: Manages SBOM generation using Syft tool
- **Key Features**:
  - Syft command execution with all catalogers
  - Temporary file management
  - JSON SBOM parsing and validation

### License Service (`license_service.py`)
- **Responsibility**: Analyzes licenses for compliance issues
- **Key Features**:
  - Restrictive license detection (GPL, AGPL)
  - Weak copyleft identification (LGPL, MPL)
  - Complex license landscape warnings
  - License compatibility recommendations

### Component Service (`component_service.py`)
- **Responsibility**: Analyzes components for security concerns
- **Key Features**:
  - Binary package detection
  - Duplicate version identification
  - Unknown package analysis
  - Security risk assessment

### Metadata Service (`metadata_service.py`)
- **Responsibility**: Analyzes SBOM completeness and creates summaries
- **Key Features**:
  - Package information completeness analysis
  - Language inference from package types
  - SBOM summary generation for other analyzers
  - Quality metrics calculation

## Features

- **Comprehensive SBOM Generation**: Uses all Syft catalogers
- **License Compliance**: Identifies restrictive and problematic licenses
- **Security Analysis**: Detects binary packages and version conflicts
- **Quality Assessment**: Measures SBOM completeness
- **Integration Support**: Provides summaries for other analyzers
- **Multi-Format Support**: JSON SBOM with extensible parsing

## License Classifications

### Restrictive Licenses (High Severity)
- GPL-2.0, GPL-3.0, AGPL-3.0 (and variants)
- Requires source code disclosure

### Weak Copyleft (Medium Severity)  
- LGPL-2.1, LGPL-3.0, MPL-2.0, EPL-2.0
- Limited copyleft requirements

## Component Issues Detected

- **Binary Packages**: Hard-to-audit executables
- **Version Conflicts**: Multiple versions of same package
- **Unknown Packages**: Missing version information
- **Incomplete Metadata**: Poor package management

## Clean Architecture Benefits

1. **Separation of Concerns**: Each service handles one analysis type
2. **Testability**: Services can be tested independently
3. **Maintainability**: Easy to add new analysis types
4. **Reusability**: Services can be used by other analyzers
5. **Extensibility**: Easy to add new license types or rules