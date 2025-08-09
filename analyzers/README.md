# Analyzers Module - Modular Security Analysis Architecture

## Overview

The `analyzers` module has been refactored to follow **Sandi Metz best practices** and **clean architecture principles**. Large monolithic files have been broken down into focused, modular components.

## Refactoring Results

### ✅ Completed Refactorings

#### 1. MCP Analyzer (`mcp_analyzer.py` → `mcp/`)
**Before**: 2246 lines of monolithic code  
**After**: Modular architecture with focused components

```
analyzers/mcp/
├── main_analyzer.py          # Orchestrator (95 lines)
├── services/                 # Business logic
│   ├── config_analyzer.py   # Configuration analysis (185 lines)
│   └── code_analyzer.py     # Python code analysis (165 lines)
├── detectors/               # Detection engines
│   ├── injection_detector.py  # Injection detection (120 lines)
│   └── permission_detector.py # Permission analysis (155 lines)
└── models/                  # Data structures
    └── patterns.py          # Security patterns (85 lines)
```

**Benefits**:
- Each component has a single responsibility
- Easy to test individual detectors
- Clear separation between configuration and code analysis
- Maintainable pattern definitions

#### 2. Attack Payloads (`attack_payloads.py` → `payloads/`)
**Before**: 1445 lines of payload definitions  
**After**: Organized payload library

```
analyzers/payloads/
├── main_payloads.py         # Main interface (75 lines)
├── generators/              # Payload generation
│   └── payload_generator.py # Generation logic (155 lines)
└── categories/              # Organized by attack type
    ├── prompt_injection.py  # Prompt injection payloads (65 lines)
    ├── command_injection.py # Command injection payloads (85 lines)
    └── path_traversal.py   # Path traversal payloads (75 lines)
```

**Benefits**:
- Payloads organized by attack category
- Easy to add new payload types
- Consistent payload structure
- Automated variation generation

### 📋 Architecture Principles Applied

#### Single Responsibility Principle
- `InjectionDetector`: Only handles injection pattern detection
- `ConfigAnalyzer`: Only analyzes MCP configuration files  
- `CodeAnalyzer`: Only analyzes Python source code
- `PermissionDetector`: Only detects permission abuse

#### Small Classes & Methods
- All classes under 200 lines (most under 100)
- All methods under 10 lines of logic
- Complex operations decomposed into smaller methods

#### Dependency Injection
```python
class MCPSpecificAnalyzer:
    def __init__(self):
        # Services injected, not inherited
        self.config_analyzer = ConfigAnalyzer()
        self.code_analyzer = CodeAnalyzer()
        self.injection_detector = InjectionDetector()
```

#### Clear Separation of Concerns
- **Detectors**: Pattern matching and rule application
- **Services**: Business logic and analysis orchestration
- **Models**: Data structures and pattern definitions
- **Main Analyzer**: Coordination only

## Usage Examples

### Using Modular MCP Analyzer
```python
from analyzers.mcp import MCPSpecificAnalyzer

analyzer = MCPSpecificAnalyzer()
findings = await analyzer.analyze(repo_path, project_info)
```

### Using Individual Components
```python
from analyzers.mcp.detectors import InjectionDetector

detector = InjectionDetector()
findings = detector.check_text_for_injection(text, location, "tool")
```

### Using Payload Library
```python
from analyzers.payloads import AdvancedPayloadGenerator

generator = AdvancedPayloadGenerator()
critical_payloads = generator.get_critical_payloads()
```

## Legacy Files Status

### 🚫 Deprecated (Use New Modules)
- `mcp_analyzer.py` → Use `analyzers.mcp.MCPSpecificAnalyzer`
- `attack_payloads.py` → Use `analyzers.payloads.AdvancedPayloadGenerator`

### 📋 Pending Refactoring
- `dynamic_analyzer.py` (1383 lines) - Needs modular structure
- `traffic_analyzer.py` (737 lines) - Requires service extraction  
- `ml_anomaly_detector.py` (691 lines) - ML components need separation
- `mcp_client.py` (637 lines) - Client logic needs modularity

### ✅ Already Well-Structured
- `intelligent/` - Already follows clean architecture
- `security_tools/` - Focused analyzer tools
- `base.py` - Clean base class (98 lines)

## Development Guidelines

### Adding New Analyzers

1. **Create Module Structure**:
```bash
mkdir analyzers/new_analyzer/{services,detectors,models,utils}
```

2. **Follow Pattern**:
```python
# analyzers/new_analyzer/main_analyzer.py
class NewAnalyzer(BaseAnalyzer):  # ≤100 lines
    def __init__(self):
        # Inject services
        self.service = AnalysisService()
        self.detector = PatternDetector()
    
    async def analyze(self, repo_path, project_info):  # ≤10 lines
        findings = self.service.analyze_files(repo_path)
        return self.detector.filter_findings(findings)
```

3. **Create Focused Services**:
```python
# analyzers/new_analyzer/services/analysis_service.py  
class AnalysisService:  # ≤100 lines
    def analyze_files(self, path):  # ≤10 lines
        files = self._find_files(path)
        return self._process_files(files)
```

### Testing Strategy

Each component can be tested independently:

```python
# Test detector in isolation
def test_injection_detector():
    detector = InjectionDetector()
    findings = detector.check_text_for_injection("malicious text", "test")
    assert len(findings) > 0

# Test service in isolation  
def test_config_analyzer():
    analyzer = ConfigAnalyzer()
    findings = analyzer.analyze_mcp_config(test_config, "test.json")
    assert findings[0].severity == SeverityLevel.HIGH
```

## Performance Benefits

### Before Refactoring
- Single large files difficult to navigate
- Hard to test specific functionality
- Tight coupling between components
- Code duplication across analyzers

### After Refactoring
- Fast imports (only load needed components)
- Parallel testing of components
- Easy to mock dependencies
- Reusable detection logic
- Clear error boundaries

## Future Improvements

1. **Complete Remaining Refactorings**
   - Break down `dynamic_analyzer.py` into services
   - Modularize `traffic_analyzer.py` 
   - Extract ML components from `ml_anomaly_detector.py`

2. **Add Interface Protocols**
   ```python
   from typing import Protocol
   
   class Detector(Protocol):
       def detect(self, content: str) -> List[Finding]: ...
   ```

3. **Implement Plugin System**
   - Dynamic analyzer registration
   - External analyzer plugins
   - Configuration-driven analysis

4. **Enhanced Testing**
   - Component integration tests
   - Performance benchmarks
   - Coverage reporting per service

## Migration Guide

### Existing Code Using Old Analyzers

```python
# OLD - Still works but deprecated
from analyzers.mcp_analyzer import MCPSpecificAnalyzer

# NEW - Recommended approach  
from analyzers.mcp import MCPSpecificAnalyzer
```

### Extending Functionality

```python
# OLD - Modifying large monolithic file
# Edit mcp_analyzer.py (2246 lines) 

# NEW - Add focused component
# Create analyzers/mcp/detectors/new_detector.py (≤100 lines)
# Register in main_analyzer.py
```

The refactored analyzer architecture provides a solid foundation for maintainable, testable, and extensible security analysis components.