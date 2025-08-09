# CLAUDE.md

This file provides guidance to Claude Code when working with this MCP security scanner repository.

## Essential Commands

### Development & Testing
```bash
make restart              # Stop, build, and start all services  
make up                  # Start services
make down                # Stop services
make logs                # Show scanner logs
make test                # Run comprehensive tests
make scan URL=<repo>     # Scan a repository
```

### Direct Python Usage
```bash
pip install -r requirements.txt
python main.py                    # Run FastAPI server
python test_scanner.py           # Run tests
```

## Architecture Overview

**Main Flow**: `scanner/` → **Analyzers** → **Scoring** → **Results**

### Clean Architecture Principles

This codebase follows **Sandi Metz best practices** and **clean architecture**:

#### 📐 Mandatory Rules
1. **Classes**: ≤100 lines of code
2. **Methods**: ≤10 lines of code  
3. **Single Responsibility**: Each class/method does ONE thing
4. **Clear Separation**: Business logic, utilities, and orchestration are separate

#### 🎯 Design Patterns
- **Service Layer Pattern**: Business logic in dedicated services
- **Repository Pattern**: Data access abstraction
- **Dependency Injection**: Services are composed, not inherited
- **Async/Parallel**: Uses `asyncio.gather()` for performance

### Core Components

#### 1. **Scanner Module** (`scanner/`) - MODULAR ARCHITECTURE
```
scanner/
├── main_scanner.py              # Orchestrator (68 lines)
├── services/                    # Business logic layer
│   ├── repository_service.py   # Git operations (171 lines)
│   ├── analyzer_orchestrator.py # Analyzer management (127 lines)
│   ├── finding_service.py      # Finding processing (155 lines)
│   ├── finding_aggregator.py   # Aggregation logic (108 lines)
│   └── result_builder.py       # Result construction (111 lines)
└── utils/                       # Utilities
    └── url_parser.py           # URL parsing (68 lines)
```

#### 2. **Modular Analyzers** (`analyzers/`)
- **Static Analysis**: Bandit, CodeQL, YARA
- **Universal**: Trivy, Grype  
- **MCP-Specific**: Custom MCP vulnerability detection
- **Dynamic Analysis**: Runtime behavior analysis
- **Secret Detection**: TruffleHog
- **Malware**: ClamAV

#### 3. **Intelligent Analysis** (`analyzers/intelligent/`) - EXEMPLAR MODULE
```
intelligent/
├── main_analyzer.py            # Orchestrator
├── components/                 # Single-purpose analyzers
│   ├── semantic_analyzer.py   
│   ├── behavioral_analyzer.py 
│   ├── ecosystem_analyzer.py  
│   └── anomaly_detector.py    
├── services/                   # Business services
│   ├── risk_aggregator.py     
│   └── learning_system.py     
├── models/                     # Data structures
└── utils/                      # Utilities
```

### Module Design Requirements

When creating or refactoring modules, ALWAYS follow this structure:

```
module_name/
├── __init__.py                 # Public exports only
├── main_<module>.py           # Orchestrator (≤100 lines)
├── services/                   # Business logic
│   └── *.py                   # Each service ≤100 lines
├── models/                     # Data structures
│   └── *.py                   # Pydantic models
└── utils/                      # Pure utilities
    └── *.py                   # Stateless helpers
```

## Development Guidelines

### 🔴 CRITICAL: Code Structure Rules

**EVERY** new component MUST follow these rules:

1. **File Structure**:
   - Group related functionality in modules
   - Use `services/` for business logic
   - Use `utils/` for pure functions
   - Use `models/` for data structures

2. **Class Rules**:
   ```python
   class ServiceName:  # ≤100 lines TOTAL
       def method_one(self):  # ≤10 lines
           # Single responsibility
           pass
       
       def method_two(self):  # ≤10 lines
           # Another single responsibility
           pass
   ```

3. **Method Decomposition**:
   ```python
   # ❌ BAD: Long method
   def process_data(self, data):
       # 50 lines of code doing multiple things
       
   # ✅ GOOD: Decomposed methods
   def process_data(self, data):
       validated = self._validate(data)
       transformed = self._transform(validated)
       return self._format(transformed)
   
   def _validate(self, data):  # ≤10 lines
       # Just validation
   
   def _transform(self, data):  # ≤10 lines
       # Just transformation
   
   def _format(self, data):  # ≤10 lines
       # Just formatting
   ```

### Adding New Features

1. **New Analyzer**:
   - Create in `analyzers/` following `BaseAnalyzer`
   - Register in `AnalyzerOrchestrator`
   - Keep analyze() method ≤10 lines

2. **New Service**:
   - Create in appropriate `services/` directory
   - Single responsibility only
   - Inject dependencies via __init__

3. **New Utility**:
   - Create in `utils/`
   - Pure functions only (no state)
   - Group related utilities in single file

### Refactoring Checklist

When refactoring existing code:

- [ ] Identify responsibilities (list them)
- [ ] Create service for each responsibility
- [ ] Ensure each class ≤100 lines
- [ ] Ensure each method ≤10 lines
- [ ] Extract utilities to `utils/`
- [ ] Extract models to `models/`
- [ ] Update imports and dependencies
- [ ] Test each service independently

## MCP Security Focus

Specialized for Model Context Protocol server security:

**Vulnerability Types**:
- Prompt injection in tool descriptions
- Tool poisoning attacks (TPAs)
- Permission abuse and privilege escalation
- Schema injection vulnerabilities
- Data exfiltration patterns

**Advanced Features**:
- Context-aware analysis to reduce false positives
- ML-based legitimacy assessment
- Real MCP protocol communication testing
- Behavioral pattern recognition

## Critical Files

- `scanner/main_scanner.py`: Clean orchestration example
- `scanner/services/`: Service layer examples
- `analyzers/intelligent/`: Best-in-class module structure
- `analyzers/mcp_analyzer.py`: MCP-specific detection  
- `models.py`: Pydantic data structures
- `main.py`: FastAPI web service

## Examples of Good Architecture

### ✅ GOOD: scanner/services/finding_service.py
```python
class FindingService:  # 155 lines total
    def deduplicate_findings(self, findings):  # 8 lines
        grouped = self._group_findings(findings)
        unique = self._select_best_findings(grouped)
        self._log_stats(len(findings), len(unique))
        return unique
    
    def _group_findings(self, findings):  # 7 lines
        # Single responsibility: grouping
```

### ✅ GOOD: analyzers/intelligent/main_analyzer.py
```python
class IntelligentAnalyzer:  # <100 lines
    def __init__(self):
        # Dependency injection
        self.semantic = SemanticAnalyzer()
        self.behavioral = BehavioralAnalyzer()
```

### ❌ AVOID: Monolithic files
- Files with 500+ lines
- Classes doing multiple things
- Methods with nested complexity
- Direct file I/O in business logic

## Git Workflow

⚠️ **IMPORTANT**: Always git commit changes after completing tasks or implementing features. This ensures work is preserved and progress is tracked.

**Never test against** `https://github.com/modelcontextprotocol/servers` (causes timeouts)

## Quality Standards

Every PR must meet these standards:
1. No class exceeds 100 lines
2. No method exceeds 10 lines
3. Each class has single responsibility
4. Services are testable in isolation
5. Clear separation between layers

## Future Architecture Goals

1. **All modules** follow `scanner/` and `analyzers/intelligent/` patterns
2. **100% testable** services with dependency injection
3. **No monolithic files** remaining in codebase
4. **Clear boundaries** between all components
5. **Documentation** in each module's README