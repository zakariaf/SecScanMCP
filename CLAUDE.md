# CLAUDE.md

This file provides guidance to Claude Code when working with this MCP security scanner repository.

## Essential Commands

### Development & Testing

```bash
make restart              # Stop, build, and start all services
make up                   # Start services
make down                 # Stop services
make logs                 # Show scanner logs
make test                 # Run comprehensive tests
make scan URL=<repo>      # Scan a repository
make health               # Check scanner health
make status               # Show service status
```

### Direct Python Usage

```bash
pip install -r requirements.txt
python main.py                    # Run FastAPI server (port 8000)
python test_scanner.py            # Run tests
```

### Tool Setup

```bash
make setup-all            # Setup all security tools
make setup-clamav         # Setup ClamAV
make setup-yara           # Setup YARA
make setup-codeql         # Setup CodeQL
make install-local        # Install tools locally
```

## Architecture Overview

**Main Flow**: `main.py` → `scanner/` → **Analyzers** (20+) → **Scoring** → **Results**

### Clean Architecture Principles

This codebase follows **Sandi Metz best practices** and **clean architecture**:

#### Mandatory Rules

1. **Classes**: ≤100 lines of code
2. **Methods**: ≤10 lines of code
3. **Single Responsibility**: Each class/method does ONE thing
4. **Clear Separation**: Business logic, utilities, and orchestration are separate

#### Design Patterns

- **Service Layer Pattern**: Business logic in dedicated services
- **Repository Pattern**: Data access abstraction
- **Dependency Injection**: Services are composed, not inherited
- **Async/Parallel**: Uses `asyncio.gather()` for performance
- **Factory Pattern**: AnalyzerOrchestrator uses factory for analyzer creation

---

## Project Structure

```text
secscanmcp/
├── main.py                      # FastAPI entry point (175 lines)
├── models.py                    # Pydantic data models (5,777 lines)
├── enhanced_scoring.py          # Dual scoring system (16,406 lines)
├── mcp_detector.py              # Legacy MCP detection (23,595 lines)
├── requirements.txt             # Python dependencies
├── Makefile                     # Development automation (169 targets)
├── Dockerfile                   # Container image definition
├── docker-compose.yml           # Multi-service orchestration
│
├── scanner/                     # Main orchestration layer
├── analyzers/                   # 20+ security analyzers
├── config/                      # Configuration files
├── models/                      # Additional data models
├── docs/                        # Comprehensive documentation
├── scripts/                     # Setup and installation scripts
├── tests/                       # Test suite (25+ test files)
├── rules/                       # Security detection rules (CodeQL, YARA)
├── examples/                    # Vulnerable MCP server samples
└── tmp/                         # Temporary files & challenge servers
```

---

## Core Components

### 1. Scanner Module (`scanner/`) - CLEAN ARCHITECTURE

```text
scanner/
├── main_scanner.py              # Orchestrator (85 lines)
├── services/
│   ├── repository_service.py    # Git operations (170 lines)
│   ├── analyzer_orchestrator.py # Analyzer management (166 lines)
│   ├── finding_service.py       # Finding processing (183 lines)
│   ├── finding_aggregator.py    # Aggregation logic (129 lines)
│   └── result_builder.py        # Result construction (123 lines)
└── utils/
    └── url_parser.py            # URL parsing (69 lines)
```

### 2. Analyzers Module (`analyzers/`) - 20+ SPECIALIZED ANALYZERS

#### Base Class

```text
analyzers/
├── base.py                      # BaseAnalyzer abstract class (99 lines)
```

#### MCP-Specific Analyzers

```text
analyzers/mcp/                   # MCP vulnerability detection (~1,200 lines)
├── main_analyzer.py             # MCPSpecificAnalyzer orchestrator (95 lines)
├── services/
│   ├── config_analyzer.py       # Config file analysis
│   ├── code_analyzer.py         # Python code analysis
│   ├── advanced_prompt_injection_service.py
│   ├── capability_abuse_service.py
│   ├── command_injection_service.py
│   ├── output_poisoning_service.py
│   ├── token_security_service.py
│   ├── rug_pull_service.py
│   └── cross_server_service.py
├── detectors/
│   ├── injection_detector.py
│   └── permission_detector.py
└── models/
    └── patterns.py              # Security patterns library
```

#### Dynamic Analysis

```text
analyzers/dynamic/               # Runtime behavior analysis (~1,000+ lines)
├── main_analyzer.py             # DynamicAnalyzer orchestrator
├── managers/
│   ├── docker_manager.py        # Container lifecycle
│   └── mcp_connection_manager.py # MCP protocol handling
├── services/
│   ├── security_testing_service.py
│   ├── traffic_analysis_service.py
│   ├── behavioral_analysis_service.py
│   └── performance_monitoring_service.py
└── utils/
    └── mcp_client.py            # Full MCP protocol client (637 lines)
```

#### ML Anomaly Detection

```text
analyzers/ml_anomaly/            # Machine learning detection (~700 lines)
├── main_analyzer.py             # MLAnomalyAnalyzer orchestrator
├── detectors/
│   └── isolation_forest_detector.py
├── services/
│   ├── ml_detector.py
│   ├── feature_extraction_service.py
│   ├── behavior_profiler.py
│   └── statistical_detector.py
└── models/
    ├── enums.py
    └── metrics.py
```

#### Traffic Analysis

```text
analyzers/traffic/               # Network traffic monitoring (~700 lines)
├── main_analyzer.py             # TrafficAnalyzer (513 lines)
├── managers/
│   └── network_monitor.py
├── services/
│   ├── data_leakage_detector.py
│   ├── exfiltration_detection_service.py
│   ├── network_anomaly_detector.py
│   ├── threat_detection_service.py
│   └── anomaly_detection_service.py
└── models/
    ├── enums.py
    └── events.py
```

#### Intelligent Context Analyzer (EXEMPLAR MODULE)

```text
analyzers/intelligent/           # Context-aware analysis (~800 lines)
├── main_analyzer.py             # IntelligentContextAnalyzer
├── components/
│   ├── base_analyzer.py
│   ├── semantic_analyzer.py
│   ├── behavioral_analyzer.py
│   ├── ecosystem_analyzer.py
│   └── anomaly_detector.py
├── services/
│   ├── risk_aggregator.py
│   └── learning_system.py
├── models/
│   ├── analysis_models.py
│   └── risk_models.py
└── utils/
    ├── config_manager.py
    ├── embeddings.py
    ├── logging_utils.py
    ├── ml_utils.py
    └── text_utils.py
```

#### Attack Payload Library

```text
analyzers/payloads/              # Security testing payloads (~700 lines)
├── main_payloads.py             # AdvancedPayloadGenerator (82 lines)
├── generators/
│   └── payload_generator.py     # Payload generation (155 lines)
└── categories/
    ├── prompt_injection.py
    ├── command_injection.py
    ├── code_injection.py
    ├── sql_injection.py
    ├── path_traversal.py
    ├── data_exfiltration.py
    ├── privilege_escalation.py
    ├── tool_manipulation.py
    └── xss.py
```

#### Security Tool Wrappers

```text
analyzers/security_tools/
├── codeql/                      # CodeQL semantic analysis
│   ├── main_analyzer.py
│   └── services/
│       ├── cli_service.py
│       ├── language_service.py
│       ├── pack_service.py
│       └── sarif_service.py
│
├── yara/                        # YARA pattern matching
│   ├── main_analyzer.py
│   └── services/
│       ├── scan_service.py
│       ├── rule_service.py
│       └── finding_service.py
│
└── clamav/                      # ClamAV malware detection
    ├── main_analyzer.py
    └── services/
        ├── connection_service.py
        ├── pattern_service.py
        └── scanning_service.py
```

#### Universal Analyzers

```text
analyzers/
├── trivy/                       # Vulnerability + secret + config scanning
│   ├── main_analyzer.py         # TrivyAnalyzer (49 lines)
│   └── services/
│       ├── scanning_service.py
│       └── result_parser.py
│
├── grype/                       # SBOM-based vulnerability scanning
│   ├── main_analyzer.py
│   └── services/
│       ├── scan_service.py
│       ├── sbom_service.py
│       └── finding_service.py
│
├── syft/                        # SBOM generation (SPDX/CycloneDX)
│   ├── main_analyzer.py         # SyftAnalyzer (73 lines)
│   └── services/
│       ├── sbom_service.py
│       ├── component_service.py
│       ├── license_service.py
│       └── metadata_service.py
│
├── bandit/                      # Python AST security linter
│   ├── main_analyzer.py
│   └── services/
│       ├── scan_service.py
│       └── finding_service.py
│
├── opengrep/                    # Semgrep-compatible pattern analysis
│   ├── main_analyzer.py
│   └── services/
│       ├── command_service.py
│       ├── parser_service.py
│       └── rule_service.py
│
└── trufflehog/                  # Secret/credential detection
    ├── main_analyzer.py         # TruffleHogAnalyzer (47 lines)
    └── services/
        ├── scan_service.py
        └── finding_service.py
```

---

## Configuration

```text
config/
├── default.yaml                 # Default configuration (2,340 lines)
├── scanner.yml                  # Scanner configuration (5,363 lines)
├── ignore_patterns.py           # Ignore patterns (9,927 lines)
└── clamav/                      # ClamAV-specific configuration
```

---

## Data Models (`models.py`)

Key Pydantic models:

```python
SeverityLevel (Enum)             # CRITICAL, HIGH, MEDIUM, LOW, INFO

VulnerabilityType (Enum)         # 40+ types including:
  # Code: command_injection, sql_injection, path_traversal, xss, xxe, ssrf
  # MCP: prompt_injection, tool_poisoning, schema_injection, output_poisoning
  # Crypto: weak_crypto
  # Dependencies: vulnerable_dependency, outdated_dependency, license_violation
  # Secrets: hardcoded_secret, api_key_exposure
  # Runtime: behavioral_anomaly, data_leakage, network_security, resource_abuse
  # Malware: malware, backdoor

Finding (BaseModel)              # Individual security finding
ScanRequest (BaseModel)          # API request model
ScanResult (BaseModel)           # API response model with scores
```

---

## Scoring System (`enhanced_scoring.py`)

Dual-scoring algorithm:

- **User Safety Score (0-100)**: Focuses on MCP-exploitable vulnerabilities
- **Developer Security Score (0-100)**: Comprehensive code security
- Letter grades (A-F) with color-coded badges
- Malware/backdoor detection triggers instant F rating

---

## Testing Suite

```text
tests/
├── conftest.py                  # Pytest fixtures
├── analyzers/
│   ├── bandit/
│   │   ├── unit/
│   │   └── integration/
│   ├── codeql/
│   │   ├── unit/
│   │   └── integration/
│   └── yara/
│       ├── unit/
│       └── integration/
├── test_base_analyzer.py
├── test_ignore_patterns.py
├── test_mcp_specific_vulnerabilities.py
├── test_enhanced_scoring.py
├── test_dynamic_integration.py
├── test_scanner_integration.py
└── test_attack_payloads.py
```

---

## Scripts

```text
scripts/
├── install-tools.sh             # Install all security tools (1,776 lines)
├── setup_clamav.sh              # ClamAV setup (5,955 lines)
├── setup_yara.sh                # YARA setup (5,608 lines)
├── setup_codeql.sh              # CodeQL setup (5,156 lines)
├── download_models.py           # Download ML models
└── clamav_healthcheck.sh        # ClamAV health monitoring
```

---

## Security Rules

```text
rules/
├── codeql/
│   ├── MCP_SECURITY_SUITE.md
│   └── mcp-security-queries/
│       ├── python/
│       └── qlpack.yml
└── yara/
    └── yara_rules/              # Malware detection patterns
```

---

## Documentation

```text
docs/
├── README.md                    # Documentation index
├── quick-reference.md           # Quick start
├── project-summary.md           # Project overview
├── guides/
│   ├── DEPLOYMENT.md
│   ├── TESTING.md
│   └── DOCKER_TEST_RESULTS.md
├── analysis/
│   ├── ANALYZER_ENHANCEMENTS.md
│   └── MCP_NATIVE_ENHANCEMENTS.md
└── tools/                       # 20+ tool documentation files
    ├── dynamic_analyzer_documentation.md
    ├── mcp_specific_analyzer_documentation.md
    ├── ml_anomaly_detector_documentation.md
    └── ...
```

---

## Examples & Test Samples

```text
examples/
├── scan_example.py              # Example scan code
├── vulnerable-mcp-server.py     # Vulnerable Python MCP server
├── vulnerable-mcp-server.js     # Vulnerable JavaScript server
└── vulnerability_samples/
    ├── malicious_mcp_samples/
    └── yara_patterns/

tmp/damn-vulnerable-MCP-server/  # Challenge-based learning
├── challenges/                  # 10 vulnerability challenges
│   ├── easy/
│   ├── medium/
│   └── hard/
├── solutions/
└── common/
```

---

## Development Guidelines

### Code Structure Rules

**EVERY** new component MUST follow these rules:

1. **File Structure**:

   ```text
   module_name/
   ├── __init__.py               # Public exports only
   ├── main_<module>.py          # Orchestrator (≤100 lines)
   ├── services/                 # Business logic (each ≤100 lines)
   ├── models/                   # Pydantic models
   └── utils/                    # Stateless helpers
   ```

2. **Class Rules**:

   ```python
   class ServiceName:  # ≤100 lines TOTAL
       def method_one(self):  # ≤10 lines
           pass
   ```

3. **Method Decomposition**:

   ```python
   # BAD: Long method doing multiple things
   def process_data(self, data):
       # 50 lines of code doing multiple things
       pass

   # GOOD: Decomposed methods
   def process_data(self, data):
       validated = self._validate(data)
       transformed = self._transform(validated)
       return self._format(transformed)

   def _validate(self, data):  # ≤10 lines
       # Just validation
       pass

   def _transform(self, data):  # ≤10 lines
       # Just transformation
       pass

   def _format(self, data):  # ≤10 lines
       # Just formatting
       pass
   ```

### Adding New Features

1. **New Analyzer**:
   - Create in `analyzers/` following `BaseAnalyzer`
   - Register in `AnalyzerOrchestrator`
   - Keep `analyze()` method ≤10 lines

2. **New Service**:
   - Create in appropriate `services/` directory
   - Single responsibility only
   - Inject dependencies via `__init__`

3. **New Utility**:
   - Create in `utils/`
   - Pure functions only (no state)

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

---

## Examples of Good Architecture

### GOOD: scanner/services/finding_service.py

```python
class FindingService:  # 155 lines total
    def deduplicate_findings(self, findings):  # 8 lines
        grouped = self._group_findings(findings)
        unique = self._select_best_findings(grouped)
        self._log_stats(len(findings), len(unique))
        return unique

    def _group_findings(self, findings):  # 7 lines
        # Single responsibility: grouping
        pass
```

### GOOD: analyzers/intelligent/main_analyzer.py

```python
class IntelligentAnalyzer:  # <100 lines
    def __init__(self):
        # Dependency injection
        self.semantic = SemanticAnalyzer()
        self.behavioral = BehavioralAnalyzer()
```

### AVOID: Monolithic files

- Files with 500+ lines
- Classes doing multiple things
- Methods with nested complexity
- Direct file I/O in business logic

---

## MCP Security Focus

Specialized for Model Context Protocol server security:

**Vulnerability Types Detected**:

- Prompt injection in tool descriptions
- Tool poisoning attacks (TPAs)
- Permission abuse and privilege escalation
- Schema injection vulnerabilities
- Data exfiltration patterns
- Command injection
- Output poisoning
- Cross-server attacks
- Token/secret security issues
- Rug pull patterns (crypto)

**Advanced Features**:

- Context-aware analysis to reduce false positives
- ML-based legitimacy assessment (Isolation Forest)
- Real MCP protocol communication testing
- Behavioral pattern recognition
- Traffic analysis for data leakage

---

## API Endpoints

```text
GET  /health    # Health check
POST /scan      # Main scanning endpoint
GET  /tools     # List available security tools
```

---

## Docker Services

```yaml
scanner:        # Main FastAPI application (port 8000)
clamav:         # ClamAV daemon (port 3310)
```

---

## Git Workflow

**IMPORTANT**: Always git commit changes after completing tasks.

**Never test against** `https://github.com/modelcontextprotocol/servers` (causes timeouts)

---

## Quality Standards

Every PR must meet:

1. No class exceeds 100 lines
2. No method exceeds 10 lines
3. Each class has single responsibility
4. Services are testable in isolation
5. Clear separation between layers

---

## Project Statistics

- **Security Analyzers**: 20+
- **Integrated Security Tools**: 11 (Trivy, Grype, Syft, Bandit, Semgrep, TruffleHog, CodeQL, YARA, ClamAV, MCP-specific, Dynamic)
