# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development & Testing
```bash
# Development workflow
make restart              # Stop, build, and start all services
make up                  # Start services
make down                # Stop services
make logs                # Show scanner logs
make health              # Check scanner health

# Testing
make test                # Run comprehensive tests
make test-examples       # Test with local vulnerable examples
make test-python         # Quick test with Python example
make test-js             # Quick test with JavaScript example

# Scanning
make scan URL=<repo>     # Scan a repository
make scan-vulnerable     # Scan local vulnerable examples

# Setup and cleanup
make clean               # Clean up containers and volumes
make setup-all           # Install all security tools
```

### Direct Python Usage
```bash
# Install dependencies
pip install -r requirements.txt

# Run scanner directly
python main.py

# Run specific analyzer tests
python test_scanner.py
python test_scanner.py --real-repos

# Dynamic analysis only
python scanner.py --dynamic-analysis /path/to/repo
```

### Docker Commands
```bash
# Build and run with Docker Compose
docker-compose up -d
docker-compose logs -f scanner

# Build individual image
docker build -t mcp-scanner .

# Run with Docker (requires Docker-in-Docker for dynamic analysis)
docker run -d -p 8000:8000 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  mcp-scanner
```

## Architecture

### Core Components

**Main Scanner Flow**: `scanner.py` → **Analyzers** → **Scoring** → **Results**

1. **SecurityScanner** (`scanner.py`): Main orchestrator that:
   - Clones repositories
   - Detects project type and MCP configuration
   - Runs analyzers in parallel
   - Calculates security scores
   - Builds comprehensive results

2. **Analyzer Architecture** (`analyzers/`): Modular analyzer system:
   - **BaseAnalyzer**: Abstract base class for all analyzers
   - **Static Analysis**: Bandit, OpenGrep, CodeQL, YARA
   - **Universal Scanners**: Trivy, Grype, Syft
   - **Secret Detection**: TruffleHog
   - **MCP-Specific**: Custom MCP vulnerability detection
   - **Dynamic Analysis**: Advanced runtime behavior analysis with ML
   - **Malware Detection**: ClamAV for enterprise-grade malware scanning

3. **Enhanced Dynamic Analyzer** (`analyzers/dynamic_analyzer.py`): Enterprise-grade dynamic analysis with:
   - **Full MCP Protocol Support**: JSON-RPC 2.0, STDIO, SSE, WebSocket transports
   - **Advanced Attack Payloads**: 1000+ sophisticated payloads across 9 categories
   - **ML-based Anomaly Detection**: Isolation Forest and statistical analysis
   - **Network Traffic Analysis**: Real-time monitoring and data exfiltration detection
   - **Behavioral Profiling**: Runtime behavior pattern analysis

### Key Architecture Patterns

**Parallel Analysis**: Most analyzers run concurrently using `asyncio.gather()` for performance.

**Modular Design**: Each analyzer is self-contained and can be enabled/disabled independently.

**Docker-in-Docker**: Dynamic analysis uses nested containers for secure sandboxing.

**Scoring System**: OWASP-style weighted scoring with confidence factors and severity multipliers.

### Critical Files

- `scanner.py`: Main scanning orchestration
- `analyzers/dynamic_analyzer.py`: Advanced dynamic analysis (2200+ lines, enterprise-grade)
- `analyzers/mcp_analyzer.py`: MCP-specific vulnerability detection
- `models.py`: Pydantic models for all data structures
- `scoring.py`: Security scoring algorithm
- `main.py`: FastAPI web service

### Advanced Dynamic Analysis Components

The enhanced Dynamic Analyzer includes several sophisticated components:

- `analyzers/mcp_client.py`: Full MCP protocol implementation
- `analyzers/attack_payloads.py`: Advanced payload generation (1000+ payloads)
- `analyzers/ml_anomaly_detector.py`: Machine learning anomaly detection
- `analyzers/traffic_analyzer.py`: Network traffic and data exfiltration analysis

### Testing and Examples
- `tests/`: Comprehensive test suite for all components
- `examples/`: Local vulnerable examples for testing
- `TESTING.md`: Guidelines for writing and running tests
- `test_scanner.py`: Main test runner for the scanner

*Never test against https://github.com/modelcontextprotocol/servers. it includes many many repos and we get timeouts.*

## MCP-Specific Security Features

This scanner specializes in Model Context Protocol (MCP) server security:

**MCP Vulnerability Types**:
- Prompt injection in tool descriptions and prompts
- Tool manipulation and poisoning attacks
- Schema injection vulnerabilities
- Permission abuse and privilege escalation
- Output poisoning risks

**Dynamic MCP Analysis**:
- Runtime MCP server instantiation in sandboxed containers
- Real MCP protocol communication testing
- Behavioral analysis of tool execution
- Network traffic monitoring for data exfiltration

## Integration Notes

**Docker Socket Access**: Required for dynamic analysis. The scanner runs containers within containers for isolation.

**Security Tools Integration**: Uses external tools (Trivy, CodeQL, YARA, ClamAV) via subprocess calls and Docker containers.

**Async Architecture**: Heavy use of `asyncio` for parallel processing and I/O operations.

**Error Handling**: Robust error handling with partial results - if one analyzer fails, others continue.

## Development Guidelines

### Adding New Analyzers

1. Create analyzer class inheriting from `BaseAnalyzer` in `analyzers/`
2. Implement `async def analyze(self, repo_path, project_info)` method
3. Register in `analyzers/__init__.py`
4. Add to `scanner.py` analyzer dictionary
5. Add corresponding tests

### Working with Dynamic Analysis

The Dynamic Analyzer requires Docker access and uses advanced features:
- Docker-in-Docker for container sandboxing
- Advanced MCP protocol client implementation
- ML-based behavioral analysis
- Real-time network traffic monitoring

When modifying dynamic analysis, ensure:
- Container cleanup in finally blocks
- Proper error handling for Docker operations
- Resource limits to prevent DoS
- Traffic analyzer cleanup

### Security Tool Configuration

Security tools are configured via:
- Environment variables in `docker-compose.yml`
- Rule files in `rules/` directory (YARA, CodeQL)
- Tool-specific configuration in analyzer classes

The system supports both containerized and local tool execution, with containerized being preferred for consistency.