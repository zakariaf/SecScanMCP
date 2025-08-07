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

**Main Flow**: `scanner.py` → **Analyzers** → **Scoring** → **Results**

### Core Components

1. **SecurityScanner** (`scanner.py`): Main orchestrator
2. **Modular Analyzers** (`analyzers/`):
   - **Static Analysis**: Bandit, CodeQL, YARA
   - **Universal**: Trivy, Grype  
   - **MCP-Specific**: Custom MCP vulnerability detection
   - **Intelligent Context**: ML-based analysis with reduced false positives
   - **Dynamic Analysis**: Runtime behavior analysis
   - **Secret Detection**: TruffleHog
   - **Malware**: ClamAV

3. **Intelligent Analysis** (`analyzers/intelligent/`): Modular ML-powered system:
   - **Semantic Analysis**: Intent vs behavior alignment
   - **Behavioral Patterns**: Code pattern recognition
   - **Ecosystem Intelligence**: Peer project comparison  
   - **Anomaly Detection**: Statistical and ML anomaly detection
   - **Risk Aggregation**: Probabilistic risk assessment
   - **Learning System**: Continuous improvement from feedback

### Key Architecture Principles

- **Sandi Metz Best Practices**: Small classes (≤100 lines), short methods (≤10 lines)
- **Single Responsibility**: Each component has one clear purpose
- **Modular Design**: Components can be enabled/disabled independently
- **Async/Parallel**: Uses `asyncio.gather()` for performance
- **Docker Integration**: Containerized security tools for consistency

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

- `scanner.py`: Main orchestration
- `analyzers/mcp_analyzer.py`: MCP-specific detection  
- `analyzers/intelligent/`: Modular ML analysis system
- `models.py`: Pydantic data structures
- `main.py`: FastAPI web service

## Development Guidelines

### Adding Analyzers
1. Inherit from `BaseAnalyzer` 
2. Implement `async def analyze(self, repo_path, project_info)`
3. Register in `analyzers/__init__.py` and `scanner.py`
4. Follow Sandi Metz principles (small, focused classes)

### Working with Intelligent Analysis
- Keep classes ≤100 lines, methods ≤10 lines
- Use composition over inheritance
- Single responsibility per class
- Clear separation of concerns

### Git Workflow
⚠️ **IMPORTANT**: Always git commit changes after completing tasks or implementing features. This ensures work is preserved and progress is tracked.

**Never test against** `https://github.com/modelcontextprotocol/servers` (causes timeouts)