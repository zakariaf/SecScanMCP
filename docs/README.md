# MCP Security Scanner Documentation

This directory contains comprehensive documentation for the MCP Security Scanner. The documentation is organized into three main categories:

## 📁 Documentation Structure

### 🔧 [Tools Documentation](tools/)
Complete individual analyzer documentation following a consistent format:

**Static Analysis Tools:**
- **[Bandit Analyzer](tools/bandit_analyzer_documentation.md)** - Python security linting
- **[OpenGrep Analyzer](tools/opengrep_analyzer_documentation.md)** - Open-source pattern-based analysis
- **[CodeQL Integration](tools/codeql_documentation.md)** - Semantic code analysis
- **[YARA Integration](tools/yara_documentation.md)** - Advanced pattern matching for APTs

**Vulnerability & Dependency Analysis:**
- **[Trivy Analyzer](tools/trivy_analyzer_documentation.md)** - All-in-one security scanner
- **[Grype Analyzer](tools/grype_analyzer_documentation.md)** - Fast vulnerability scanner
- **[Syft Analyzer](tools/syft_analyzer_documentation.md)** - SBOM generation and analysis

**Secret & Malware Detection:**
- **[TruffleHog Analyzer](tools/trufflehog_analyzer_documentation.md)** - Advanced secret detection
- **[ClamAV Integration](tools/clamav_documentation.md)** - Military-grade malware detection

**MCP-Specific Analysis:**
- **[MCP-Specific Analyzer](tools/mcp_specific_analyzer_documentation.md)** - Specialized MCP security analysis
- **[Dynamic Analyzer](tools/dynamic_analyzer_documentation.md)** - Advanced MCP runtime security analysis

**ML-Powered Analysis:**
- **[Intelligent Context Analyzer](tools/intelligent_analyzer_documentation.md)** - ML-powered legitimacy assessment

### 📚 [User Guides](guides/)
Practical guides for deployment and testing:

- **[Testing Guide](guides/TESTING.md)** - How to test the scanner with examples
- **[Deployment Guide](guides/DEPLOYMENT.md)** - Production deployment instructions
- **[Docker Test Results](guides/DOCKER_TEST_RESULTS.md)** - Container testing validation

### 📊 [Analysis Documents](analysis/)
Research and analysis documentation:

- **[New Analyzers Analysis](analysis/NEW_ANALYZERS_ANALYSIS.md)** - Comprehensive analysis of all new components
- **[Analyzer Categorization](analysis/ANALYZER_CATEGORIZATION_ANALYSIS.md)** - Complete analyzer overview
- **[User Impact Analysis](analysis/USER_IMPACT_ANALYSIS.md)** - Which vulnerabilities actually affect users
- **[Security Rating Recommendation](analysis/SECURITY_RATING_RECOMMENDATION.md)** - Two-score system design
- **[Tool Optimization Analysis](analysis/TOOL_OPTIMIZATION_ANALYSIS.md)** - Duplication analysis and optimization
- **[Analyzer Enhancements](analysis/ANALYZER_ENHANCEMENTS.md)** - New capabilities overview
- **[MCP Native Enhancements](analysis/MCP_NATIVE_ENHANCEMENTS.md)** - MCP-specific improvements
- **[Expert Analysis](analysis/Expert_Analyze.md)** - Expert recommendations and improvements

### 📖 General Documentation
- **[Project Summary](project-summary.md)** - Complete implementation overview
- **[Quick Reference](quick-reference.md)** - Fast command reference
- **[Universal Scanner Guide](universal-scanner-guide.md)** - Universal scanner implementation

## 🚀 Quick Start

For immediate usage:
1. See **[Quick Reference](quick-reference.md)** for commands
2. Read **[Testing Guide](guides/TESTING.md)** for examples
3. Check **[Project Summary](project-summary.md)** for architecture

## 🔧 Tool-Specific Help

Each analyzer has detailed documentation in the `tools/` directory covering:
- **Overview** and capabilities
- **Architecture** and integration  
- **Setup** and configuration
- **Usage** examples and API
- **Performance** characteristics
- **Troubleshooting** common issues

## 📊 Understanding Results

For help interpreting scan results:
- **[User Impact Analysis](analysis/USER_IMPACT_ANALYSIS.md)** - Which findings matter for users
- **[Security Rating System](analysis/SECURITY_RATING_RECOMMENDATION.md)** - How scoring works
- **[Intelligent Analysis](tools/intelligent_analyzer_documentation.md)** - ML-powered legitimacy assessment

## 🏗️ Development & Analysis

For developers and security researchers:
- **[New Analyzers Analysis](analysis/NEW_ANALYZERS_ANALYSIS.md)** - Complete technical analysis
- **[Expert Recommendations](analysis/Expert_Analyze.md)** - Professional security advice
- **[Tool Optimization](analysis/TOOL_OPTIMIZATION_ANALYSIS.md)** - Performance improvements

## 🐛 Troubleshooting

Having issues? Check:
1. **Tool-specific documentation** in `tools/` for your analyzer
2. **[Docker Test Results](guides/DOCKER_TEST_RESULTS.md)** for known container issues
3. **[Testing Guide](guides/TESTING.md)** for validation steps

## 📝 Contributing

To contribute to documentation:
1. Follow the established format in `tools/` directory
2. Include all standard sections (Overview, Architecture, Setup, Usage, etc.)
3. Provide practical examples and troubleshooting guidance
4. Update this README when adding new documents