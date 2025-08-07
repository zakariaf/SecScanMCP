# Intelligent Context Analyzer - ML-Powered Legitimacy Assessment

## Overview

The **Intelligent Context Analyzer** provides advanced machine learning-based security analysis that goes beyond simple pattern matching to assess the legitimacy of code behavior through contextual understanding:

- **Semantic Intent Analysis** using sentence transformers (all-MiniLM-L6-v2)
- **Behavioral Pattern Recognition** with heuristic scoring systems
- **Ecosystem Intelligence** comparing against legitimate project patterns
- **Anomaly Detection** using statistical methods and feature extraction
- **Production-Ready Architecture** with frozen models and async processing

## Architecture

The Intelligent Analyzer follows **Sandi Metz principles** with modular, focused components:

```
┌─────────────────────────────────────────────────────────────┐
│                IntelligentContextAnalyzer                   │
│                   (Main Orchestrator)                       │
└─────────────────┬───────────────────────────────────────────┘
                  │
    ┌─────────────┼─────────────┐
    │             │             │
    ▼             ▼             ▼
┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────┐
│Semantic │  │Behavioral│  │Ecosystem│  │   Anomaly   │
│Analyzer │  │Analyzer  │  │Analyzer │  │  Detector   │
└─────────┘  └─────────┘  └─────────┘  └─────────────┘
    │             │             │             │
    ▼             ▼             ▼             ▼
┌─────────────────────────────────────────────────────────────┐
│                    Risk Aggregator                          │
│            (Weighted Multi-Dimensional Scoring)             │
└─────────────────────────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                  Learning System                            │
│              (Async Feedback Processing)                    │
└─────────────────────────────────────────────────────────────┘
```

## Key Components

### 1. Semantic Intent Analyzer
- **Purpose**: Analyze alignment between declared intent and actual behavior
- **Technology**: Sentence transformers with 384-dimensional embeddings
- **Input**: Code documentation, comments, function names, and actual operations
- **Output**: Intent alignment score (0.0-1.0)

### 2. Behavioral Pattern Analyzer  
- **Purpose**: Recognize legitimate vs suspicious code patterns
- **Technology**: Heuristic scoring with pattern recognition
- **Analysis**: File operations, network calls, system commands, permission usage
- **Output**: Behavioral legitimacy score (0.0-1.0)

### 3. Ecosystem Intelligence Analyzer
- **Purpose**: Compare behavior against known legitimate projects
- **Technology**: Pattern comparison and statistical analysis
- **Database**: Known patterns from legitimate MCP servers and similar projects
- **Output**: Ecosystem similarity score (0.0-1.0)

### 4. Anomaly Detector
- **Purpose**: Identify statistically unusual patterns
- **Technology**: Statistical analysis (Z-scores, IQR methods)
- **Features**: Code complexity, operation frequency, resource usage patterns
- **Output**: Anomaly score (0.0-1.0, where higher = more normal)

## Setup and Configuration

### Container Deployment (Recommended)

The Intelligent Analyzer is pre-configured in the main container with frozen models:

```bash
# Models are pre-cached during container build
# No additional setup required - ready in 2-3 seconds
make up
```

### External Configuration

Configure via environment variables or `config.yaml`:

```yaml
# analyzers/intelligent/config.yaml
intelligent_analyzer:
  model_path: "/app/models/embeddings"
  db_path: "/app/data/learning/security_learning.db"
  confidence_threshold: 0.55
  risk_weights:
    intent: 0.3
    behavior: 0.25
    ecosystem: 0.25
    anomaly: 0.2
  
  # Model settings
  model_name: "all-MiniLM-L6-v2"
  max_sequence_length: 512
  embedding_dimension: 384
```

### Environment Variables

```bash
# Core paths
INTELLIGENT_ANALYZER_MODEL_PATH="/app/models/embeddings"
INTELLIGENT_ANALYZER_DB_PATH="/app/data/learning/security_learning.db"

# Performance tuning
TRANSFORMERS_CACHE="/app/models/embeddings"
SENTENCE_TRANSFORMERS_HOME="/app/models/embeddings"

# Logging
LOG_LEVEL="INFO"
```

## Usage

### Programmatic Usage

```python
from analyzers.intelligent.main_analyzer import IntelligentContextAnalyzer
from analyzers.intelligent.models.analysis_models import CodeContext

# Initialize analyzer
analyzer = IntelligentContextAnalyzer()

# Create analysis context
context = CodeContext(
    project_name="memory-server",
    file_operations=["fs.writeFile", "fs.readFile"],
    system_operations=[],
    network_operations=[],
    documented_purpose="MCP memory server for persistent storage"
)

# Run analysis
analysis = await analyzer.analyze_legitimacy(context)

print(f"Legitimate: {analysis.is_legitimate}")
print(f"Confidence: {analysis.confidence_score:.2f}")
print(f"Risk Level: {analysis.risk_level}")
print(f"Explanation: {analysis.explanation}")
```

### API Integration

The analyzer is automatically integrated into the main scanning API:

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/modelcontextprotocol/servers/tree/main/src/memory"
  }'
```

Response includes intelligent analysis results:

```json
{
  "intelligent_analysis": {
    "is_legitimate": true,
    "confidence_score": 0.95,
    "risk_level": "low",
    "explanation": "Analysis indicates legitimate functionality (confidence: 95.0%). Strong alignment between declared intent and actual behavior.",
    "intent_alignment_score": 0.89,
    "behavioral_anomaly_score": 0.12,
    "ecosystem_similarity_score": 0.91
  }
}
```

## Performance

### Cold Start Performance
- **Container**: 2-3 seconds (pre-cached models)
- **Local**: 10-15 seconds (model download required)

### Analysis Performance
- **Simple projects**: 200-500ms
- **Complex projects**: 1-3 seconds
- **Memory usage**: ~512MB (transformer models)

### Scalability Features
- **Async Processing**: Non-blocking database operations with aiosqlite
- **Structured Logging**: Full observability with scan ID tracking
- **Resource Management**: Automatic model caching and cleanup

## Monitoring and Observability

### Structured Logging

The analyzer provides comprehensive structured logging:

```json
{
  "timestamp": "2025-08-07T14:32:11.810007",
  "level": "info",
  "message": "Analysis completed successfully",
  "scan_id": "memory-abc123def",
  "component": "intelligent_analyzer", 
  "is_legitimate": true,
  "confidence_score": 0.95,
  "risk_level": "low",
  "intent_score": 0.89,
  "behavior_score": 0.93,
  "ecosystem_score": 0.91,
  "anomaly_score": 0.88
}
```

### Performance Metrics

Component-level timing is automatically tracked:

```json
{
  "component": "semantic_analyzer",
  "score": 0.89,
  "duration_ms": 245
}
```

## Troubleshooting

### Common Issues

**Q: Analysis returns low confidence scores**
A: Check that the project has sufficient documentation and clear intent declarations

**Q: High memory usage**  
A: The analyzer loads transformer models (~400MB). This is normal for production ML systems

**Q: Slow first analysis**
A: First analysis loads models. Subsequent analyses are much faster due to caching

### Debug Mode

Enable detailed debugging:

```bash
# Set debug logging
LOG_LEVEL=DEBUG

# Check component scores individually
python -c "
from analyzers.intelligent.main_analyzer import IntelligentContextAnalyzer
analyzer = IntelligentContextAnalyzer()
# Analysis will show detailed component breakdowns
"
```

### Model Verification

Verify models are properly loaded:

```bash
# Check model files exist
ls -la /app/models/embeddings/

# Test model loading
python -c "
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('all-MiniLM-L6-v2')
print('Model loaded successfully')
"
```

## Integration with Other Analyzers

The Intelligent Analyzer complements static analysis tools:

1. **Static analyzers** (Bandit, CodeQL) find potential vulnerabilities
2. **Intelligent analyzer** assesses whether patterns represent legitimate functionality
3. **Enhanced scoring** uses intelligent analysis to reduce false positives

Example: A file write operation might trigger static analysis warnings, but the intelligent analyzer can determine it's legitimate configuration storage for an MCP server.

## Future Enhancements

- **Fine-tuned models** for MCP-specific patterns
- **Federated learning** across scanned repositories  
- **Real-time model updates** based on user feedback
- **Multi-language support** beyond current JavaScript/Python focus