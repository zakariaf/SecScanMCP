# ML Anomaly Detector - Machine Learning Runtime Behavior Analysis

## Overview

The **ML Anomaly Detector** provides sophisticated machine learning-based anomaly detection for MCP runtime behavior analysis. It uses advanced statistical models and simplified isolation forest algorithms to identify unusual patterns, behavioral deviations, and potential security threats in real-time during MCP server execution.

- **Real-Time Behavioral Analysis** - Live monitoring and analysis of runtime metrics
- **Machine Learning Models** - Isolation Forest and statistical anomaly detection
- **Adaptive Baseline Learning** - Automatic establishment of normal behavior patterns
- **Multi-Dimensional Analysis** - CPU, memory, network, process, and temporal pattern analysis
- **Behavioral Profiling** - Create and compare behavioral fingerprints over time
- **Anomaly Classification** - Categorize and prioritize different types of anomalies

## Architecture

The ML Anomaly Detector combines multiple analysis approaches:

```
┌─────────────────────────────────────────────────┐
│              ML Anomaly Detector                │
├─────────────────────────────────────────────────┤
│                                                 │
│ ┌─────────────┐    ┌─────────────────────────┐ │
│ │   Feature   │    │    Machine Learning     │ │
│ │  Extraction │◄──►│    Anomaly Detection    │ │
│ │   Engine    │    │       Engine            │ │
│ └─────────────┘    └─────────────────────────┘ │
│        │                        │              │
│        ▼                        ▼              │
│ ┌──────────────────────────────────────────────┐│
│ │          Detection Models                    ││
│ ├──────────────────────────────────────────────┤│
│ │ • Isolation Forest • Statistical Analysis   ││
│ │ • Behavioral Profiler • Network Anomalies   ││
│ │ • Temporal Patterns • Performance Anomalies ││
│ └──────────────────────────────────────────────┘│
└─────────────────────────────────────────────────┘
```

## Machine Learning Models

### Isolation Forest Implementation

**Simplified Isolation Forest Algorithm**:
```python
class IsolationForestDetector:
    """Simplified Isolation Forest implementation for anomaly detection"""
    
    def __init__(self, n_trees: int = 100, max_depth: int = 10):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []
        self.trained = False
        self.feature_mins = None
        self.feature_maxs = None
```

**Training Process**:
```python
def fit(self, training_data: np.ndarray):
    """Train the isolation forest"""
    
    # Normalize training data
    self.feature_mins = np.min(training_data, axis=0)
    self.feature_maxs = np.max(training_data, axis=0)
    normalized_data = self._normalize_features(training_data)
    
    # Build isolation trees
    for _ in range(self.n_trees):
        # Sample subset of data
        sample_size = min(256, len(normalized_data))
        indices = np.random.choice(len(normalized_data), sample_size, replace=False)
        sample_data = normalized_data[indices]
        
        # Build isolation tree
        tree = self._build_tree(sample_data, 0)
        self.trees.append(tree)
```

**Anomaly Detection**:
```python
def predict_anomaly_score(self, data_point: np.ndarray) -> float:
    """Predict anomaly score for a data point"""
    
    # Normalize the data point
    normalized_point = self._normalize_features(data_point.reshape(1, -1))[0]
    
    # Calculate average path length across all trees
    path_lengths = []
    for tree in self.trees:
        path_length = self._calculate_path_length(normalized_point, tree, 0)
        path_lengths.append(path_length)
    
    avg_path_length = np.mean(path_lengths)
    
    # Convert to anomaly score (0 = normal, 1 = anomaly)
    expected_path_length = self._expected_path_length(256)
    anomaly_score = 2 ** (-avg_path_length / expected_path_length)
    
    return anomaly_score
```

### Statistical Anomaly Detection

**Multi-Method Statistical Analysis**:
```python
class StatisticalAnomalyDetector:
    """Statistical anomaly detection using z-scores and IQR"""
    
    def detect_anomalies(self, features: np.ndarray, feature_names: List[str]) -> List[Dict]:
        """Detect anomalies using statistical methods"""
        anomalies = []
        
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            stats = self.feature_stats[feature_name]
            
            # Z-score anomaly detection
            if stats['std'] > 0:
                z_score = abs(feature_val - stats['mean']) / stats['std']
                if z_score > 3:  # 3-sigma rule
                    anomalies.append({
                        'type': 'statistical_outlier',
                        'feature': feature_name,
                        'value': feature_val,
                        'z_score': z_score,
                        'severity': 'high' if z_score > 4 else 'medium'
                    })
            
            # IQR anomaly detection
            iqr = stats['q3'] - stats['q1']
            if iqr > 0:
                lower_bound = stats['q1'] - 1.5 * iqr
                upper_bound = stats['q3'] + 1.5 * iqr
                
                if feature_val < lower_bound or feature_val > upper_bound:
                    anomalies.append({
                        'type': 'iqr_outlier',
                        'feature': feature_name,
                        'value': feature_val,
                        'severity': 'high' if deviation > 2 * iqr else 'medium'
                    })
        
        return anomalies
```

## Feature Engineering

### Comprehensive Feature Extraction

**Basic Resource Metrics**:
```python
def extract_features(self, raw_metrics: Dict[str, Any]) -> np.ndarray:
    """Extract feature vector from raw metrics"""
    features = []
    
    # Basic resource metrics
    features.extend([
        raw_metrics.get('cpu_percent', 0),
        raw_metrics.get('memory_mb', 0),
        raw_metrics.get('network_connections', 0),
        raw_metrics.get('dns_queries', 0),
        raw_metrics.get('file_operations', 0),
        raw_metrics.get('process_spawns', 0),
        raw_metrics.get('tool_calls', 0),
        raw_metrics.get('error_count', 0),
        raw_metrics.get('response_time_ms', 0),
        raw_metrics.get('data_volume_bytes', 0),
    ])
```

**Derived Features**:
```python
def _calculate_derived_features(self, metrics: Dict[str, Any]) -> List[float]:
    """Calculate derived features from basic metrics"""
    derived = []
    
    # Resource utilization ratio
    cpu = metrics.get('cpu_percent', 0)
    memory = metrics.get('memory_mb', 0)
    derived.append(cpu * memory if memory > 0 else 0)  # Combined stress
    
    # Network activity intensity
    connections = metrics.get('network_connections', 0)
    dns_queries = metrics.get('dns_queries', 0)
    derived.append(connections + dns_queries * 2)  # Weighted activity
    
    # Process activity ratio
    spawns = metrics.get('process_spawns', 0)
    tools = metrics.get('tool_calls', 0)
    derived.append(spawns / max(tools, 1))  # Processes per tool call
    
    # Error rate
    errors = metrics.get('error_count', 0)
    total_operations = tools + metrics.get('file_operations', 0)
    derived.append(errors / max(total_operations, 1))
    
    # Data transfer efficiency
    data_volume = metrics.get('data_volume_bytes', 0)
    response_time = metrics.get('response_time_ms', 1)
    derived.append(data_volume / response_time)  # Bytes per ms
    
    return derived
```

**Temporal Features**:
```python
def _calculate_temporal_features(self, metrics: Dict[str, Any]) -> List[float]:
    """Calculate temporal pattern features"""
    temporal = []
    current_time = time.time()
    
    # Time of day features (cyclical encoding)
    hour = time.localtime(current_time).tm_hour
    temporal.extend([
        math.sin(2 * math.pi * hour / 24),  # Hour sin
        math.cos(2 * math.pi * hour / 24),  # Hour cos
    ])
    
    # Activity frequency
    if len(self.feature_history) > 1:
        recent_activity = sum(
            m.get('tool_calls', 0) for m in list(self.feature_history)[-10:]
        )
        temporal.append(recent_activity / 10)  # Average recent activity
    
    # Trend detection
    if len(self.feature_history) >= 5:
        recent_cpu = [m.get('cpu_percent', 0) for m in list(self.feature_history)[-5:]]
        cpu_trend = (recent_cpu[-1] - recent_cpu[0]) / 5
        temporal.append(cpu_trend)
    
    return temporal
```

**Statistical Features**:
```python
def _calculate_statistical_features(self) -> List[float]:
    """Calculate statistical features from recent history"""
    if len(self.feature_history) < 3:
        return [0] * 6
    
    recent_metrics = list(self.feature_history)[-10:]
    stats = []
    
    # CPU statistics
    cpu_values = [m.get('cpu_percent', 0) for m in recent_metrics]
    stats.extend([
        statistics.mean(cpu_values),
        statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0,
    ])
    
    # Memory statistics
    memory_values = [m.get('memory_mb', 0) for m in recent_metrics]
    stats.extend([
        statistics.mean(memory_values),
        statistics.stdev(memory_values) if len(memory_values) > 1 else 0,
    ])
    
    # Network activity statistics
    network_values = [m.get('network_connections', 0) for m in recent_metrics]
    stats.extend([
        statistics.mean(network_values),
        statistics.stdev(network_values) if len(network_values) > 1 else 0,
    ])
    
    return stats
```

## Behavioral Analysis

### ML-Based Anomaly Detection

**Main Detection Engine**:
```python
class MLAnomalyDetector:
    """Main ML-based anomaly detection system"""
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.isolation_forest = IsolationForestDetector()
        self.statistical_detector = StatisticalAnomalyDetector()
        self.training_data = []
        self.is_trained = False
        self.anomaly_threshold = 0.6  # Threshold for anomaly scores
        
        # Feature names for interpretability
        self.feature_names = [
            'cpu_percent', 'memory_mb', 'network_connections', 'dns_queries',
            'file_operations', 'process_spawns', 'tool_calls', 'error_count',
            'response_time_ms', 'data_volume_bytes',
            # Derived features
            'resource_stress', 'network_activity', 'process_ratio', 
            'error_rate', 'transfer_efficiency',
            # Temporal features
            'hour_sin', 'hour_cos', 'recent_activity', 'cpu_trend',
            # Statistical features
            'cpu_mean', 'cpu_std', 'memory_mean', 'memory_std', 
            'network_mean', 'network_std'
        ]
```

**Training Process**:
```python
def train(self, training_metrics: List[Dict[str, Any]]):
    """Train the anomaly detection models"""
    if len(training_metrics) < 10:
        logger.warning("Insufficient training data for ML anomaly detection")
        return
    
    # Extract features from training data
    training_features = []
    for metrics in training_metrics:
        self.feature_extractor.update_history(metrics)
        features = self.feature_extractor.extract_features(metrics)
        training_features.append(features)
    
    training_array = np.array(training_features)
    
    # Train isolation forest
    self.isolation_forest.fit(training_array)
    
    # Update statistical models
    for features in training_features:
        self.statistical_detector.update_statistics(features, self.feature_names)
    
    self.training_data = training_array
    self.is_trained = True
    logger.info("Anomaly detection models training completed")
```

**Anomaly Detection Process**:
```python
def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[AnomalyDetection]:
    """Detect anomalies in current metrics"""
    anomalies = []
    
    # Update feature history and extract features
    self.feature_extractor.update_history(current_metrics)
    features = self.feature_extractor.extract_features(current_metrics)
    
    # Update statistical models (continuous learning)
    self.statistical_detector.update_statistics(features, self.feature_names)
    
    if not self.is_trained:
        return anomalies
    
    # Isolation Forest detection
    anomaly_score = self.isolation_forest.predict_anomaly_score(features)
    
    if anomaly_score > self.anomaly_threshold:
        # Identify which features contribute most to the anomaly
        affected_features = self._identify_anomalous_features(features, current_metrics)
        severity = self._calculate_severity(anomaly_score, affected_features)
        
        anomaly = AnomalyDetection(
            anomaly_type=AnomalyType.BEHAVIORAL,
            severity=severity,
            confidence=anomaly_score,
            description=f"Behavioral anomaly detected (score: {anomaly_score:.3f})",
            metrics=current_metrics,
            timestamp=time.time(),
            baseline_deviation=anomaly_score - self.anomaly_threshold,
            affected_features=affected_features,
            recommendation=self._generate_recommendation(affected_features)
        )
        anomalies.append(anomaly)
    
    # Statistical anomaly detection
    statistical_anomalies = self.statistical_detector.detect_anomalies(features, self.feature_names)
    
    for stat_anomaly in statistical_anomalies:
        anomaly = AnomalyDetection(
            anomaly_type=AnomalyType.PERFORMANCE,
            severity=AnomalySeverity(stat_anomaly['severity']),
            confidence=0.8,  # High confidence for statistical methods
            description=f"Statistical anomaly in {stat_anomaly['feature']}: {stat_anomaly['value']:.2f}",
            metrics=current_metrics,
            timestamp=time.time(),
            baseline_deviation=stat_anomaly.get('z_score', stat_anomaly.get('deviation', 0)),
            affected_features=[stat_anomaly['feature']],
            recommendation=f"Investigate unusual {stat_anomaly['feature']} values"
        )
        anomalies.append(anomaly)
    
    return anomalies
```

### Behavioral Profiling

**Profile Creation and Management**:
```python
class BehaviorProfiler:
    """Creates behavioral profiles of MCP servers for comparison"""
    
    def create_profile(self, session_data: List[Dict[str, Any]], profile_name: str = "default"):
        """Create a behavioral profile from session data"""
        if not session_data:
            return
        
        # Calculate aggregate statistics
        profile = {
            'name': profile_name,
            'session_count': len(session_data),
            'avg_cpu': statistics.mean(d.get('cpu_percent', 0) for d in session_data),
            'avg_memory': statistics.mean(d.get('memory_mb', 0) for d in session_data),
            'avg_network': statistics.mean(d.get('network_connections', 0) for d in session_data),
            'total_tool_calls': sum(d.get('tool_calls', 0) for d in session_data),
            'total_errors': sum(d.get('error_count', 0) for d in session_data),
            'patterns': self._extract_behavior_patterns(session_data),
            'created_at': time.time()
        }
        
        self.profiles[profile_name] = profile
```

**Profile Comparison**:
```python
def compare_to_profile(self, current_data: List[Dict[str, Any]], profile_name: str = "default") -> Dict[str, Any]:
    """Compare current behavior to a stored profile"""
    if profile_name not in self.profiles or not current_data:
        return {}
    
    profile = self.profiles[profile_name]
    
    # Calculate current statistics
    current_stats = {
        'avg_cpu': statistics.mean(d.get('cpu_percent', 0) for d in current_data),
        'avg_memory': statistics.mean(d.get('memory_mb', 0) for d in current_data),
        'avg_network': statistics.mean(d.get('network_connections', 0) for d in current_data),
        'total_tool_calls': sum(d.get('tool_calls', 0) for d in current_data),
        'total_errors': sum(d.get('error_count', 0) for d in current_data),
    }
    
    # Calculate deviations
    deviations = {}
    for key in current_stats:
        profile_val = profile.get(key, 0)
        current_val = current_stats[key]
        
        if profile_val > 0:
            deviation = (current_val - profile_val) / profile_val
            deviations[key] = deviation
    
    return {
        'profile_name': profile_name,
        'current_stats': current_stats,
        'profile_stats': {k: profile.get(k, 0) for k in current_stats.keys()},
        'deviations': deviations,
        'similarity_score': self._calculate_similarity_score(deviations)
    }
```

## Usage Examples

### Basic Anomaly Detection

```python
from analyzers.ml_anomaly_detector import MLAnomalyDetector

# Initialize detector
detector = MLAnomalyDetector()

# Training data from normal operation
training_metrics = [
    {"cpu_percent": 5, "memory_mb": 100, "network_connections": 2, ...},
    {"cpu_percent": 7, "memory_mb": 105, "network_connections": 3, ...},
    # ... more training samples
]

# Train the models
detector.train(training_metrics)

# Detect anomalies in new data
current_metrics = {"cpu_percent": 95, "memory_mb": 500, "network_connections": 50, ...}
anomalies = detector.detect_anomalies(current_metrics)

for anomaly in anomalies:
    print(f"Anomaly detected: {anomaly.description}")
    print(f"Severity: {anomaly.severity.value}")
    print(f"Confidence: {anomaly.confidence:.2f}")
    print(f"Affected features: {anomaly.affected_features}")
    print(f"Recommendation: {anomaly.recommendation}")
```

### Behavioral Profiling

```python
from analyzers.ml_anomaly_detector import BehaviorProfiler

# Initialize profiler
profiler = BehaviorProfiler()

# Create baseline profile from normal operation
baseline_metrics = [
    {"cpu_percent": 5, "memory_mb": 100, "tool_calls": 10, ...},
    {"cpu_percent": 6, "memory_mb": 102, "tool_calls": 12, ...},
    # ... more baseline data
]
profiler.create_profile(baseline_metrics, "baseline")

# Compare current session to baseline
current_session = [
    {"cpu_percent": 25, "memory_mb": 200, "tool_calls": 50, ...},
    {"cpu_percent": 30, "memory_mb": 220, "tool_calls": 55, ...},
    # ... current session data
]

comparison = profiler.compare_to_profile(current_session, "baseline")
print(f"Similarity score: {comparison['similarity_score']:.2f}")
print(f"Deviations: {comparison['deviations']}")
```

### Integration with Dynamic Analysis

```python
from analyzers.dynamic_analyzer import DynamicAnalyzer
from analyzers.ml_anomaly_detector import MLAnomalyDetector

async def enhanced_dynamic_analysis():
    # Initialize analyzers
    dynamic_analyzer = DynamicAnalyzer()
    ml_detector = MLAnomalyDetector()
    
    # Start containerized analysis
    container = await dynamic_analyzer._create_sandbox("/path/to/mcp/server")
    
    # Collect baseline metrics
    baseline_metrics = []
    for _ in range(30):  # 30 samples for baseline
        metrics = await dynamic_analyzer._collect_runtime_metrics(container)
        if metrics:
            baseline_metrics.append(metrics)
        await asyncio.sleep(2)
    
    # Train ML models
    ml_detector.train(baseline_metrics)
    
    # Start continuous anomaly detection
    while container.status == 'running':
        current_metrics = await dynamic_analyzer._collect_runtime_metrics(container)
        
        if current_metrics:
            anomalies = ml_detector.detect_anomalies(current_metrics)
            
            for anomaly in anomalies:
                if anomaly.severity in [AnomalySeverity.HIGH, AnomalySeverity.CRITICAL]:
                    logger.warning(f"Critical anomaly detected: {anomaly.description}")
                    # Take action based on anomaly type
                    await handle_critical_anomaly(anomaly)
        
        await asyncio.sleep(5)  # Check every 5 seconds
```

## Output Examples

### Behavioral Anomaly Detection

```json
{
  "anomaly_type": "behavioral",
  "severity": "high",
  "confidence": 0.85,
  "description": "Behavioral anomaly detected (score: 0.85)",
  "timestamp": 1641234567.89,
  "baseline_deviation": 0.25,
  "affected_features": ["network_connections", "process_spawns", "cpu_percent"],
  "recommendation": "Monitor network activity for unauthorized connections; Check for suspicious process creation; Monitor CPU usage patterns and check for resource-intensive operations",
  "metrics": {
    "cpu_percent": 75.2,
    "memory_mb": 512.1,
    "network_connections": 45,
    "dns_queries": 15,
    "file_operations": 8,
    "process_spawns": 12,
    "tool_calls": 25,
    "error_count": 2,
    "response_time_ms": 150.5,
    "data_volume_bytes": 102400
  },
  "ml_analysis": {
    "isolation_forest_score": 0.85,
    "anomalous_features": ["network_connections", "process_spawns"],
    "model_trained": true
  }
}
```

### Statistical Anomaly Detection

```json
{
  "anomaly_type": "performance",
  "severity": "medium",
  "confidence": 0.8,
  "description": "Statistical anomaly in memory_mb: 1024.50",
  "timestamp": 1641234567.89,
  "baseline_deviation": 3.2,
  "affected_features": ["memory_mb"],
  "recommendation": "Investigate memory leaks or excessive memory allocation",
  "metrics": {
    "memory_mb": 1024.5,
    "cpu_percent": 15.2
  },
  "statistical_analysis": {
    "method": "z_score",
    "z_score": 3.2,
    "baseline_mean": 150.0,
    "baseline_std": 25.0,
    "threshold_exceeded": "3_sigma"
  }
}
```

### Behavioral Profile Comparison

```json
{
  "profile_name": "baseline",
  "current_stats": {
    "avg_cpu": 45.2,
    "avg_memory": 256.8,
    "avg_network": 12.5,
    "total_tool_calls": 150,
    "total_errors": 5
  },
  "profile_stats": {
    "avg_cpu": 8.5,
    "avg_memory": 120.2,
    "avg_network": 3.2,
    "total_tool_calls": 45,
    "total_errors": 1
  },
  "deviations": {
    "avg_cpu": 4.32,
    "avg_memory": 1.14,
    "avg_network": 2.91,
    "total_tool_calls": 2.33,
    "total_errors": 4.0
  },
  "similarity_score": 0.15,
  "interpretation": "Significant behavioral deviation detected",
  "risk_level": "high"
}
```

### Model Performance Metrics

```json
{
  "model_status": {
    "is_trained": true,
    "training_samples": 150,
    "feature_count": 25,
    "anomaly_threshold": 0.6,
    "isolation_forest_trees": 100,
    "statistical_features_tracked": 15
  },
  "detection_performance": {
    "total_samples_analyzed": 1250,
    "anomalies_detected": 23,
    "anomaly_rate": 0.018,
    "avg_confidence": 0.74,
    "false_positive_rate": 0.05
  },
  "feature_importance": {
    "most_anomalous_features": [
      "network_connections",
      "process_spawns", 
      "error_count",
      "cpu_percent"
    ],
    "stable_features": [
      "hour_sin",
      "hour_cos",
      "transfer_efficiency"
    ]
  }
}
```

## Configuration

### ML Model Configuration

```python
ML_DETECTOR_CONFIG = {
    'isolation_forest': {
        'n_trees': 100,                    # Number of isolation trees
        'max_depth': 10,                   # Maximum tree depth
        'sample_size': 256,                # Samples per tree
        'anomaly_threshold': 0.6,          # Anomaly score threshold
        'contamination': 0.1               # Expected anomaly rate
    },
    
    'statistical_detection': {
        'window_size': 50,                 # Historical samples to maintain
        'z_score_threshold': 3.0,          # Standard deviations for outliers
        'iqr_multiplier': 1.5,            # IQR range multiplier
        'confidence_threshold': 0.7        # Minimum confidence for alerts
    },
    
    'feature_extraction': {
        'history_length': 1000,            # Feature history buffer size
        'temporal_features': True,         # Enable time-based features
        'derived_features': True,          # Enable calculated features
        'statistical_features': True,      # Enable historical statistics
        'normalization': 'min_max'        # Feature normalization method
    }
}
```

### Behavioral Analysis Configuration

```python
BEHAVIORAL_CONFIG = {
    'profiling': {
        'min_samples_for_profile': 20,     # Minimum samples to create profile
        'profile_retention_days': 30,      # How long to keep profiles
        'similarity_threshold': 0.8,       # Minimum similarity for "normal"
        'deviation_threshold': 2.0         # Max deviation for alerts
    },
    
    'anomaly_types': {
        'behavioral': {
            'enabled': True,
            'severity_mapping': {
                'low': [0.6, 0.7],
                'medium': [0.7, 0.8],
                'high': [0.8, 0.9],
                'critical': [0.9, 1.0]
            }
        },
        'performance': {
            'enabled': True,
            'cpu_threshold': 80,            # CPU anomaly threshold
            'memory_threshold': 500,        # Memory anomaly threshold (MB)
            'network_threshold': 100        # Network connections threshold
        }
    },
    
    'continuous_learning': {
        'enabled': True,                    # Update models with new data
        'update_frequency': 100,            # Update every N samples
        'adaptation_rate': 0.1,            # Learning rate for updates
        'drift_detection': True            # Detect concept drift
    }
}
```

## Performance Considerations

### Computational Efficiency

- **Training Time**: O(n * log n) for isolation forest training
- **Prediction Time**: O(log n) per sample for real-time detection
- **Memory Usage**: ~50-100MB for models and feature history
- **Scalability**: Supports thousands of samples with sub-second response

### Optimization Features

- **Incremental Learning**: Models adapt to new data without full retraining
- **Feature Caching**: Expensive feature calculations cached for reuse
- **Batch Processing**: Multiple samples processed together for efficiency
- **Model Persistence**: Save and load trained models to avoid retraining

## Best Practices

### Training Data Quality

1. **Sufficient Samples**: Minimum 50-100 samples for reliable training
2. **Representative Data**: Include various operational scenarios
3. **Clean Data**: Remove outliers from training data
4. **Balanced Coverage**: Include both normal and edge cases

### Anomaly Threshold Tuning

```python
# Recommended threshold tuning process
def tune_anomaly_threshold(historical_data, validation_data):
    detector = MLAnomalyDetector()
    detector.train(historical_data)
    
    thresholds = np.arange(0.3, 0.9, 0.05)
    best_threshold = 0.6
    best_f1_score = 0
    
    for threshold in thresholds:
        detector.anomaly_threshold = threshold
        predictions = []
        
        for sample in validation_data:
            anomalies = detector.detect_anomalies(sample['metrics'])
            predictions.append(len(anomalies) > 0)
        
        # Calculate F1 score against known labels
        f1 = calculate_f1_score(validation_data['labels'], predictions)
        
        if f1 > best_f1_score:
            best_f1_score = f1
            best_threshold = threshold
    
    return best_threshold, best_f1_score
```

### Integration Guidelines

```python
# Recommended integration with dynamic analysis
async def integrate_ml_anomaly_detection():
    # Phase 1: Baseline establishment
    baseline_period = 60  # seconds
    baseline_metrics = await collect_baseline_metrics(baseline_period)
    
    # Phase 2: Model training
    detector = MLAnomalyDetector()
    detector.train(baseline_metrics)
    
    # Phase 3: Real-time monitoring
    while analysis_active:
        current_metrics = await collect_current_metrics()
        anomalies = detector.detect_anomalies(current_metrics)
        
        # Phase 4: Anomaly handling
        for anomaly in anomalies:
            await handle_anomaly(anomaly)
            
        await asyncio.sleep(monitoring_interval)
```

## Troubleshooting

### Common Issues

**Q: High false positive rate in anomaly detection**
A: Increase training data size and adjust anomaly threshold

**Q: Model not detecting obvious anomalies**  
A: Check feature extraction and ensure training data represents normal behavior

**Q: Poor performance with high-dimensional data**
A: Enable feature selection and dimensionality reduction

**Q: Memory usage growing over time**
A: Configure feature history limits and enable periodic cleanup

### Debug Mode

```python
# Enable comprehensive debugging
detector = MLAnomalyDetector()
detector.debug_mode = True
detector.log_feature_importance = True

# Analyze feature contributions
feature_analysis = detector.analyze_feature_importance(sample_metrics)
print(f"Most important features: {feature_analysis['top_features']}")
print(f"Feature correlations: {feature_analysis['correlations']}")
```

### Performance Monitoring

```python
# Monitor detector performance
performance_stats = detector.get_performance_stats()
print(f"Training time: {performance_stats['training_time']}s")
print(f"Average prediction time: {performance_stats['avg_prediction_time']}ms")
print(f"Model accuracy: {performance_stats['accuracy']:.2f}")
print(f"False positive rate: {performance_stats['false_positive_rate']:.3f}")
```

## Version Information

```bash
# Check ML anomaly detector capabilities
python -c "
from analyzers.ml_anomaly_detector import MLAnomalyDetector
detector = MLAnomalyDetector()
print('Feature count:', len(detector.feature_names))
print('Supported models:', ['isolation_forest', 'statistical_analysis'])
print('Real-time detection:', detector.supports_realtime)
print('Behavioral profiling:', hasattr(detector, 'behavior_profiler'))
"
```