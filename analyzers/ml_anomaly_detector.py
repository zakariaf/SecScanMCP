"""
ML-Based Anomaly Detection for MCP Runtime Behavior
Uses machine learning to detect unusual patterns and behaviors
"""

import numpy as np
import json
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import deque, defaultdict
import hashlib
import statistics
import math

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    BEHAVIORAL = "behavioral"
    PERFORMANCE = "performance"
    NETWORK = "network"
    PROCESS = "process"
    DATA_FLOW = "data_flow"
    TEMPORAL = "temporal"


class AnomalySeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehaviorMetrics:
    """Runtime behavior metrics for analysis"""
    timestamp: float
    cpu_percent: float
    memory_mb: float
    network_connections: int
    dns_queries: int
    file_operations: int
    process_spawns: int
    tool_calls: int
    error_count: int
    response_time_ms: float
    data_volume_bytes: int
    unique_destinations: int


@dataclass
class AnomalyDetection:
    """Represents a detected anomaly"""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float
    description: str
    metrics: Dict[str, Any]
    timestamp: float
    baseline_deviation: float
    affected_features: List[str]
    recommendation: str


class FeatureExtractor:
    """
    Extracts meaningful features from raw runtime data
    """
    
    def __init__(self):
        self.feature_history = deque(maxlen=1000)
        self.temporal_patterns = {}
    
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
        
        # Derived features
        features.extend(self._calculate_derived_features(raw_metrics))
        
        # Temporal features
        features.extend(self._calculate_temporal_features(raw_metrics))
        
        # Statistical features from recent history
        features.extend(self._calculate_statistical_features())
        
        return np.array(features, dtype=np.float32)
    
    def _calculate_derived_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Calculate derived features from basic metrics"""
        derived = []
        
        # Resource utilization ratio
        cpu = metrics.get('cpu_percent', 0)
        memory = metrics.get('memory_mb', 0)
        derived.append(cpu * memory if memory > 0 else 0)  # Combined resource stress
        
        # Network activity intensity
        connections = metrics.get('network_connections', 0)
        dns_queries = metrics.get('dns_queries', 0)
        derived.append(connections + dns_queries * 2)  # Weighted network activity
        
        # Process activity ratio
        spawns = metrics.get('process_spawns', 0)
        tools = metrics.get('tool_calls', 0)
        derived.append(spawns / max(tools, 1))  # Processes per tool call
        
        # Error rate
        errors = metrics.get('error_count', 0)
        total_operations = tools + metrics.get('file_operations', 0)
        derived.append(errors / max(total_operations, 1))  # Error rate
        
        # Data transfer efficiency
        data_volume = metrics.get('data_volume_bytes', 0)
        response_time = metrics.get('response_time_ms', 1)
        derived.append(data_volume / response_time)  # Bytes per ms
        
        return derived
    
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
        else:
            temporal.append(0)
        
        # Trend detection
        if len(self.feature_history) >= 5:
            recent_cpu = [m.get('cpu_percent', 0) for m in list(self.feature_history)[-5:]]
            cpu_trend = (recent_cpu[-1] - recent_cpu[0]) / 5  # CPU trend
            temporal.append(cpu_trend)
        else:
            temporal.append(0)
        
        return temporal
    
    def _calculate_statistical_features(self) -> List[float]:
        """Calculate statistical features from recent history"""
        stats = []
        
        if len(self.feature_history) < 3:
            return [0] * 6  # Return zeros if insufficient history
        
        recent_metrics = list(self.feature_history)[-10:]
        
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
    
    def update_history(self, metrics: Dict[str, Any]):
        """Update feature history"""
        self.feature_history.append(metrics.copy())


class IsolationForestDetector:
    """
    Simplified Isolation Forest implementation for anomaly detection
    """
    
    def __init__(self, n_trees: int = 100, max_depth: int = 10):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []
        self.trained = False
        self.feature_mins = None
        self.feature_maxs = None
    
    def fit(self, training_data: np.ndarray):
        """Train the isolation forest"""
        if len(training_data) == 0:
            return
        
        self.feature_mins = np.min(training_data, axis=0)
        self.feature_maxs = np.max(training_data, axis=0)
        
        # Normalize training data
        normalized_data = self._normalize_features(training_data)
        
        # Build isolation trees
        self.trees = []
        n_samples = len(normalized_data)
        
        for _ in range(self.n_trees):
            # Sample subset of data
            sample_size = min(256, n_samples)  # Standard subsample size
            indices = np.random.choice(n_samples, sample_size, replace=False)
            sample_data = normalized_data[indices]
            
            # Build tree
            tree = self._build_tree(sample_data, 0)
            self.trees.append(tree)
        
        self.trained = True
    
    def predict_anomaly_score(self, data_point: np.ndarray) -> float:
        """Predict anomaly score for a data point"""
        if not self.trained or len(self.trees) == 0:
            return 0.5  # Neutral score if not trained
        
        # Normalize the data point
        normalized_point = self._normalize_features(data_point.reshape(1, -1))[0]
        
        # Calculate average path length across all trees
        path_lengths = []
        for tree in self.trees:
            path_length = self._calculate_path_length(normalized_point, tree, 0)
            path_lengths.append(path_length)
        
        avg_path_length = np.mean(path_lengths)
        
        # Convert to anomaly score (0 = normal, 1 = anomaly)
        # Shorter paths indicate anomalies
        expected_path_length = self._expected_path_length(256)  # Based on sample size
        anomaly_score = 2 ** (-avg_path_length / expected_path_length)
        
        return anomaly_score
    
    def _normalize_features(self, data: np.ndarray) -> np.ndarray:
        """Normalize features to [0, 1] range"""
        if self.feature_mins is None or self.feature_maxs is None:
            return data
        
        # Avoid division by zero
        feature_ranges = self.feature_maxs - self.feature_mins
        feature_ranges[feature_ranges == 0] = 1
        
        return (data - self.feature_mins) / feature_ranges
    
    def _build_tree(self, data: np.ndarray, depth: int) -> Dict[str, Any]:
        """Build an isolation tree"""
        if depth >= self.max_depth or len(data) <= 1:
            return {'type': 'leaf', 'size': len(data)}
        
        # Choose random feature and split point
        n_features = data.shape[1]
        feature_idx = np.random.randint(0, n_features)
        
        feature_values = data[:, feature_idx]
        if len(np.unique(feature_values)) == 1:
            return {'type': 'leaf', 'size': len(data)}
        
        min_val, max_val = np.min(feature_values), np.max(feature_values)
        split_point = np.random.uniform(min_val, max_val)
        
        # Split data
        left_mask = feature_values < split_point
        left_data = data[left_mask]
        right_data = data[~left_mask]
        
        return {
            'type': 'node',
            'feature': feature_idx,
            'split': split_point,
            'left': self._build_tree(left_data, depth + 1),
            'right': self._build_tree(right_data, depth + 1)
        }
    
    def _calculate_path_length(self, point: np.ndarray, tree: Dict[str, Any], depth: int) -> float:
        """Calculate path length for a point in a tree"""
        if tree['type'] == 'leaf':
            # Add expected path length for remaining points in leaf
            return depth + self._expected_path_length(tree['size'])
        
        if point[tree['feature']] < tree['split']:
            return self._calculate_path_length(point, tree['left'], depth + 1)
        else:
            return self._calculate_path_length(point, tree['right'], depth + 1)
    
    def _expected_path_length(self, n: int) -> float:
        """Expected path length for n points"""
        if n <= 1:
            return 0
        return 2 * (np.log(n - 1) + 0.5772) - 2 * (n - 1) / n  # Euler constant approximation


class StatisticalAnomalyDetector:
    """
    Statistical anomaly detection using z-scores and interquartile ranges
    """
    
    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.feature_stats = {}
        self.feature_history = defaultdict(lambda: deque(maxlen=window_size))
    
    def update_statistics(self, features: np.ndarray, feature_names: List[str]):
        """Update statistical models with new features"""
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            self.feature_history[feature_name].append(feature_val)
            
            # Calculate statistics if we have enough data
            if len(self.feature_history[feature_name]) >= 5:
                values = list(self.feature_history[feature_name])
                self.feature_stats[feature_name] = {
                    'mean': statistics.mean(values),
                    'std': statistics.stdev(values) if len(values) > 1 else 0,
                    'median': statistics.median(values),
                    'q1': np.percentile(values, 25),
                    'q3': np.percentile(values, 75),
                }
    
    def detect_anomalies(self, features: np.ndarray, feature_names: List[str]) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical methods"""
        anomalies = []
        
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            if feature_name not in self.feature_stats:
                continue
            
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
                        'severity': 'high' if z_score > 4 else 'medium',
                        'method': 'z_score'
                    })
            
            # IQR anomaly detection
            iqr = stats['q3'] - stats['q1']
            if iqr > 0:
                lower_bound = stats['q1'] - 1.5 * iqr
                upper_bound = stats['q3'] + 1.5 * iqr
                
                if feature_val < lower_bound or feature_val > upper_bound:
                    deviation = max(
                        abs(feature_val - lower_bound),
                        abs(feature_val - upper_bound)
                    )
                    
                    anomalies.append({
                        'type': 'iqr_outlier',
                        'feature': feature_name,
                        'value': feature_val,
                        'deviation': deviation,
                        'severity': 'high' if deviation > 2 * iqr else 'medium',
                        'method': 'iqr'
                    })
        
        return anomalies


class MLAnomalyDetector:
    """
    Main ML-based anomaly detection system
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.isolation_forest = IsolationForestDetector()
        self.statistical_detector = StatisticalAnomalyDetector()
        self.training_data = []
        self.is_trained = False
        self.anomaly_threshold = 0.6  # Threshold for isolation forest scores
        
        # Feature names for interpretability
        self.feature_names = [
            'cpu_percent', 'memory_mb', 'network_connections', 'dns_queries',
            'file_operations', 'process_spawns', 'tool_calls', 'error_count',
            'response_time_ms', 'data_volume_bytes',
            # Derived features
            'resource_stress', 'network_activity', 'process_ratio', 'error_rate', 'transfer_efficiency',
            # Temporal features
            'hour_sin', 'hour_cos', 'recent_activity', 'cpu_trend',
            # Statistical features
            'cpu_mean', 'cpu_std', 'memory_mean', 'memory_std', 'network_mean', 'network_std'
        ]
    
    def train(self, training_metrics: List[Dict[str, Any]]):
        """Train the anomaly detection models"""
        if len(training_metrics) < 10:
            logger.warning("Insufficient training data for ML anomaly detection")
            return
        
        logger.info(f"Training anomaly detection models with {len(training_metrics)} samples")
        
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
    
    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies in current metrics"""
        anomalies = []
        
        # Update feature history and extract features
        self.feature_extractor.update_history(current_metrics)
        features = self.feature_extractor.extract_features(current_metrics)
        
        # Update statistical models (continuous learning)
        self.statistical_detector.update_statistics(features, self.feature_names)
        
        if not self.is_trained:
            # Not enough training data yet
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
    
    def _identify_anomalous_features(self, features: np.ndarray, metrics: Dict[str, Any]) -> List[str]:
        """Identify which features are most anomalous"""
        if len(self.training_data) == 0:
            return []
        
        # Calculate z-scores for each feature compared to training data
        training_means = np.mean(self.training_data, axis=0)
        training_stds = np.std(self.training_data, axis=0)
        
        anomalous_features = []
        for i, (feature_val, feature_name) in enumerate(zip(features, self.feature_names)):
            if training_stds[i] > 0:
                z_score = abs(feature_val - training_means[i]) / training_stds[i]
                if z_score > 2:  # 2-sigma threshold
                    anomalous_features.append(feature_name)
        
        return anomalous_features
    
    def _calculate_severity(self, anomaly_score: float, affected_features: List[str]) -> AnomalySeverity:
        """Calculate severity based on anomaly score and affected features"""
        base_severity = AnomalySeverity.MEDIUM
        
        # Adjust based on score
        if anomaly_score > 0.8:
            base_severity = AnomalySeverity.HIGH
        elif anomaly_score > 0.9:
            base_severity = AnomalySeverity.CRITICAL
        
        # Adjust based on affected features
        critical_features = {'process_spawns', 'network_connections', 'error_count'}
        if any(feature in critical_features for feature in affected_features):
            if base_severity == AnomalySeverity.MEDIUM:
                base_severity = AnomalySeverity.HIGH
            elif base_severity == AnomalySeverity.HIGH:
                base_severity = AnomalySeverity.CRITICAL
        
        return base_severity
    
    def _generate_recommendation(self, affected_features: List[str]) -> str:
        """Generate recommendations based on anomalous features"""
        recommendations = {
            'cpu_percent': "Monitor CPU usage patterns and check for resource-intensive operations",
            'memory_mb': "Investigate memory leaks or excessive memory allocation",
            'network_connections': "Review network activity for unauthorized connections",
            'process_spawns': "Check for suspicious process creation or command execution",
            'error_count': "Investigate error patterns and potential security issues",
            'dns_queries': "Monitor DNS queries for potential data exfiltration",
            'tool_calls': "Analyze tool usage patterns for anomalous behavior"
        }
        
        specific_recommendations = []
        for feature in affected_features:
            if feature in recommendations:
                specific_recommendations.append(recommendations[feature])
        
        if specific_recommendations:
            return "; ".join(specific_recommendations)
        else:
            return "Investigate unusual runtime behavior patterns"
    
    def get_model_status(self) -> Dict[str, Any]:
        """Get status of anomaly detection models"""
        return {
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data),
            'feature_count': len(self.feature_names),
            'anomaly_threshold': self.anomaly_threshold,
            'isolation_forest_trees': len(self.isolation_forest.trees),
            'statistical_features_tracked': len(self.statistical_detector.feature_stats)
        }
    
    def update_threshold(self, new_threshold: float):
        """Update anomaly detection threshold"""
        self.anomaly_threshold = max(0.1, min(1.0, new_threshold))
        logger.info(f"Updated anomaly threshold to {self.anomaly_threshold}")


class BehaviorProfiler:
    """
    Creates behavioral profiles of MCP servers for comparison
    """
    
    def __init__(self):
        self.profiles = {}
        self.current_session = []
        
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
        logger.info(f"Created behavioral profile '{profile_name}' with {len(session_data)} data points")
    
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
    
    def _extract_behavior_patterns(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract behavioral patterns from session data"""
        patterns = {}
        
        # Tool usage patterns
        tool_calls = [d.get('tool_calls', 0) for d in session_data]
        patterns['tool_usage'] = {
            'burst_detection': len([x for x in tool_calls if x > statistics.mean(tool_calls) * 2]),
            'consistency': statistics.stdev(tool_calls) if len(tool_calls) > 1 else 0
        }
        
        # Resource usage patterns
        cpu_usage = [d.get('cpu_percent', 0) for d in session_data]
        patterns['resource_usage'] = {
            'peak_cpu': max(cpu_usage),
            'cpu_variance': statistics.variance(cpu_usage) if len(cpu_usage) > 1 else 0
        }
        
        return patterns
    
    def _calculate_similarity_score(self, deviations: Dict[str, float]) -> float:
        """Calculate similarity score between current behavior and profile"""
        if not deviations:
            return 1.0
        
        # Calculate weighted similarity (lower deviations = higher similarity)
        weights = {
            'avg_cpu': 0.2,
            'avg_memory': 0.2,
            'avg_network': 0.3,
            'total_tool_calls': 0.2,
            'total_errors': 0.1
        }
        
        weighted_deviation = sum(
            abs(deviations.get(key, 0)) * weight
            for key, weight in weights.items()
        )
        
        # Convert to similarity score (0-1, where 1 is identical)
        similarity = max(0, 1 - weighted_deviation)
        return similarity