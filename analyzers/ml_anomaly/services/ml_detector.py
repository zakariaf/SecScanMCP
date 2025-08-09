"""
ML-based Anomaly Detection Service

Core ML anomaly detection using trained models
Following clean architecture with single responsibility
"""

import time
import logging
import numpy as np
from typing import Dict, List, Any

from ..models.enums import AnomalyType, AnomalySeverity
from ..models.metrics import AnomalyDetection

logger = logging.getLogger(__name__)


class MLDetector:
    """ML-based anomaly detection using isolation forest"""
    
    def __init__(self, feature_service, isolation_forest):
        self.feature_service = feature_service
        self.isolation_forest = isolation_forest
        self.training_data = []
        self.is_trained = False
        self.anomaly_threshold = 0.6
    
    def train(self, training_metrics: List[Dict[str, Any]]) -> bool:
        """Train the ML anomaly detection models"""
        if len(training_metrics) < 10:
            logger.warning("Insufficient training data for ML anomaly detection")
            return False
        
        logger.info(f"Training anomaly detection models with {len(training_metrics)} samples")
        
        training_features = self._extract_training_features(training_metrics)
        training_array = np.array(training_features)
        
        self.isolation_forest.fit(training_array)
        self.training_data = training_array
        self.is_trained = True
        
        logger.info("Anomaly detection models training completed")
        return True
    
    def detect(self, current_metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies using trained ML models"""
        if not self.is_trained:
            return []
        
        features = self._extract_current_features(current_metrics)
        anomaly_score = self.isolation_forest.predict_anomaly_score(features)
        
        if anomaly_score > self.anomaly_threshold:
            return [self._create_anomaly_detection(anomaly_score, current_metrics)]
        
        return []
    
    def update_threshold(self, new_threshold: float):
        """Update anomaly detection threshold"""
        self.anomaly_threshold = max(0.1, min(1.0, new_threshold))
        logger.info(f"Updated anomaly threshold to {self.anomaly_threshold}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get ML detector status"""
        return {
            'is_trained': self.is_trained,
            'training_samples': len(self.training_data),
            'anomaly_threshold': self.anomaly_threshold,
            'isolation_forest_trees': len(self.isolation_forest.trees) if self.is_trained else 0
        }
    
    def _extract_training_features(self, training_metrics: List[Dict[str, Any]]) -> List[np.ndarray]:
        """Extract features from training data"""
        training_features = []
        
        for metrics in training_metrics:
            self.feature_service.update_history(metrics)
            features = self.feature_service.extract_features(metrics)
            training_features.append(features)
        
        return training_features
    
    def _extract_current_features(self, current_metrics: Dict[str, Any]) -> np.ndarray:
        """Extract features from current metrics"""
        self.feature_service.update_history(current_metrics)
        return self.feature_service.extract_features(current_metrics)
    
    def _create_anomaly_detection(self, anomaly_score: float, metrics: Dict[str, Any]) -> AnomalyDetection:
        """Create AnomalyDetection from anomaly score"""
        affected_features = self._identify_anomalous_features(metrics)
        severity = self._calculate_severity(anomaly_score, affected_features)
        
        return AnomalyDetection(
            anomaly_type=AnomalyType.BEHAVIORAL,
            severity=severity,
            confidence=anomaly_score,
            description=f"Behavioral anomaly detected (score: {anomaly_score:.3f})",
            metrics=metrics,
            timestamp=time.time(),
            baseline_deviation=anomaly_score - self.anomaly_threshold,
            affected_features=affected_features,
            recommendation=self._generate_recommendation(affected_features)
        )
    
    def _identify_anomalous_features(self, metrics: Dict[str, Any]) -> List[str]:
        """Identify which features are most anomalous"""
        if len(self.training_data) == 0:
            return []
        
        features = self.feature_service.extract_features(metrics)
        feature_names = self.feature_service.get_feature_names()
        
        training_means = np.mean(self.training_data, axis=0)
        training_stds = np.std(self.training_data, axis=0)
        
        anomalous_features = []
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            if training_stds[i] > 0:
                z_score = abs(feature_val - training_means[i]) / training_stds[i]
                if z_score > 2:
                    anomalous_features.append(feature_name)
        
        return anomalous_features
    
    def _calculate_severity(self, anomaly_score: float, affected_features: List[str]) -> AnomalySeverity:
        """Calculate severity based on anomaly score and affected features"""
        base_severity = AnomalySeverity.MEDIUM
        
        if anomaly_score > 0.8:
            base_severity = AnomalySeverity.HIGH
        elif anomaly_score > 0.9:
            base_severity = AnomalySeverity.CRITICAL
        
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
        
        specific = [recommendations[f] for f in affected_features if f in recommendations]
        
        if specific:
            return "; ".join(specific)
        else:
            return "Investigate unusual runtime behavior patterns"