"""
Statistical Anomaly Detection Service

Statistical anomaly detection using z-scores and interquartile ranges
Following clean architecture with single responsibility
"""

import time
import logging
import statistics
import numpy as np
from typing import Dict, List, Any
from collections import defaultdict, deque

from ..models.enums import AnomalyType, AnomalySeverity
from ..models.metrics import AnomalyDetection

logger = logging.getLogger(__name__)


class StatisticalDetector:
    """Statistical anomaly detection using z-scores and IQR"""
    
    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self.feature_stats = {}
        self.feature_history = defaultdict(lambda: deque(maxlen=window_size))
    
    def detect(self, metrics: Dict[str, Any], feature_service) -> List[AnomalyDetection]:
        """Detect statistical anomalies"""
        features = feature_service.extract_features(metrics)
        feature_names = feature_service.get_feature_names()
        
        self._update_statistics(features, feature_names)
        raw_anomalies = self._detect_anomalies(features, feature_names)
        
        return self._convert_to_detections(raw_anomalies, metrics)
    
    def _update_statistics(self, features: np.ndarray, feature_names: List[str]):
        """Update statistical models with new features"""
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            self.feature_history[feature_name].append(feature_val)
            
            if len(self.feature_history[feature_name]) >= 5:
                values = list(self.feature_history[feature_name])
                self.feature_stats[feature_name] = self._calculate_stats(values)
    
    def _calculate_stats(self, values: List[float]) -> Dict[str, float]:
        """Calculate statistical measures for values"""
        return {
            'mean': statistics.mean(values),
            'std': statistics.stdev(values) if len(values) > 1 else 0,
            'median': statistics.median(values),
            'q1': np.percentile(values, 25),
            'q3': np.percentile(values, 75),
        }
    
    def _detect_anomalies(self, features: np.ndarray, feature_names: List[str]) -> List[Dict[str, Any]]:
        """Detect anomalies using statistical methods"""
        anomalies = []
        
        for i, (feature_val, feature_name) in enumerate(zip(features, feature_names)):
            if feature_name not in self.feature_stats:
                continue
            
            stats = self.feature_stats[feature_name]
            
            # Z-score detection
            z_anomaly = self._detect_z_score_anomaly(feature_val, feature_name, stats)
            if z_anomaly:
                anomalies.append(z_anomaly)
            
            # IQR detection
            iqr_anomaly = self._detect_iqr_anomaly(feature_val, feature_name, stats)
            if iqr_anomaly:
                anomalies.append(iqr_anomaly)
        
        return anomalies
    
    def _detect_z_score_anomaly(self, value: float, feature: str, stats: Dict[str, float]) -> Optional[Dict[str, Any]]:
        """Detect z-score based anomaly"""
        if stats['std'] <= 0:
            return None
        
        z_score = abs(value - stats['mean']) / stats['std']
        if z_score > 3:  # 3-sigma rule
            return {
                'type': 'statistical_outlier',
                'feature': feature,
                'value': value,
                'z_score': z_score,
                'severity': 'high' if z_score > 4 else 'medium',
                'method': 'z_score'
            }
        return None
    
    def _detect_iqr_anomaly(self, value: float, feature: str, stats: Dict[str, float]) -> Optional[Dict[str, Any]]:
        """Detect IQR based anomaly"""
        iqr = stats['q3'] - stats['q1']
        if iqr <= 0:
            return None
        
        lower_bound = stats['q1'] - 1.5 * iqr
        upper_bound = stats['q3'] + 1.5 * iqr
        
        if value < lower_bound or value > upper_bound:
            deviation = max(abs(value - lower_bound), abs(value - upper_bound))
            return {
                'type': 'iqr_outlier',
                'feature': feature,
                'value': value,
                'deviation': deviation,
                'severity': 'high' if deviation > 2 * iqr else 'medium',
                'method': 'iqr'
            }
        return None
    
    def _convert_to_detections(self, raw_anomalies: List[Dict[str, Any]], metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Convert raw anomalies to AnomalyDetection objects"""
        detections = []
        
        for anomaly in raw_anomalies:
            detection = AnomalyDetection(
                anomaly_type=AnomalyType.PERFORMANCE,
                severity=AnomalySeverity(anomaly['severity']),
                confidence=0.8,
                description=f"Statistical anomaly in {anomaly['feature']}: {anomaly['value']:.2f}",
                metrics=metrics,
                timestamp=time.time(),
                baseline_deviation=anomaly.get('z_score', anomaly.get('deviation', 0)),
                affected_features=[anomaly['feature']],
                recommendation=f"Investigate unusual {anomaly['feature']} values"
            )
            detections.append(detection)
        
        return detections