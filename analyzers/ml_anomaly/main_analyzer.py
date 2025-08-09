"""
Main ML Anomaly Detection Analyzer

Orchestrates ML-based anomaly detection for MCP runtime behavior
Following clean architecture principles with ≤100 lines per file
"""

import logging
from typing import Dict, List, Any, Optional

from .models.enums import AnomalyType
from .models.metrics import AnomalyDetection
from .services.feature_extraction_service import FeatureExtractionService
from .services.statistical_detector import StatisticalDetector
from .services.behavior_profiler import BehaviorProfiler
from .services.ml_detector import MLDetector
from .detectors.isolation_forest_detector import IsolationForestDetector

logger = logging.getLogger(__name__)


class MLAnomalyAnalyzer:
    """Clean orchestrator for ML anomaly detection"""
    
    def __init__(self):
        self.feature_service = FeatureExtractionService()
        self.ml_detector = MLDetector(
            feature_service=self.feature_service,
            isolation_forest=IsolationForestDetector()
        )
        self.statistical_detector = StatisticalDetector()
        self.behavior_profiler = BehaviorProfiler()
        self.is_trained = False
    
    def train(self, training_metrics: List[Dict[str, Any]]) -> bool:
        """Train anomaly detection models"""
        if len(training_metrics) < 10:
            logger.warning("Insufficient training data")
            return False
        
        success = self.ml_detector.train(training_metrics)
        self.is_trained = success
        return success
    
    def detect_anomalies(self, metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies in current metrics"""
        if not self.is_trained:
            return []
        
        # ML-based detection
        ml_anomalies = self.ml_detector.detect(metrics)
        
        # Statistical detection
        statistical_anomalies = self.statistical_detector.detect(
            metrics, self.feature_service
        )
        
        return ml_anomalies + statistical_anomalies
    
    def create_profile(self, session_data: List[Dict[str, Any]], name: str):
        """Create behavioral profile"""
        self.behavior_profiler.create_profile(session_data, name)
    
    def compare_to_profile(self, data: List[Dict[str, Any]], name: str):
        """Compare behavior to profile"""
        return self.behavior_profiler.compare_to_profile(data, name)
    
    def get_status(self) -> Dict[str, Any]:
        """Get analyzer status"""
        return {
            'is_trained': self.is_trained,
            'ml_detector_status': self.ml_detector.get_status(),
            'statistical_features': len(self.statistical_detector.feature_stats),
            'profiles_count': len(self.behavior_profiler.profiles)
        }
    
    def update_threshold(self, threshold: float):
        """Update anomaly detection threshold"""
        self.ml_detector.update_threshold(threshold)