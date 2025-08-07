"""Anomaly detection component."""

import numpy as np
from typing import Tuple, Dict, Any, List

from .base_analyzer import BaseAnalyzer
from ..models.analysis_models import CodeContext
from ..utils.ml_utils import is_ml_available
from ..utils.config_manager import ConfigManager
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class FeatureExtractor:
    """Extracts features for anomaly detection."""
    
    def extract_features(self, context: CodeContext) -> np.ndarray:
        """Extract numerical features for ML anomaly detection."""
        features = []
        
        # Operation counts
        features.extend([
            len(context.file_operations),
            len(context.network_operations),
            len(context.system_operations),
            len(context.functions)
        ])
        
        # Ratios and derived metrics
        total_ops = sum(features[:3])
        if total_ops > 0:
            features.extend([
                len(context.file_operations) / total_ops,
                len(context.network_operations) / total_ops,
                len(context.system_operations) / total_ops
            ])
        else:
            features.extend([0.0, 0.0, 0.0])
        
        # Complexity metrics
        complexities = [f.get('complexity', 1) for f in context.functions]
        features.extend([
            np.mean(complexities) if complexities else 0,
            np.max(complexities) if complexities else 0,
            len(context.dependencies)
        ])
        
        # Project characteristics
        features.extend([
            len(context.project_name) if context.project_name else 0,
            len(context.readme_content) if context.readme_content else 0,
            len(context.docstrings)
        ])
        
        return np.array(features, dtype=np.float32)


class StatisticalAnomalyDetector:
    """Statistical anomaly detection using configurable thresholds."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
    
    def detect_anomalies(self, context: CodeContext) -> List[str]:
        """Detect statistical anomalies in the code context."""
        anomalies = []
        
        anomalies.extend(self._check_operation_counts(context))
        anomalies.extend(self._check_operation_combinations(context))
        anomalies.extend(self._check_user_input_patterns(context))
        anomalies.extend(self._check_complexity_anomalies(context))
        
        return anomalies
    
    def _check_operation_counts(self, context: CodeContext) -> List[str]:
        """Check for unusual operation counts using configurable thresholds."""
        anomalies = []
        thresholds = self.config_manager.get_anomaly_thresholds()
        
        file_ops = len(context.file_operations)
        net_ops = len(context.network_operations)
        sys_ops = len(context.system_operations)
        
        # Check against configured thresholds
        if file_ops > thresholds['excessive_file_ops']:
            anomalies.append(f"Excessive file operations ({file_ops})")
        
        if net_ops > thresholds['excessive_network_ops']:
            anomalies.append(f"Excessive network operations ({net_ops})")
        
        if sys_ops > thresholds['excessive_system_ops']:
            anomalies.append(f"Excessive system operations ({sys_ops})")
        
        return anomalies
    
    def _check_operation_combinations(self, context: CodeContext) -> List[str]:
        """Check for suspicious operation combinations."""
        anomalies = []
        
        has_file_ops = len(context.file_operations) > 0
        has_net_ops = len(context.network_operations) > 0
        has_sys_ops = len(context.system_operations) > 0
        
        # Risky combinations
        if has_sys_ops and has_net_ops:
            anomalies.append("System commands combined with network operations")
        
        if has_sys_ops and has_file_ops and has_net_ops:
            anomalies.append("File, network, and system operations all present")
        
        return anomalies
    
    def _check_user_input_patterns(self, context: CodeContext) -> List[str]:
        """Check for dangerous user input patterns."""
        anomalies = []
        
        all_operations = (context.file_operations + 
                         context.network_operations + 
                         context.system_operations)
        
        user_input_keywords = ['user', 'input', 'request', 'param', 'arg']
        dangerous_ops = ['exec', 'eval', 'system', 'shell', 'command']
        
        for op in all_operations:
            op_str = str(op).lower()
            
            has_user_input = any(kw in op_str for kw in user_input_keywords)
            has_dangerous_op = any(dop in op_str for dop in dangerous_ops)
            
            if has_user_input and has_dangerous_op:
                anomalies.append("User input in dangerous operations detected")
                break
        
        return anomalies
    
    def _check_complexity_anomalies(self, context: CodeContext) -> List[str]:
        """Check for complexity-related anomalies using configurable thresholds."""
        anomalies = []
        thresholds = self.config_manager.get_anomaly_thresholds()
        
        if context.functions:
            complexities = [f.get('complexity', 1) for f in context.functions]
            max_complexity = max(complexities)
            avg_complexity = np.mean(complexities)
            
            if max_complexity > thresholds['max_function_complexity']:
                anomalies.append(f"Very high function complexity ({max_complexity})")
            
            if avg_complexity > thresholds['max_avg_complexity']:
                anomalies.append(f"High average complexity ({avg_complexity:.1f})")
        
        # Dependency anomalies
        if len(context.dependencies) > thresholds['max_dependencies']:
            anomalies.append(f"Excessive dependencies ({len(context.dependencies)})")
        
        return anomalies


class MLAnomalyDetector:
    """Machine learning-based anomaly detection."""
    
    def __init__(self):
        self.model = None
        self.feature_extractor = FeatureExtractor()
        
        if is_ml_available():
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize the ML anomaly detection model."""
        try:
            from sklearn.ensemble import IsolationForest
            self.model = IsolationForest(
                contamination=0.1,
                random_state=42,
                n_estimators=100
            )
        except ImportError:
            logger.warning("ML libraries not available for anomaly detection",
                          component="anomaly_detector")
    
    def detect_ml_anomalies(self, context: CodeContext) -> Tuple[float, Dict]:
        """Detect anomalies using ML model."""
        if not self.model:
            return 0.0, {'ml_available': False}
        
        try:
            features = self.feature_extractor.extract_features(context)
            features = features.reshape(1, -1)  # Single sample
            
            # Use heuristic-based score since model is not pre-trained
            # In production, would use: self.model.decision_function(features)
            anomaly_score = self._calculate_heuristic_anomaly_score(features[0])
            
            return anomaly_score, {
                'ml_available': True,
                'feature_vector': features[0].tolist(),
                'anomaly_score': anomaly_score,
                'model_trained': False
            }
            
        except Exception as e:
            logger.debug("ML anomaly detection failed",
                        error=str(e),
                        component="anomaly_detector")
            return 0.0, {'ml_available': True, 'error': str(e)}
    
    def _calculate_heuristic_anomaly_score(self, features: np.ndarray) -> float:
        """Calculate anomaly score using heuristics."""
        score = 0.0
        
        # Check feature ranges against expected norms
        file_ops, net_ops, sys_ops, functions = features[:4]
        
        # Anomaly indicators (higher = more anomalous)
        if file_ops > 20:
            score += 0.3
        if net_ops > 15:
            score += 0.3
        if sys_ops > 5:
            score += 0.4
        
        # Operation ratios
        if len(features) > 6:
            file_ratio, net_ratio, sys_ratio = features[4:7]
            
            if sys_ratio > 0.3:  # System ops > 30% of total
                score += 0.3
            if net_ratio > 0.7:  # Network ops > 70% of total
                score += 0.2
        
        return min(1.0, score)


class AnomalyDetector(BaseAnalyzer):
    """Comprehensive anomaly detection system."""
    
    def __init__(self, config_manager: ConfigManager = None):
        self.config_manager = config_manager or ConfigManager()
        self.statistical_detector = StatisticalAnomalyDetector(self.config_manager)
        self.ml_detector = MLAnomalyDetector()
    
    async def analyze(self, context: CodeContext) -> Tuple[float, Dict[str, Any]]:
        """Detect behavioral anomalies."""
        evidence = {
            'statistical_anomalies': [],
            'ml_anomalies': {},
            'anomaly_score': 0.0,
            'anomaly_reasons': []
        }
        
        # Statistical anomaly detection
        statistical_anomalies = self.statistical_detector.detect_anomalies(context)
        evidence['statistical_anomalies'] = statistical_anomalies
        
        # ML-based anomaly detection
        ml_score, ml_evidence = self.ml_detector.detect_ml_anomalies(context)
        evidence['ml_anomalies'] = ml_evidence
        
        # Combine scores
        statistical_score = min(1.0, len(statistical_anomalies) / 10.0)
        combined_anomaly_score = (statistical_score * 0.6 + ml_score * 0.4)
        
        evidence['anomaly_score'] = combined_anomaly_score
        evidence['anomaly_reasons'] = statistical_anomalies
        
        # Convert to legitimacy score (inverted)
        legitimacy_score = 1.0 - combined_anomaly_score
        
        return float(legitimacy_score), evidence