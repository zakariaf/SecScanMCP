"""
ML Anomaly Detection Module

Clean modular architecture for ML-based anomaly detection
Following Sandi Metz best practices and clean architecture principles
"""

# Public exports - main interface only
from .main_analyzer import MLAnomalyAnalyzer

# Export models for external use
from .models.enums import AnomalyType, AnomalySeverity
from .models.metrics import AnomalyDetection, BehaviorMetrics

__all__ = [
    'MLAnomalyAnalyzer',
    'AnomalyType',
    'AnomalySeverity', 
    'AnomalyDetection',
    'BehaviorMetrics'
]