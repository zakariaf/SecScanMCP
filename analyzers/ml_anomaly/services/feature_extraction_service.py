"""Feature extraction service for ML anomaly detection."""

import numpy as np
import logging
import statistics
from typing import Dict, List, Any
from collections import deque

logger = logging.getLogger(__name__)


class FeatureExtractionService:
    """Extracts meaningful features from raw runtime data."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.feature_history = deque(maxlen=1000)
        self.temporal_patterns = {}
    
    def extract_features(self, raw_metrics: Dict[str, Any]) -> np.ndarray:
        """Extract feature vector from raw metrics."""
        try:
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
            
        except Exception as e:
            self.logger.error(f"Feature extraction failed: {e}")
            return np.zeros(25, dtype=np.float32)  # Return default feature vector
    
    def _calculate_derived_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Calculate derived features from basic metrics matching original."""
        derived = []
        
        try:
            # Resource utilization ratio - from original
            cpu = metrics.get('cpu_percent', 0)
            memory = metrics.get('memory_mb', 0)
            derived.append(cpu * memory if memory > 0 else 0)  # Combined resource stress
            
            # Network activity intensity - from original
            connections = metrics.get('network_connections', 0)
            dns_queries = metrics.get('dns_queries', 0)
            derived.append(connections + dns_queries * 2)  # Weighted network activity
            
            # Process activity ratio - from original
            spawns = metrics.get('process_spawns', 0)
            tools = metrics.get('tool_calls', 0)
            derived.append(spawns / max(tools, 1))  # Processes per tool call
            
            # Error rate - from original
            errors = metrics.get('error_count', 0)
            total_operations = tools + metrics.get('file_operations', 0)
            derived.append(errors / max(total_operations, 1))  # Error rate
            
            # Data transfer efficiency - from original
            data_volume = metrics.get('data_volume_bytes', 0)
            response_time = metrics.get('response_time_ms', 1)
            derived.append(data_volume / response_time)  # Bytes per ms
            
        except Exception as e:
            self.logger.debug(f"Derived feature calculation error: {e}")
            derived = [0.0] * 5  # Default values
        
        return derived
    
    def _calculate_temporal_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Calculate temporal pattern features matching original implementation."""
        import time
        import math
        
        temporal = []
        
        try:
            current_time = time.time()
            
            # Time of day features (cyclical encoding) - from original
            hour = time.localtime(current_time).tm_hour
            temporal.extend([
                math.sin(2 * math.pi * hour / 24),  # Hour sin
                math.cos(2 * math.pi * hour / 24),  # Hour cos
            ])
            
            # Activity frequency - from original
            if len(self.feature_history) > 1:
                recent_activity = sum(
                    m.get('tool_calls', 0) for m in list(self.feature_history)[-10:]
                )
                temporal.append(recent_activity / 10)  # Average recent activity
            else:
                temporal.append(0)
            
            # Trend detection - from original
            if len(self.feature_history) >= 5:
                recent_cpu = [m.get('cpu_percent', 0) for m in list(self.feature_history)[-5:]]
                cpu_trend = (recent_cpu[-1] - recent_cpu[0]) / 5  # CPU trend
                temporal.append(cpu_trend)
            else:
                temporal.append(0)
            
        except Exception as e:
            self.logger.debug(f"Temporal feature calculation error: {e}")
            temporal = [0.0] * 4  # Updated count
        
        return temporal
    
    def _calculate_statistical_features(self) -> List[float]:
        """Calculate statistical features from recent history matching original."""
        stats = []
        
        try:
            if len(self.feature_history) < 3:
                return [0] * 6  # Return zeros if insufficient history
            
            recent_metrics = list(self.feature_history)[-10:]
            
            # CPU statistics - from original
            cpu_values = [m.get('cpu_percent', 0) for m in recent_metrics]
            stats.extend([
                statistics.mean(cpu_values),
                statistics.stdev(cpu_values) if len(cpu_values) > 1 else 0,
            ])
            
            # Memory statistics - from original
            memory_values = [m.get('memory_mb', 0) for m in recent_metrics]
            stats.extend([
                statistics.mean(memory_values),
                statistics.stdev(memory_values) if len(memory_values) > 1 else 0,
            ])
            
            # Network activity statistics - from original
            network_values = [m.get('network_connections', 0) for m in recent_metrics]
            stats.extend([
                statistics.mean(network_values),
                statistics.stdev(network_values) if len(network_values) > 1 else 0,
            ])
            
        except Exception as e:
            self.logger.debug(f"Statistical feature calculation error: {e}")
            stats = [0.0] * 6
        
        return stats
    
    def update_history(self, metrics: Dict[str, Any]):
        """Update feature history with new metrics."""
        try:
            self.feature_history.append(dict(metrics))
        except Exception as e:
            self.logger.debug(f"History update error: {e}")
    
    def get_feature_names(self) -> List[str]:
        """Get names of all extracted features exactly matching original implementation."""
        return [
            # Basic features (10)
            'cpu_percent', 'memory_mb', 'network_connections', 'dns_queries',
            'file_operations', 'process_spawns', 'tool_calls', 'error_count',
            'response_time_ms', 'data_volume_bytes',
            
            # Derived features (5) - exactly matching original
            'resource_stress', 'network_activity', 'process_ratio', 'error_rate', 'transfer_efficiency',
            
            # Temporal features (4) - exactly matching original
            'hour_sin', 'hour_cos', 'recent_activity', 'cpu_trend',
            
            # Statistical features (6) - exactly matching original  
            'cpu_mean', 'cpu_std', 'memory_mean', 'memory_std', 'network_mean', 'network_std'
        ]