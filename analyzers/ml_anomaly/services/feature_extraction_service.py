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
            return np.zeros(30, dtype=np.float32)  # Return default feature vector
    
    def _calculate_derived_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Calculate derived features from basic metrics."""
        derived = []
        
        try:
            # Resource utilization ratio
            cpu = metrics.get('cpu_percent', 0)
            memory = metrics.get('memory_mb', 0)
            derived.append(cpu * memory if memory > 0 else 0)  # Combined resource stress
            
            # Network activity intensity
            connections = metrics.get('network_connections', 0)
            dns_queries = metrics.get('dns_queries', 0)
            derived.append(connections + dns_queries * 0.5)  # Network activity score
            
            # Process activity ratio
            spawns = metrics.get('process_spawns', 0)
            operations = metrics.get('file_operations', 0)
            derived.append(spawns / max(operations, 1))  # Process-to-file ratio
            
            # Error density
            errors = metrics.get('error_count', 0)
            tool_calls = metrics.get('tool_calls', 0)
            derived.append(errors / max(tool_calls, 1))  # Error rate
            
            # Data throughput efficiency
            data_volume = metrics.get('data_volume_bytes', 0)
            response_time = metrics.get('response_time_ms', 1)
            derived.append(data_volume / max(response_time, 1))  # Bytes per ms
            
            # Anomaly indicators
            derived.extend([
                1.0 if cpu > 90 else 0.0,  # High CPU indicator
                1.0 if memory > 1000 else 0.0,  # High memory indicator
                1.0 if errors > 5 else 0.0,  # High error indicator
                1.0 if connections > 20 else 0.0,  # High network indicator
            ])
            
        except Exception as e:
            self.logger.debug(f"Derived feature calculation error: {e}")
            derived = [0.0] * 9  # Default values
        
        return derived
    
    def _calculate_temporal_features(self, metrics: Dict[str, Any]) -> List[float]:
        """Calculate temporal features based on recent history."""
        temporal = []
        
        try:
            if len(self.feature_history) < 2:
                return [0.0] * 6  # Not enough history
            
            # Rate of change calculations
            current = metrics
            previous = self.feature_history[-1] if self.feature_history else {}
            
            # CPU change rate
            cpu_change = current.get('cpu_percent', 0) - previous.get('cpu_percent', 0)
            temporal.append(cpu_change)
            
            # Memory change rate
            mem_change = current.get('memory_mb', 0) - previous.get('memory_mb', 0)
            temporal.append(mem_change)
            
            # Network change rate
            net_change = (current.get('network_connections', 0) - 
                         previous.get('network_connections', 0))
            temporal.append(net_change)
            
            # Response time trend (last 5 samples)
            recent_response_times = [
                m.get('response_time_ms', 0) 
                for m in list(self.feature_history)[-5:] + [current]
            ]
            
            if len(recent_response_times) >= 2:
                trend = statistics.mean(recent_response_times[-3:]) - statistics.mean(recent_response_times[:3])
                temporal.append(trend)
            else:
                temporal.append(0.0)
            
            # Variability indicators
            if len(self.feature_history) >= 5:
                recent_cpu = [m.get('cpu_percent', 0) for m in list(self.feature_history)[-5:]]
                cpu_std = statistics.stdev(recent_cpu) if len(recent_cpu) > 1 else 0
                temporal.append(cpu_std)
                
                recent_memory = [m.get('memory_mb', 0) for m in list(self.feature_history)[-5:]]
                mem_std = statistics.stdev(recent_memory) if len(recent_memory) > 1 else 0
                temporal.append(mem_std)
            else:
                temporal.extend([0.0, 0.0])
            
        except Exception as e:
            self.logger.debug(f"Temporal feature calculation error: {e}")
            temporal = [0.0] * 6
        
        return temporal
    
    def _calculate_statistical_features(self) -> List[float]:
        """Calculate statistical features from history."""
        stats = []
        
        try:
            if not self.feature_history:
                return [0.0] * 8
            
            # CPU statistics
            cpu_values = [m.get('cpu_percent', 0) for m in self.feature_history]
            if cpu_values:
                stats.extend([
                    statistics.mean(cpu_values),
                    statistics.median(cpu_values),
                    max(cpu_values) - min(cpu_values),  # Range
                ])
            else:
                stats.extend([0.0, 0.0, 0.0])
            
            # Memory statistics
            mem_values = [m.get('memory_mb', 0) for m in self.feature_history]
            if mem_values:
                stats.extend([
                    statistics.mean(mem_values),
                    statistics.median(mem_values),
                    max(mem_values) - min(mem_values),  # Range
                ])
            else:
                stats.extend([0.0, 0.0, 0.0])
            
            # Network activity statistics
            net_values = [m.get('network_connections', 0) for m in self.feature_history]
            if net_values:
                stats.extend([
                    statistics.mean(net_values),
                    max(net_values) - min(net_values),  # Range
                ])
            else:
                stats.extend([0.0, 0.0])
            
        except Exception as e:
            self.logger.debug(f"Statistical feature calculation error: {e}")
            stats = [0.0] * 8
        
        return stats
    
    def update_history(self, metrics: Dict[str, Any]):
        """Update feature history with new metrics."""
        try:
            self.feature_history.append(dict(metrics))
        except Exception as e:
            self.logger.debug(f"History update error: {e}")
    
    def get_feature_names(self) -> List[str]:
        """Get names of all extracted features."""
        return [
            # Basic features (10)
            'cpu_percent', 'memory_mb', 'network_connections', 'dns_queries',
            'file_operations', 'process_spawns', 'tool_calls', 'error_count',
            'response_time_ms', 'data_volume_bytes',
            
            # Derived features (9)
            'resource_stress', 'network_activity', 'process_file_ratio',
            'error_rate', 'data_efficiency', 'high_cpu_flag', 'high_memory_flag',
            'high_error_flag', 'high_network_flag',
            
            # Temporal features (6)
            'cpu_change', 'memory_change', 'network_change', 'response_trend',
            'cpu_variability', 'memory_variability',
            
            # Statistical features (8)
            'cpu_mean', 'cpu_median', 'cpu_range', 'memory_mean',
            'memory_median', 'memory_range', 'network_mean', 'network_range'
        ]