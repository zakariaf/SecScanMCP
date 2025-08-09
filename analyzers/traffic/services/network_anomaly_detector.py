"""Network anomaly detector service."""

import logging
from typing import Dict, List, Any
from collections import deque

logger = logging.getLogger(__name__)


class NetworkAnomalyDetector:
    """ML-based network anomaly detection (simplified implementation)."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations from normal
        self.metrics_history = deque(maxlen=1000)
    
    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior."""
        if not metrics:
            return
        
        try:
            # Calculate statistical baselines
            connection_counts = [m.get('connection_count', 0) for m in metrics]
            dns_query_counts = [m.get('dns_queries', 0) for m in metrics]
            data_volumes = [m.get('data_volume', 0) for m in metrics]
            
            self.baseline_metrics = {
                'connection_count': {
                    'mean': self._calculate_mean(connection_counts),
                    'std': self._calculate_std(connection_counts)
                },
                'dns_queries': {
                    'mean': self._calculate_mean(dns_query_counts),
                    'std': self._calculate_std(dns_query_counts)
                },
                'data_volume': {
                    'mean': self._calculate_mean(data_volumes),
                    'std': self._calculate_std(data_volumes)
                }
            }
            
            self.logger.info("Network baseline established")
            
        except Exception as e:
            self.logger.error(f"Baseline establishment failed: {e}")
    
    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in current metrics compared to baseline."""
        anomalies = []
        
        if not self.baseline_metrics:
            return anomalies
        
        try:
            for metric_name, current_value in current_metrics.items():
                if metric_name in self.baseline_metrics:
                    baseline = self.baseline_metrics[metric_name]
                    
                    # Calculate z-score
                    if baseline['std'] > 0:
                        z_score = abs(current_value - baseline['mean']) / baseline['std']
                        
                        if z_score > self.anomaly_threshold:
                            anomalies.append({
                                'metric': metric_name,
                                'current_value': current_value,
                                'baseline_mean': baseline['mean'],
                                'z_score': z_score,
                                'severity': 'high' if z_score > 3.0 else 'medium',
                                'confidence': min(z_score / 4.0, 1.0)
                            })
            
            # Store current metrics for trend analysis
            self.metrics_history.append(current_metrics)
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def detect_trend_anomalies(self) -> List[Dict[str, Any]]:
        """Detect trend-based anomalies."""
        anomalies = []
        
        if len(self.metrics_history) < 10:
            return anomalies
        
        try:
            # Analyze trends in recent history
            recent_metrics = list(self.metrics_history)[-10:]  # Last 10 samples
            
            for metric_name in ['connection_count', 'dns_queries', 'data_volume']:
                values = [m.get(metric_name, 0) for m in recent_metrics]
                
                if len(values) < 5:
                    continue
                
                # Check for monotonic increase (potential attack)
                if self._is_monotonic_increasing(values):
                    anomalies.append({
                        'type': 'trend_anomaly',
                        'metric': metric_name,
                        'pattern': 'monotonic_increase',
                        'confidence': 0.8,
                        'description': f'Consistent increase in {metric_name}'
                    })
                
                # Check for sudden spikes
                if len(values) >= 3:
                    recent_avg = sum(values[-3:]) / 3
                    earlier_avg = sum(values[:-3]) / len(values[:-3]) if len(values) > 3 else recent_avg
                    
                    if earlier_avg > 0 and recent_avg > earlier_avg * 3:
                        anomalies.append({
                            'type': 'trend_anomaly',
                            'metric': metric_name,
                            'pattern': 'sudden_spike',
                            'confidence': 0.9,
                            'spike_ratio': recent_avg / earlier_avg,
                            'description': f'Sudden spike in {metric_name}'
                        })
        
        except Exception as e:
            self.logger.error(f"Trend anomaly detection failed: {e}")
        
        return anomalies
    
    def analyze_connection_patterns(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze connection patterns for anomalies."""
        patterns = []
        
        try:
            if not connections:
                return patterns
            
            # Analyze destination distribution
            destinations = [conn.get('foreign_address', '') for conn in connections]
            unique_destinations = set(destinations)
            
            # Check for connection concentration
            if len(unique_destinations) == 1 and len(connections) > 20:
                patterns.append({
                    'type': 'connection_concentration',
                    'destination': list(unique_destinations)[0],
                    'connection_count': len(connections),
                    'confidence': 0.8
                })
            
            # Check for port scanning behavior
            ports_accessed = []
            for conn in connections:
                addr = conn.get('foreign_address', '')
                if ':' in addr:
                    port = addr.split(':')[-1]
                    if port.isdigit():
                        ports_accessed.append(int(port))
            
            unique_ports = set(ports_accessed)
            if len(unique_ports) > 50:  # Accessing many ports
                patterns.append({
                    'type': 'port_scanning',
                    'unique_ports': len(unique_ports),
                    'confidence': min(len(unique_ports) / 100, 1.0)
                })
        
        except Exception as e:
            self.logger.error(f"Connection pattern analysis failed: {e}")
        
        return patterns
    
    def _calculate_mean(self, values: List[float]) -> float:
        """Calculate mean of values."""
        return sum(values) / len(values) if values else 0.0
    
    def _calculate_std(self, values: List[float]) -> float:
        """Calculate standard deviation of values."""
        if len(values) < 2:
            return 0.0
        
        mean = self._calculate_mean(values)
        variance = sum((x - mean) ** 2 for x in values) / (len(values) - 1)
        return variance ** 0.5
    
    def _is_monotonic_increasing(self, values: List[float]) -> bool:
        """Check if values are monotonically increasing."""
        if len(values) < 3:
            return False
        
        increases = 0
        for i in range(1, len(values)):
            if values[i] > values[i-1]:
                increases += 1
        
        # At least 80% of transitions should be increases
        return increases / (len(values) - 1) >= 0.8