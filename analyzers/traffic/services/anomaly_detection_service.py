"""Network anomaly detection service using ML techniques."""

import logging
import time
from typing import Dict, List, Any
from collections import deque, defaultdict

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """ML-based network anomaly detection."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.baseline_metrics = {}
        self.anomaly_threshold = 2.0  # Standard deviations
        self.metrics_history = deque(maxlen=1000)
        self.baseline_established = False
    
    def establish_baseline(self, metrics: List[Dict[str, Any]]):
        """Establish baseline network behavior."""
        if not metrics:
            return
        
        try:
            # Calculate statistical baselines
            connection_counts = [m.get('connection_count', 0) for m in metrics]
            dns_query_counts = [m.get('dns_queries', 0) for m in metrics]
            data_volumes = [m.get('data_volume', 0) for m in metrics]
            request_rates = [m.get('request_rate', 0) for m in metrics]
            
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
                },
                'request_rate': {
                    'mean': self._calculate_mean(request_rates),
                    'std': self._calculate_std(request_rates)
                }
            }
            
            self.baseline_established = True
            self.logger.info("Network baseline established")
            
        except Exception as e:
            self.logger.error(f"Baseline establishment failed: {e}")
    
    def detect_anomalies(self, current_metrics: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalies in current metrics."""
        anomalies = []
        
        if not self.baseline_established:
            return anomalies
        
        try:
            # Add current metrics to history
            self.metrics_history.append(current_metrics)
            
            # Check each metric against baseline
            for metric_name, current_value in current_metrics.items():
                if metric_name in self.baseline_metrics:
                    anomaly = self._check_metric_anomaly(
                        metric_name, current_value
                    )
                    if anomaly:
                        anomalies.append(anomaly)
            
            # Check for temporal patterns
            temporal_anomalies = self._detect_temporal_anomalies()
            anomalies.extend(temporal_anomalies)
            
        except Exception as e:
            self.logger.error(f"Anomaly detection failed: {e}")
        
        return anomalies
    
    def detect_traffic_bursts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual traffic bursts."""
        bursts = []
        
        try:
            # Group events by time windows
            window_size = 60  # 1 minute windows
            time_windows = defaultdict(list)
            
            for event in events:
                timestamp = event.get('timestamp', time.time())
                window = int(timestamp // window_size)
                time_windows[window].append(event)
            
            # Calculate normal traffic rate
            window_counts = [len(events) for events in time_windows.values()]
            if not window_counts:
                return bursts
            
            mean_count = self._calculate_mean(window_counts)
            std_count = self._calculate_std(window_counts)
            
            # Find burst windows
            for window, window_events in time_windows.items():
                event_count = len(window_events)
                
                if std_count > 0:
                    z_score = (event_count - mean_count) / std_count
                    
                    if z_score > self.anomaly_threshold:
                        bursts.append({
                            'type': 'traffic_burst',
                            'window': window,
                            'event_count': event_count,
                            'normal_count': mean_count,
                            'z_score': z_score,
                            'confidence': min(z_score / 5.0, 1.0)
                        })
            
        except Exception as e:
            self.logger.error(f"Burst detection failed: {e}")
        
        return bursts
    
    def detect_connection_anomalies(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect anomalous connection patterns."""
        anomalies = []
        
        try:
            # Analyze connection destinations
            dest_counts = defaultdict(int)
            for conn in connections:
                dest = conn.get('foreign_address', '')
                if dest:
                    dest_counts[dest] += 1
            
            # Check for connection concentration
            total_connections = len(connections)
            if total_connections > 0:
                for dest, count in dest_counts.items():
                    concentration = count / total_connections
                    
                    # Flag high concentration to single destination
                    if concentration > 0.7 and count > 10:
                        anomalies.append({
                            'type': 'connection_concentration',
                            'destination': dest,
                            'connection_count': count,
                            'concentration': concentration,
                            'confidence': min(concentration, 1.0)
                        })
            
            # Check for unusual port patterns
            port_anomalies = self._detect_port_anomalies(connections)
            anomalies.extend(port_anomalies)
            
        except Exception as e:
            self.logger.error(f"Connection anomaly detection failed: {e}")
        
        return anomalies
    
    def detect_behavioral_changes(self) -> List[Dict[str, Any]]:
        """Detect behavioral changes over time."""
        changes = []
        
        try:
            if len(self.metrics_history) < 20:
                return changes
            
            # Compare recent behavior to historical
            recent_metrics = list(self.metrics_history)[-10:]  # Last 10 samples
            historical_metrics = list(self.metrics_history)[:-10]  # Earlier samples
            
            for metric_name in ['connection_count', 'data_volume', 'dns_queries']:
                recent_values = [m.get(metric_name, 0) for m in recent_metrics]
                historical_values = [m.get(metric_name, 0) for m in historical_metrics]
                
                if not recent_values or not historical_values:
                    continue
                
                recent_mean = self._calculate_mean(recent_values)
                historical_mean = self._calculate_mean(historical_values)
                historical_std = self._calculate_std(historical_values)
                
                if historical_std > 0:
                    change_score = abs(recent_mean - historical_mean) / historical_std
                    
                    if change_score > self.anomaly_threshold:
                        changes.append({
                            'type': 'behavioral_change',
                            'metric': metric_name,
                            'recent_mean': recent_mean,
                            'historical_mean': historical_mean,
                            'change_score': change_score,
                            'confidence': min(change_score / 4.0, 1.0)
                        })
            
        except Exception as e:
            self.logger.error(f"Behavioral change detection failed: {e}")
        
        return changes
    
    def _check_metric_anomaly(self, metric_name: str, current_value: float) -> Dict[str, Any]:
        """Check if a single metric value is anomalous."""
        baseline = self.baseline_metrics[metric_name]
        
        if baseline['std'] > 0:
            z_score = abs(current_value - baseline['mean']) / baseline['std']
            
            if z_score > self.anomaly_threshold:
                return {
                    'type': 'statistical_anomaly',
                    'metric': metric_name,
                    'current_value': current_value,
                    'baseline_mean': baseline['mean'],
                    'z_score': z_score,
                    'confidence': min(z_score / 4.0, 1.0)
                }
        
        return None
    
    def _detect_temporal_anomalies(self) -> List[Dict[str, Any]]:
        """Detect temporal patterns and anomalies."""
        anomalies = []
        
        if len(self.metrics_history) < 10:
            return anomalies
        
        try:
            # Check for unusual timing patterns
            recent_metrics = list(self.metrics_history)[-10:]
            timestamps = [m.get('timestamp', 0) for m in recent_metrics]
            
            # Check for very rapid requests
            intervals = []
            for i in range(1, len(timestamps)):
                interval = timestamps[i] - timestamps[i-1]
                intervals.append(interval)
            
            if intervals:
                avg_interval = self._calculate_mean(intervals)
                min_interval = min(intervals)
                
                # Flag if minimum interval is much smaller than average
                if avg_interval > 0 and min_interval < avg_interval * 0.1:
                    anomalies.append({
                        'type': 'rapid_requests',
                        'min_interval': min_interval,
                        'avg_interval': avg_interval,
                        'confidence': 0.8
                    })
        
        except Exception as e:
            self.logger.error(f"Temporal anomaly detection failed: {e}")
        
        return anomalies
    
    def _detect_port_anomalies(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect unusual port usage patterns."""
        anomalies = []
        
        try:
            port_counts = defaultdict(int)
            
            for conn in connections:
                addr = conn.get('foreign_address', '')
                if ':' in addr:
                    port = addr.split(':')[-1]
                    if port.isdigit():
                        port_counts[int(port)] += 1
            
            # Check for unusual high ports
            high_ports = [p for p in port_counts.keys() if p > 49152]
            if len(high_ports) > 10:  # Many ephemeral ports
                anomalies.append({
                    'type': 'excessive_high_ports',
                    'port_count': len(high_ports),
                    'confidence': min(len(high_ports) / 50.0, 1.0)
                })
            
            # Check for known suspicious ports
            suspicious_ports = {1234, 4444, 5555, 6666, 8080, 9999}
            used_suspicious = suspicious_ports.intersection(port_counts.keys())
            
            if used_suspicious:
                anomalies.append({
                    'type': 'suspicious_ports',
                    'ports': list(used_suspicious),
                    'confidence': 0.9
                })
        
        except Exception as e:
            self.logger.error(f"Port anomaly detection failed: {e}")
        
        return anomalies
    
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