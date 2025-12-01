"""Anomaly detection service using statistical analysis."""

import logging
from typing import List, Dict, Any, Tuple

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class AnomalyDetectionService:
    """Detects behavioral anomalies using statistical analysis."""

    METRICS_TO_ANALYZE = [
        ('cpu_percent', 'CPU Usage'),
        ('memory_mb', 'Memory Usage'),
        ('network_connections', 'Network Connections'),
        ('process_count', 'Process Count'),
        ('file_descriptors', 'File Descriptors')
    ]

    THRESHOLD_CHECKS = [
        ('cpu_percent', 90, SeverityLevel.MEDIUM, VulnerabilityType.RESOURCE_ABUSE, 'High CPU Usage'),
        ('network_connections', 50, SeverityLevel.LOW, VulnerabilityType.NETWORK_SECURITY, 'High Network'),
    ]

    async def detect_anomalies(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect anomalies in behavioral metrics."""
        findings = []
        findings.extend(self._detect_statistical_anomalies(metrics))
        findings.extend(self._detect_threshold_anomalies(metrics))
        findings.extend(self._detect_memory_growth(metrics))
        return findings

    def _detect_statistical_anomalies(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect statistical outliers in metrics."""
        findings = []
        for metric_name, display_name in self.METRICS_TO_ANALYZE:
            values = [m.get(metric_name, 0) for m in metrics if metric_name in m]
            if not values:
                continue
            for idx, value, z_score in self._find_outliers(values):
                findings.append(self._create_anomaly_finding(
                    display_name, metric_name, value, z_score, metrics[idx].get('timestamp')
                ))
        return findings

    def _find_outliers(self, values: List[float], threshold: float = 2.0) -> List[Tuple]:
        """Find statistical outliers using z-score."""
        if len(values) < 3:
            return []
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        if std_dev == 0:
            return []
        return [(i, v, abs(v - mean) / std_dev) for i, v in enumerate(values)
                if abs(v - mean) > threshold * std_dev]

    def _create_anomaly_finding(self, display_name, metric_name, value, z_score, timestamp):
        """Create a finding for a detected anomaly."""
        severity = SeverityLevel.HIGH if z_score > 3.0 else SeverityLevel.MEDIUM
        return Finding(
            title=f"Behavioral Anomaly: {display_name}",
            description=f"Unusual {display_name.lower()}: {value} (z-score: {z_score:.2f})",
            severity=severity, vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
            location="runtime:behavior", confidence=min(0.9, z_score / 4.0),
            recommendation=f"Investigate unusual {display_name.lower()} patterns",
            evidence={'metric': metric_name, 'value': value, 'z_score': z_score, 'timestamp': timestamp}
        )

    def _detect_threshold_anomalies(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect anomalies based on threshold checks."""
        findings = []
        for metric, threshold, severity, vuln_type, title in self.THRESHOLD_CHECKS:
            values = [m.get(metric, 0) for m in metrics]
            if values and max(values) > threshold:
                findings.append(Finding(
                    title=f"{title} Anomaly", description=f"Max {metric}: {max(values):.1f}",
                    severity=severity, vulnerability_type=vuln_type,
                    location="behavioral_analysis", confidence=0.7,
                    evidence={'max': max(values), 'avg': sum(values)/len(values)}
                ))
        return findings

    def _detect_memory_growth(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect memory growth anomalies."""
        findings = []
        memory_values = [m.get('memory_mb', 0) for m in metrics]
        if len(memory_values) > 1 and (growth := memory_values[-1] - memory_values[0]) > 100:
            findings.append(Finding(
                title="Memory Growth Anomaly", description=f"Memory growth: {growth:.1f} MB",
                severity=SeverityLevel.MEDIUM, vulnerability_type=VulnerabilityType.RESOURCE_ABUSE,
                location="behavioral_analysis", confidence=0.6, evidence={'memory_growth_mb': growth}
            ))
        return findings
