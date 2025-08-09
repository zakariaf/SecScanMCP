"""ML anomaly detection data models."""

from dataclasses import dataclass
from typing import Dict, List, Any

from .enums import AnomalyType, AnomalySeverity


@dataclass
class BehaviorMetrics:
    """Runtime behavior metrics for analysis."""
    timestamp: float
    cpu_percent: float
    memory_mb: float
    network_connections: int
    dns_queries: int
    file_operations: int
    process_spawns: int
    tool_calls: int
    error_count: int
    response_time_ms: float
    data_volume_bytes: int
    unique_destinations: int


@dataclass
class AnomalyDetection:
    """Represents a detected anomaly."""
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    confidence: float
    description: str
    metrics: Dict[str, Any]
    timestamp: float
    baseline_deviation: float
    affected_features: List[str]
    recommendation: str