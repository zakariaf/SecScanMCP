"""ML anomaly detection enums."""

from enum import Enum


class AnomalyType(Enum):
    """Types of anomalies that can be detected."""
    BEHAVIORAL = "behavioral"
    PERFORMANCE = "performance"
    NETWORK = "network"
    PROCESS = "process"
    DATA_FLOW = "data_flow"
    TEMPORAL = "temporal"


class AnomalySeverity(Enum):
    """Severity levels for detected anomalies."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"