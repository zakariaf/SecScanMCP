"""Traffic analysis event models."""

from dataclasses import dataclass
from typing import Optional

from .enums import ExfiltrationMethod


@dataclass
class NetworkEvent:
    """Represents a network event detected during analysis."""
    timestamp: float
    event_type: str
    source: str
    destination: str
    protocol: str
    data: Optional[str] = None
    size: int = 0
    suspicious: bool = False
    exfiltration_method: Optional[ExfiltrationMethod] = None


@dataclass
class DataExfiltrationIndicator:
    """Indicators of potential data exfiltration."""
    method: ExfiltrationMethod
    confidence: float
    data_pattern: str
    destination: str
    volume: int
    frequency: int
    encoding_detected: Optional[str] = None
    description: str = ""