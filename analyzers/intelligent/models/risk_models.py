"""Risk assessment data models."""

from dataclasses import dataclass
from typing import Dict


@dataclass
class ComponentScores:
    """Individual component scores."""
    intent: float
    behavior: float
    ecosystem: float
    anomaly: float


@dataclass
class RiskAssessment:
    """Comprehensive risk assessment result."""
    legitimacy_score: float
    confidence: float
    risk_level: str
    signal_agreement: float
    component_scores: ComponentScores