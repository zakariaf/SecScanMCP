"""Core data models for security analysis."""

from dataclasses import dataclass
from typing import Dict, List, Any


@dataclass
class CodeContext:
    """Rich context information about code under analysis."""
    project_name: str
    project_description: str
    project_type: str
    language: str
    
    # Code analysis
    functions: List[Dict[str, Any]]
    file_operations: List[Dict[str, Any]] 
    network_operations: List[Dict[str, Any]]
    system_operations: List[Dict[str, Any]]
    
    # Documentation analysis
    readme_content: str
    docstrings: List[str]
    comments: List[str]
    commit_messages: List[str]
    
    # Ecosystem context
    dependencies: List[str]
    similar_projects: List[Dict[str, Any]]
    community_reputation: Dict[str, Any]


@dataclass 
class LegitimacyAnalysis:
    """Result of intelligent legitimacy analysis."""
    is_legitimate: bool
    confidence_score: float
    risk_level: str  # low, medium, high
    explanation: str
    evidence: Dict[str, Any]
    recommendations: List[str]
    
    # ML insights
    intent_alignment_score: float
    behavioral_anomaly_score: float
    ecosystem_similarity_score: float