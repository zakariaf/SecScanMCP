"""Configuration management with Pydantic settings."""

import yaml
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class MLModelsConfig(BaseModel):
    """ML models configuration."""
    embeddings: Dict[str, any] = Field(default_factory=dict)
    anomaly_detection: Dict[str, any] = Field(default_factory=dict)
    clustering: Dict[str, any] = Field(default_factory=dict)


class RiskWeights(BaseModel):
    """Risk assessment weights."""
    intent: float = 0.35
    behavior: float = 0.25
    ecosystem: float = 0.25
    anomaly: float = 0.15


class RiskThresholds(BaseModel):
    """Risk assessment thresholds."""
    high_legitimacy: float = 0.75
    medium_legitimacy: float = 0.55
    high_confidence: float = 0.6
    medium_confidence: float = 0.3


class AnomalyThresholds(BaseModel):
    """Anomaly detection thresholds."""
    excessive_file_ops: int = 25
    excessive_network_ops: int = 20
    excessive_system_ops: int = 8
    max_function_complexity: int = 15
    max_avg_complexity: float = 8.0
    max_dependencies: int = 50


class RiskAssessmentConfig(BaseModel):
    """Risk assessment configuration."""
    weights: RiskWeights = Field(default_factory=RiskWeights)
    thresholds: RiskThresholds = Field(default_factory=RiskThresholds)
    anomaly_thresholds: AnomalyThresholds = Field(default_factory=AnomalyThresholds)


class SemanticConfig(BaseModel):
    """Semantic analysis configuration."""
    similarity_thresholds: Dict[str, float] = Field(default_factory=dict)
    storage_keywords: List[str] = Field(default_factory=list)
    trusted_dependencies: List[str] = Field(default_factory=list)


class DatabaseConfig(BaseModel):
    """Database configuration."""
    type: str = "sqlite"
    path: str = "/tmp/security_learning/feedback.db"
    async_enabled: bool = False
    connection_pool_size: int = 10
    timeout: int = 30


class LoggingConfig(BaseModel):
    """Logging configuration."""
    level: str = "INFO"
    structured: bool = True
    include_scan_id: bool = True
    format: str = "json"


class SecurityPatternsConfig(BaseModel):
    """Security patterns configuration."""
    mcp_storage_patterns: List[str] = Field(default_factory=list)
    suspicious_patterns: List[str] = Field(default_factory=list)


class IntelligentAnalyzerSettings(BaseSettings):
    """Main configuration settings for intelligent analyzer."""
    
    ml_models: MLModelsConfig = Field(default_factory=MLModelsConfig)
    risk_assessment: RiskAssessmentConfig = Field(default_factory=RiskAssessmentConfig)
    semantic_analysis: SemanticConfig = Field(default_factory=SemanticConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    security_patterns: SecurityPatternsConfig = Field(default_factory=SecurityPatternsConfig)
    
    class Config:
        env_prefix = "INTELLIGENT_ANALYZER_"
        case_sensitive = False


class ConfigManager:
    """Manages configuration loading and validation."""
    
    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path or Path(__file__).parent.parent.parent / "config" / "default.yaml"
        self._settings = None
    
    def load_settings(self) -> IntelligentAnalyzerSettings:
        """Load and validate settings."""
        if self._settings is None:
            # Load YAML config
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    yaml_config = yaml.safe_load(f)
                
                # Create settings with YAML data
                self._settings = IntelligentAnalyzerSettings(**yaml_config)
            else:
                # Use defaults
                self._settings = IntelligentAnalyzerSettings()
        
        return self._settings
    
    def get_weights(self) -> Dict[str, float]:
        """Get risk assessment weights."""
        settings = self.load_settings()
        weights = settings.risk_assessment.weights
        return {
            'intent': weights.intent,
            'behavior': weights.behavior,
            'ecosystem': weights.ecosystem,
            'anomaly': weights.anomaly
        }
    
    def get_thresholds(self) -> Dict[str, float]:
        """Get risk assessment thresholds."""
        settings = self.load_settings()
        thresholds = settings.risk_assessment.thresholds
        return {
            'high_legitimacy': thresholds.high_legitimacy,
            'medium_legitimacy': thresholds.medium_legitimacy,
            'high_confidence': thresholds.high_confidence,
            'medium_confidence': thresholds.medium_confidence
        }
    
    def get_anomaly_thresholds(self) -> Dict[str, any]:
        """Get anomaly detection thresholds."""
        settings = self.load_settings()
        thresholds = settings.risk_assessment.anomaly_thresholds
        return {
            'excessive_file_ops': thresholds.excessive_file_ops,
            'excessive_network_ops': thresholds.excessive_network_ops,
            'excessive_system_ops': thresholds.excessive_system_ops,
            'max_function_complexity': thresholds.max_function_complexity,
            'max_avg_complexity': thresholds.max_avg_complexity,
            'max_dependencies': thresholds.max_dependencies
        }
    
    def get_storage_keywords(self) -> List[str]:
        """Get storage-related keywords."""
        settings = self.load_settings()
        return settings.semantic_analysis.storage_keywords
    
    def get_trusted_dependencies(self) -> List[str]:
        """Get trusted dependency patterns."""
        settings = self.load_settings()
        return settings.semantic_analysis.trusted_dependencies