"""
Data models for the security scanner
"""
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    # Code vulnerabilities
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"
    XSS = "xss"

    # Cryptography
    WEAK_CRYPTO = "weak_crypto"

    # MCP-specific
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    MCP_SPECIFIC = "mcp_specific"
    TOOL_MANIPULATION = "tool_manipulation"
    PERMISSION_ABUSE = "permission_abuse"
    SCHEMA_INJECTION = "schema_injection"
    OUTPUT_POISONING = "output_poisoning"

    # Privilege issues
    PRIVILEGE_ESCALATION = "privilege_escalation"

    # Secrets and credentials
    HARDCODED_SECRET = "hardcoded_secret"
    API_KEY_EXPOSURE = "api_key_exposure"

    # Dependencies
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    OUTDATED_DEPENDENCY = "outdated_dependency"
    LICENSE_VIOLATION = "license_violation"

    # Configuration
    INSECURE_CONFIGURATION = "insecure_configuration"
    MISSING_SECURITY_HEADERS = "missing_security_headers"

    # Runtime & Behavioral
    BEHAVIORAL_ANOMALY = "behavioral_anomaly"
    DATA_LEAKAGE = "data_leakage"
    DATA_EXPOSURE = "data_exposure"
    NETWORK_SECURITY = "network_security"
    RESOURCE_ABUSE = "resource_abuse"
    
    # Malware / other
    MALWARE = "malware"
    BACKDOOR = "backdoor"
    GENERIC = "generic"


class Finding(BaseModel):
    """Individual security finding"""

    # Core fields
    vulnerability_type: VulnerabilityType
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0, default=0.8)

    # Details
    title: str
    description: str
    location: str  # file:line or similar

    # Remediation
    recommendation: str
    references: List[str] = Field(default_factory=list)

    # Evidence
    evidence: Dict[str, Any] = Field(default_factory=dict)

    # Metadata
    tool: str  # Which analyzer found this
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "vulnerability_type": "command_injection",
                "severity": "critical",
                "confidence": 0.95,
                "title": "Command Injection in subprocess call",
                "description": "User input is passed directly to subprocess.run without sanitization",
                "location": "app/utils.py:45",
                "recommendation": "Use shlex.quote() to escape shell arguments",
                "references": ["https://cwe.mitre.org/data/definitions/78.html"],
                "evidence": {"rule_id": "python/command-injection", "message": "user input reaches shell"},
                "tool": "codeql",
                "cwe_id": "CWE-78",
            }
        }
    )


class ScanRequest(BaseModel):
    """Request to scan a repository"""

    repository_url: HttpUrl
    options: Dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "repository_url": "https://github.com/user/mcp-server",
                "options": {
                    "enable_mcp_rules": True,
                    "attempt_autobuild": True,
                    "codeql_threads": 0,
                    "codeql_ram_mb": 4096,
                },
            }
        }
    )


class ScanResult(BaseModel):
    """Complete scan results"""

    # Repository info
    repository_url: str
    project_type: str
    is_mcp_server: bool

    # Findings
    findings: List[Finding]
    user_centric_findings: List[Finding] = Field(default_factory=list)
    developer_centric_findings: List[Finding] = Field(default_factory=list)
    total_findings: int = 0

    # Enhanced Scoring (main scores)
    security_score: float = Field(ge=0.0, le=100.0)  # User Safety Score
    security_grade: str = Field(pattern="^[A-F]$")  # User Safety Grade
    enhanced_scores: Dict[str, Any] = Field(default_factory=dict)

    # Summary
    summary: Dict[str, Any]

    # Detailed results by tool
    detailed_results: Dict[str, List[Dict[str, Any]]]

    # Metadata
    scan_metadata: Dict[str, Any] = Field(default_factory=dict)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)

    def __init__(self, **data):
        super().__init__(**data)
        self.total_findings = len(self.findings)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "repository_url": "https://github.com/user/mcp-server",
                "project_type": "javascript",
                "is_mcp_server": True,
                "findings": [],
                "total_findings": 5,
                "security_score": 78.5,
                "security_grade": "B+",
                "summary": {
                    "total_findings": 5,
                    "severity_breakdown": {"critical": 0, "high": 1, "medium": 3, "low": 1, "info": 0},
                    "risk_level": "medium",
                },
                "detailed_results": {},
                "scan_metadata": {},
                "scan_timestamp": "2025-01-01T12:00:00Z",
            }
        }
    )


class ToolConfiguration(BaseModel):
    """Configuration for individual security tools"""

    enabled: bool = True
    timeout: int = 300  # seconds
    options: Dict[str, Any] = Field(default_factory=dict)
