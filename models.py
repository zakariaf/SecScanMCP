"""
Data models for the security scanner
"""

from pydantic import BaseModel, HttpUrl, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    # Code vulnerabilities
    COMMAND_INJECTION = "command_injection"
    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xxe"
    SSRF = "ssrf"

    # MCP-specific
    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    PERMISSION_ABUSE = "permission_abuse"
    SCHEMA_INJECTION = "schema_injection"
    OUTPUT_POISONING = "output_poisoning"

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

    # Malware
    MALWARE = "malware"

    # Other
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

    class Config:
        schema_extra = {
            "example": {
                "vulnerability_type": "command_injection",
                "severity": "critical",
                "confidence": 0.95,
                "title": "Command Injection in subprocess call",
                "description": "User input is passed directly to subprocess.run without sanitization",
                "location": "app/utils.py:45",
                "recommendation": "Use shlex.quote() to escape shell arguments",
                "tool": "bandit",
                "cwe_id": "CWE-78"
            }
        }


class ScanRequest(BaseModel):
    """Request to scan a repository"""

    repository_url: HttpUrl
    options: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        schema_extra = {
            "example": {
                "repository_url": "https://github.com/user/mcp-server",
                "options": {
                    "enable_dynamic_analysis": True,
                    "skip_dependencies": False
                }
            }
        }


class ScanResult(BaseModel):
    """Complete scan results"""

    # Repository info
    repository_url: str
    project_type: str
    is_mcp_server: bool

    # Findings
    findings: List[Finding]
    total_findings: int = 0

    # Scoring
    security_score: float = Field(ge=0.0, le=100.0)
    security_grade: str = Field(pattern="^[A-F][+-]?$")  # Changed from regex to pattern

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

    class Config:
        schema_extra = {
            "example": {
                "repository_url": "https://github.com/user/mcp-server",
                "project_type": "python",
                "is_mcp_server": True,
                "findings": [],
                "total_findings": 5,
                "security_score": 78.5,
                "security_grade": "B+",
                "summary": {
                    "total_findings": 5,
                    "severity_breakdown": {
                        "critical": 0,
                        "high": 1,
                        "medium": 3,
                        "low": 1,
                        "info": 0
                    },
                    "risk_level": "medium"
                },
                "detailed_results": {},
                "scan_metadata": {},
                "scan_timestamp": "2024-01-01T12:00:00Z"
            }
        }


class ToolConfiguration(BaseModel):
    """Configuration for individual security tools"""

    enabled: bool = True
    timeout: int = 300  # seconds
    options: Dict[str, Any] = Field(default_factory=dict)