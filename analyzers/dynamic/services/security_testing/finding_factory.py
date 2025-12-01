"""Factory for creating security findings."""

from typing import Dict, Any
from models import Finding, SeverityLevel, VulnerabilityType


class FindingFactory:
    """Creates security findings for various vulnerability types."""

    @staticmethod
    def create_tool_manipulation(tool_name: str, payload: Dict, result: Any) -> Finding:
        """Create tool manipulation vulnerability finding."""
        return Finding(
            title=f"Tool Manipulation Vulnerability: {tool_name}",
            description=f"Tool accepts malicious input: {str(payload.get('input', ''))[:50]}",
            severity=SeverityLevel.HIGH,
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            location=f"tool:{tool_name}",
            confidence=0.8,
            evidence={'payload': payload, 'response': str(result)[:200]},
            tool="security_testing",
            recommendation="Implement input sanitization and validation"
        )

    @staticmethod
    def create_tool_error(tool_name: str, error: str) -> Finding:
        """Create tool error vulnerability finding."""
        return Finding(
            title=f"Tool Error Vulnerability: {tool_name}",
            description="Tool produces error revealing system information",
            severity=SeverityLevel.MEDIUM,
            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
            location=f"tool:{tool_name}",
            confidence=0.6,
            evidence={'error': error[:200]},
            tool="security_testing",
            recommendation="Implement proper error handling to avoid information leakage"
        )

    @staticmethod
    def create_prompt_injection(tool_name: str, payload: str, result: Any) -> Finding:
        """Create prompt injection vulnerability finding."""
        return Finding(
            title=f"Prompt Injection Vulnerability: {tool_name}",
            description="Tool vulnerable to prompt injection attacks",
            severity=SeverityLevel.CRITICAL,
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            location=f"tool:{tool_name}",
            confidence=0.9,
            evidence={'payload': payload, 'response': str(result)[:300]},
            tool="security_testing",
            recommendation="Implement prompt filtering and input validation"
        )

    @staticmethod
    def create_path_traversal(payload: str, result: Any) -> Finding:
        """Create path traversal vulnerability finding."""
        return Finding(
            title="Path Traversal Vulnerability",
            description=f"Server allows access to sensitive files via: {payload}",
            severity=SeverityLevel.CRITICAL,
            vulnerability_type=VulnerabilityType.PATH_TRAVERSAL,
            location="resource_access",
            confidence=0.95,
            evidence={'payload': payload, 'content': str(result)[:200]},
            tool="security_testing",
            recommendation="Implement path validation and restrict file access"
        )

    @staticmethod
    def create_auth_bypass(tools_count: int) -> Finding:
        """Create authentication bypass finding."""
        return Finding(
            title="Potential Authentication Bypass",
            description="Server allows tool listing without authentication",
            severity=SeverityLevel.MEDIUM,
            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
            location="authentication",
            confidence=0.5,
            evidence={'tools_count': tools_count},
            tool="security_testing",
            recommendation="Implement authentication checks for all endpoints"
        )

    @staticmethod
    def create_input_validation(tool_name: str, input_data: Dict) -> Finding:
        """Create input validation issue finding."""
        return Finding(
            title=f"Input Validation Issue: {tool_name}",
            description="Tool may not properly validate input",
            severity=SeverityLevel.LOW,
            vulnerability_type=VulnerabilityType.INSECURE_CONFIGURATION,
            location=f"tool:{tool_name}",
            confidence=0.4,
            evidence={'input': str(input_data)[:100]},
            tool="security_testing",
            recommendation="Implement comprehensive input validation"
        )
