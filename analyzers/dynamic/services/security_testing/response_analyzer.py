"""Response analysis utilities for security testing."""

from typing import Dict, Any


class ResponseAnalyzer:
    """Analyzes responses for vulnerability indicators."""

    COMMAND_EXEC_INDICATORS = [
        'uid=', 'gid=', 'root:', 'administrator',
        '/bin/bash', '/bin/sh', 'command not found'
    ]

    REVEALING_ERRORS = [
        'permission denied', 'access denied', 'file not found',
        'syntax error', 'command not found', 'no such file'
    ]

    INJECTION_SUCCESS_INDICATORS = [
        'injected', 'debug mode', 'environment variables',
        'override', 'system:', 'forget', 'new instruction'
    ]

    SENSITIVE_PATTERNS = [
        'root:x:', 'administrator:', '/etc/passwd',
        'password', 'secret', 'private key'
    ]

    @classmethod
    def analyze_tool_response(cls, response: Dict, payload: Dict) -> bool:
        """Analyze tool response for signs of vulnerability."""
        response_str = str(response).lower()
        return any(ind in response_str for ind in cls.COMMAND_EXEC_INDICATORS)

    @classmethod
    def is_vulnerability_error(cls, error_msg: str) -> bool:
        """Check if error message reveals vulnerability."""
        error_lower = error_msg.lower()
        return any(err in error_lower for err in cls.REVEALING_ERRORS)

    @classmethod
    def detect_injection_success(cls, response: Dict, payload: str) -> bool:
        """Detect successful prompt injection."""
        response_str = str(response).lower()
        return any(ind in response_str for ind in cls.INJECTION_SUCCESS_INDICATORS)

    @classmethod
    def contains_sensitive_data(cls, content: Dict) -> bool:
        """Check if content contains sensitive system data."""
        content_str = str(content).lower()
        return any(pat in content_str for pat in cls.SENSITIVE_PATTERNS)

    @classmethod
    def indicates_poor_validation(cls, response: Dict, input_data: Dict) -> bool:
        """Check if response indicates poor input validation."""
        response_str = str(response)
        if len(response_str) > 5000:
            return True
        return any(
            str(val) in response_str for val in input_data.values()
            if isinstance(val, (str, int))
        )
