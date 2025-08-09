"""Injection detection service for MCP vulnerabilities."""

import re
import logging
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType
from ..models.patterns import MCPPatterns, InjectionPattern

logger = logging.getLogger(__name__)


class InjectionDetector:
    """Detects various injection vulnerabilities in MCP configurations."""
    
    def __init__(self):
        self.patterns = MCPPatterns()
    
    def check_text_for_injection(self, text: str, location: str,
                                context_type: str = "general") -> List[Finding]:
        """
        Check text for injection patterns.
        
        Args:
            text: Text to analyze
            location: Location identifier
            context_type: Type of context (tool, resource, prompt)
            
        Returns:
            List of findings
        """
        findings = []
        patterns = self.patterns.get_injection_patterns()
        
        for pattern_obj in patterns:
            if self._matches_pattern(text, pattern_obj.pattern):
                findings.append(self._create_finding(
                    pattern_obj, text, location, context_type
                ))
        
        return findings
    
    def check_schema_for_injection(self, schema: Dict[str, Any],
                                  location: str) -> List[Finding]:
        """
        Check schema for injection vulnerabilities.
        
        Args:
            schema: Schema dictionary to analyze
            location: Location identifier
            
        Returns:
            List of findings
        """
        findings = []
        schema_str = str(schema)
        patterns = self.patterns.get_schema_patterns()
        
        for pattern_obj in patterns:
            if self._matches_pattern(schema_str, pattern_obj.pattern):
                findings.append(self._create_schema_finding(
                    pattern_obj, schema, location
                ))
        
        return findings
    
    def _matches_pattern(self, text: str, pattern: str) -> bool:
        """Check if text matches pattern."""
        try:
            return bool(re.search(pattern, text, re.MULTILINE | re.DOTALL))
        except Exception as e:
            logger.debug(f"Pattern matching error: {e}")
            return False
    
    def _create_finding(self, pattern: InjectionPattern, text: str,
                       location: str, context_type: str) -> Finding:
        """Create a finding from matched pattern."""
        snippet = self._extract_snippet(text, pattern.pattern)
        
        return Finding(
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=pattern.severity,
            confidence=0.85,
            title=pattern.title,
            description=f"Potential injection in {context_type}: {pattern.title}",
            location=location,
            recommendation=self._get_recommendation(pattern.severity),
            references=[
                "https://github.com/modelcontextprotocol/security"
            ],
            evidence={
                "pattern": pattern.pattern,
                "snippet": snippet,
                "context_type": context_type
            },
            tool="mcp_specific",
            cve_id=pattern.cve
        )
    
    def _create_schema_finding(self, pattern: InjectionPattern,
                              schema: Dict, location: str) -> Finding:
        """Create finding for schema injection."""
        return Finding(
            vulnerability_type=VulnerabilityType.SCHEMA_INJECTION,
            severity=pattern.severity,
            confidence=0.9,
            title=f"Schema Injection: {pattern.title}",
            description=f"Dangerous pattern in schema definition",
            location=location,
            recommendation="Remove dynamic code patterns from schema",
            references=[],
            evidence={"schema": schema},
            tool="mcp_specific"
        )
    
    def _extract_snippet(self, text: str, pattern: str,
                        context: int = 50) -> str:
        """Extract snippet around matched pattern."""
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            start = max(0, match.start() - context)
            end = min(len(text), match.end() + context)
            return text[start:end]
        return ""
    
    def _get_recommendation(self, severity: SeverityLevel) -> str:
        """Get recommendation based on severity."""
        if severity == SeverityLevel.CRITICAL:
            return "Remove this pattern immediately - critical security risk"
        elif severity == SeverityLevel.HIGH:
            return "Review and sanitize this content to prevent injection"
        else:
            return "Consider reviewing this pattern for potential security issues"