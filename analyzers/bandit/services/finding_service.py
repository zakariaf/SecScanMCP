"""
Bandit Finding Service

Converts Bandit results to standardized findings with vulnerability mapping
Following clean architecture with single responsibility
"""

import logging
from typing import Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class FindingService:
    """Converts Bandit results to findings"""
    
    # Map Bandit severity to our severity levels
    SEVERITY_MAP = {
        'HIGH': SeverityLevel.HIGH,
        'MEDIUM': SeverityLevel.MEDIUM,
        'LOW': SeverityLevel.LOW
    }
    
    # Map Bandit test IDs to vulnerability types
    VULN_TYPE_MAP = {
        'B201': VulnerabilityType.COMMAND_INJECTION,  # flask_debug
        'B301': VulnerabilityType.INSECURE_CONFIGURATION,  # pickle
        'B302': VulnerabilityType.INSECURE_CONFIGURATION,  # marshal
        'B303': VulnerabilityType.INSECURE_CONFIGURATION,  # md5
        'B304': VulnerabilityType.INSECURE_CONFIGURATION,  # des
        'B305': VulnerabilityType.INSECURE_CONFIGURATION,  # cipher
        'B306': VulnerabilityType.INSECURE_CONFIGURATION,  # mktemp
        'B307': VulnerabilityType.COMMAND_INJECTION,  # eval
        'B308': VulnerabilityType.INSECURE_CONFIGURATION,  # mark_safe
        'B309': VulnerabilityType.INSECURE_CONFIGURATION,  # httpsconnection
        'B310': VulnerabilityType.PATH_TRAVERSAL,  # urllib_urlopen
        'B311': VulnerabilityType.INSECURE_CONFIGURATION,  # random
        'B312': VulnerabilityType.INSECURE_CONFIGURATION,  # telnetlib
        'B313': VulnerabilityType.XXE,  # xml_bad_cElementTree
        'B314': VulnerabilityType.XXE,  # xml_bad_ElementTree
        'B315': VulnerabilityType.XXE,  # xml_bad_expatreader
        'B316': VulnerabilityType.XXE,  # xml_bad_expatbuilder
        'B317': VulnerabilityType.XXE,  # xml_bad_sax
        'B318': VulnerabilityType.XXE,  # xml_bad_minidom
        'B319': VulnerabilityType.XXE,  # xml_bad_pulldom
        'B320': VulnerabilityType.XXE,  # xml_bad_etree
        'B321': VulnerabilityType.INSECURE_CONFIGURATION,  # ftplib
        'B322': VulnerabilityType.COMMAND_INJECTION,  # input
        'B323': VulnerabilityType.INSECURE_CONFIGURATION,  # unverified_context
        'B324': VulnerabilityType.INSECURE_CONFIGURATION,  # hashlib_new_insecure_functions
        'B325': VulnerabilityType.INSECURE_CONFIGURATION,  # tempnam
        'B601': VulnerabilityType.COMMAND_INJECTION,  # paramiko_calls
        'B602': VulnerabilityType.COMMAND_INJECTION,  # subprocess_popen_with_shell_equals_true
        'B603': VulnerabilityType.COMMAND_INJECTION,  # subprocess_without_shell_equals_true
        'B604': VulnerabilityType.COMMAND_INJECTION,  # any_other_function_with_shell_equals_true
        'B605': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_a_shell
        'B606': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_no_shell
        'B607': VulnerabilityType.COMMAND_INJECTION,  # start_process_with_partial_path
        'B608': VulnerabilityType.SQL_INJECTION,  # hardcoded_sql_expressions
        'B609': VulnerabilityType.COMMAND_INJECTION,  # linux_commands_wildcard_injection
        'B610': VulnerabilityType.SQL_INJECTION,  # django_extra_used
        'B611': VulnerabilityType.SQL_INJECTION,  # django_rawsql_used
        'B701': VulnerabilityType.INSECURE_CONFIGURATION,  # jinja2_autoescape_false
        'B702': VulnerabilityType.INSECURE_CONFIGURATION,  # use_of_mako_templates
        'B703': VulnerabilityType.SQL_INJECTION,  # django_mark_safe
    }
    
    def __init__(self):
        self.base_analyzer = BaseAnalyzer()
    
    def convert_to_finding(self, bandit_result: Dict[str, Any]) -> Finding:
        """Convert Bandit result to our Finding model"""
        # Extract basic information
        test_id = bandit_result.get('test_id', '')
        test_name = bandit_result.get('test_name', 'Unknown')
        issue_text = bandit_result.get('issue_text', '')
        
        # Determine vulnerability type and severity
        vuln_type = self._get_vulnerability_type(test_id)
        severity = self._get_severity(bandit_result)
        confidence = self._get_confidence(bandit_result)
        
        # Build finding components
        title = self._build_title(test_name, issue_text)
        description = issue_text
        location = self._build_location(bandit_result)
        recommendation = self._build_recommendation(bandit_result)
        references = self._build_references(bandit_result)
        evidence = self._build_evidence(bandit_result, test_id)
        
        return self.base_analyzer.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            location=location,
            recommendation=recommendation,
            references=references,
            evidence=evidence
        )
    
    def _get_vulnerability_type(self, test_id: str) -> VulnerabilityType:
        """Get vulnerability type from test ID"""
        return self.VULN_TYPE_MAP.get(test_id, VulnerabilityType.GENERIC)
    
    def _get_severity(self, bandit_result: Dict[str, Any]) -> SeverityLevel:
        """Get severity level from Bandit result"""
        severity_str = bandit_result.get('issue_severity', 'MEDIUM')
        return self.SEVERITY_MAP.get(severity_str, SeverityLevel.MEDIUM)
    
    def _get_confidence(self, bandit_result: Dict[str, Any]) -> float:
        """Calculate confidence based on Bandit's confidence"""
        confidence_map = {'HIGH': 0.9, 'MEDIUM': 0.7, 'LOW': 0.5}
        confidence_str = bandit_result.get('issue_confidence', 'MEDIUM')
        return confidence_map.get(confidence_str, 0.7)
    
    def _build_title(self, test_name: str, issue_text: str) -> str:
        """Build finding title"""
        return f"{test_name} - {issue_text}"
    
    def _build_location(self, bandit_result: Dict[str, Any]) -> str:
        """Build location string"""
        filename = bandit_result.get('filename', 'unknown')
        line_number = bandit_result.get('line_number', 0)
        return f"{filename}:{line_number}"
    
    def _build_recommendation(self, bandit_result: Dict[str, Any]) -> str:
        """Build recommendation text"""
        test_name = bandit_result.get('test_name', 'security issue')
        more_info = bandit_result.get('more_info', '')
        
        recommendation = f"Review and fix the {test_name}."
        if more_info:
            recommendation += f" {more_info}"
        
        return recommendation
    
    def _build_references(self, bandit_result: Dict[str, Any]) -> list:
        """Build references list"""
        more_info = bandit_result.get('more_info')
        return [more_info] if more_info else []
    
    def _build_evidence(self, bandit_result: Dict[str, Any], test_id: str) -> Dict[str, Any]:
        """Build evidence dictionary"""
        return {
            'code_snippet': bandit_result.get('code', ''),
            'test_id': test_id,
            'line_range': bandit_result.get('line_range', [])
        }