"""
Parser Service for OpenGrep Analysis

Parses OpenGrep output and creates Finding objects
Following clean architecture with single responsibility
"""

import json
import logging
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class ParserService:
    """Parses OpenGrep output into Finding objects"""
    
    def __init__(self, rule_service):
        self.rule_service = rule_service
    
    def parse_opengrep_output(self, output: str) -> List[Finding]:
        """Parse OpenGrep JSON output into Finding objects"""
        if not output.strip():
            return []
        
        try:
            data = json.loads(output)
            findings = []
            
            # Handle OpenGrep/Semgrep JSON format
            results = data.get('results', [])
            
            for result in results:
                finding = self._create_finding_from_result(result)
                if finding:
                    findings.append(finding)
            
            return findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse OpenGrep output: {e}")
            return []
        except Exception as e:
            logger.error(f"Error processing OpenGrep results: {e}")
            return []
    
    def _create_finding_from_result(self, result: Dict[str, Any]) -> Optional[Finding]:
        """Create Finding object from OpenGrep result"""
        try:
            # Extract basic information
            rule_id = result.get('check_id', 'unknown')
            message = result.get('message', 'OpenGrep finding')
            
            # Extract location information
            path_info = result.get('path', '')
            start_line = result.get('start', {}).get('line', 1)
            end_line = result.get('end', {}).get('line', start_line)
            
            # Extract code snippet
            code_snippet = self._extract_code_snippet(result)
            
            # Map severity
            severity = self._map_severity(result.get('severity', 'INFO'))
            
            # Map vulnerability type
            vuln_type = self.rule_service.map_rule_to_vulnerability_type(rule_id)
            
            # Get references
            references = self.rule_service.get_references_for_rule(rule_id)
            
            # Create finding
            finding = Finding(
                title=f"OpenGrep: {rule_id}",
                description=message,
                severity=severity,
                vulnerability_type=vuln_type,
                file_path=path_info,
                line_number=start_line,
                end_line=end_line if end_line != start_line else None,
                code_snippet=code_snippet,
                tool="opengrep",
                rule_id=rule_id,
                references=references
            )
            
            return finding
            
        except Exception as e:
            logger.error(f"Failed to create finding from result: {e}")
            return None
    
    def _extract_code_snippet(self, result: Dict[str, Any]) -> str:
        """Extract code snippet from OpenGrep result"""
        # Try to get the matched code
        extra = result.get('extra', {})
        
        # Look for lines in extra
        if 'lines' in extra:
            return '\n'.join(extra['lines'])
        
        # Look for matched text
        if 'matched_text' in extra:
            return extra['matched_text']
        
        # Look for fix suggestions
        if 'fix' in extra:
            return f"Current: {extra.get('matched_text', '')}\nSuggested: {extra['fix']}"
        
        return ""
    
    def _map_severity(self, opengrep_severity: str) -> SeverityLevel:
        """Map OpenGrep severity to internal severity level"""
        severity_map = {
            'ERROR': SeverityLevel.HIGH,
            'WARNING': SeverityLevel.MEDIUM,
            'INFO': SeverityLevel.LOW,
            'HIGH': SeverityLevel.HIGH,
            'MEDIUM': SeverityLevel.MEDIUM,
            'LOW': SeverityLevel.LOW,
            'CRITICAL': SeverityLevel.CRITICAL
        }
        
        return severity_map.get(opengrep_severity.upper(), SeverityLevel.LOW)