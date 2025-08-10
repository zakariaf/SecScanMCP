"""
YARA Finding Service

Converts YARA matches to findings with metadata extraction
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class FindingService:
    """Converts YARA matches to findings"""
    
    def __init__(self):
        # Use BaseAnalyzer for finding creation
        pass  # BaseAnalyzer removed - services create Finding objects directly
    
    def convert_match_to_finding(self, match: Any, file_path: Path, 
                                 repo_root: Path) -> Optional[Finding]:
        """Convert YARA match to Finding"""
        try:
            relative_path = self._get_relative_path(file_path, repo_root)
            meta = match.meta
            
            # Extract match details
            matched_strings = self._extract_matched_strings(match, file_path)
            location = self._build_location(relative_path, matched_strings)
            
            # Build finding
            return Finding(
                vulnerability_type=self._determine_vuln_type(meta),
                severity=self._determine_severity(meta),
                confidence=float(meta.get('confidence', 0.8)),
                title=f"YARA Detection: {match.rule}",
                description=self._build_description(match, meta),
                location=location,
                recommendation=meta.get(
                    'recommendation', 
                    'Review the detected pattern and take appropriate action'
                ),
                references=self._extract_references(meta),
                evidence=self._build_evidence(match, meta, matched_strings),
                tool="yara"
            )
            
        except Exception as e:
            logger.error(f"Failed to convert YARA match: {e}")
            return None
    
    def _get_relative_path(self, file_path: Path, repo_root: Path) -> Path:
        """Get relative path from repo root"""
        try:
            return file_path.relative_to(repo_root)
        except ValueError:
            return file_path
    
    def _extract_matched_strings(self, match: Any, file_path: Path) -> List[Dict]:
        """Extract matched strings with line information"""
        matched_strings = []
        file_content = None
        
        for s in match.strings:
            # Load file content once if we need it
            if file_content is None:
                # Check if we need to load content for any offset
                needs_content = self._needs_file_content(s)
                if needs_content:
                    file_content = self._load_file_content(file_path)
            
            string_info = self._parse_string_match(s, file_path, file_content)
            if string_info:
                matched_strings.append(string_info)
        
        return matched_strings[:10]  # Limit to 10 matches
    
    def _needs_file_content(self, s: Any) -> bool:
        """Check if string match needs file content for line numbers"""
        if isinstance(s, tuple):
            # pre-4.3: (<offset>, <identifier>, <data>)
            offset = s[0]
            return offset is not None
        else:
            # post-4.3: yara.StringMatch
            if s.instances:
                return s.instances[0].offset is not None
            return False
    
    def _parse_string_match(self, s: Any, file_path: Path, 
                           file_content: Optional[str]) -> Dict:
        """Parse a single string match"""
        # Handle different YARA versions
        if isinstance(s, tuple):
            # pre-4.3: (<offset>, <identifier>, <data>)
            offset, identifier, data = s
        else:
            # post-4.3: yara.StringMatch
            identifier = s.identifier
            if s.instances:
                inst = s.instances[0]
                offset = inst.offset
                data = inst.matched_data
            else:
                offset = None
                data = None
        
        # Get line information if possible
        line_number, line_content = self._get_line_info(
            file_path, offset, file_content
        )
        
        return {
            'offset': offset,
            'line': line_number,
            'line_content': line_content,
            'identifier': identifier,
            'content': data[:100] if data else ''  # Truncate to 100 chars
        }
    
    def _get_line_info(self, file_path: Path, offset: Optional[int], 
                      file_content: Optional[str]) -> tuple:
        """Get line number and content for offset"""
        if offset is None:
            return None, None
        
        try:
            if file_content is None:
                file_content = self._load_file_content(file_path)
            
            if file_content:
                # Count newlines up to offset
                line_number = file_content[:offset].count('\n') + 1
                
                # Get line content
                lines = file_content.split('\n')
                if 0 < line_number <= len(lines):
                    line_content = lines[line_number - 1].strip()
                    return line_number, line_content
                    
        except Exception as e:
            logger.debug(f"Could not determine line info: {e}")
        
        return None, None
    
    def _load_file_content(self, file_path: Path) -> Optional[str]:
        """Load file content for line number calculation"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
    
    def _build_location(self, relative_path: Path, matched_strings: List[Dict]) -> str:
        """Build location string with line number if available"""
        location = str(relative_path)
        
        if matched_strings and matched_strings[0].get('line'):
            location = f"{relative_path}:{matched_strings[0]['line']}"
        
        return location
    
    def _build_description(self, match: Any, meta: Dict) -> str:
        """Build finding description"""
        description = meta.get('description', f'YARA rule {match.rule} matched')
        
        if 'details' in meta:
            description += f"\n\nDetails: {meta['details']}"
        
        return description
    
    def _build_evidence(self, match: Any, meta: Dict, 
                       matched_strings: List[Dict]) -> Dict:
        """Build evidence dictionary"""
        return {
            'rule': match.rule,
            'namespace': match.namespace,
            'tags': match.tags,
            'meta': dict(meta),
            'matched_strings': matched_strings
        }
    
    def _determine_severity(self, meta: Dict[str, Any]) -> SeverityLevel:
        """Determine severity from rule metadata"""
        severity_str = meta.get('severity', 'medium').lower()
        
        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }
        
        return severity_map.get(severity_str, SeverityLevel.MEDIUM)
    
    def _determine_vuln_type(self, meta: Dict[str, Any]) -> VulnerabilityType:
        """Determine vulnerability type from rule metadata"""
        category = meta.get('category', '').lower()
        
        type_map = {
            'malware': VulnerabilityType.MALWARE,
            'backdoor': VulnerabilityType.BACKDOOR,
            'trojan': VulnerabilityType.BACKDOOR,
            'injection': VulnerabilityType.COMMAND_INJECTION,
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'xss': VulnerabilityType.XSS,
            'credential': VulnerabilityType.HARDCODED_SECRET,
            'secret': VulnerabilityType.HARDCODED_SECRET,
            'crypto': VulnerabilityType.WEAK_CRYPTO,
            'permission': VulnerabilityType.PRIVILEGE_ESCALATION,
            'path_traversal': VulnerabilityType.PATH_TRAVERSAL,
            'mcp_threats': VulnerabilityType.MCP_SPECIFIC,
            'prompt_injection': VulnerabilityType.PROMPT_INJECTION,
            'tool_manipulation': VulnerabilityType.TOOL_MANIPULATION
        }
        
        return type_map.get(category, VulnerabilityType.GENERIC)
    
    def _extract_references(self, meta: Dict[str, Any]) -> List[str]:
        """Extract references from rule metadata"""
        references = []
        
        # Add author info if available
        if 'author' in meta:
            references.append(f"Rule author: {meta['author']}")
        
        # Add any URLs in metadata
        for key, value in meta.items():
            if isinstance(value, str) and value.startswith(('http://', 'https://')):
                references.append(value)
        
        return references