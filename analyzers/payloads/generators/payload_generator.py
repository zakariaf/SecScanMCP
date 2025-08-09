"""Main payload generator service."""

import random
import string
import base64
from typing import List, Dict, Any, Optional
from enum import Enum

from ..categories.prompt_injection import PromptInjectionPayloads
from ..categories.command_injection import CommandInjectionPayloads
from ..categories.path_traversal import PathTraversalPayloads
from ..categories.code_injection import CodeInjectionPayloads
from ..categories.sql_injection import SQLInjectionPayloads
from ..categories.xss import XSSPayloads
from ..categories.tool_manipulation import ToolManipulationPayloads
from ..categories.data_exfiltration import DataExfiltrationPayloads
from ..categories.privilege_escalation import PrivilegeEscalationPayloads


class PayloadCategory(Enum):
    """Payload categories - ALL 9 CATEGORIES."""
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection" 
    PATH_TRAVERSAL = "path_traversal"
    CODE_INJECTION = "code_injection"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    TOOL_MANIPULATION = "tool_manipulation"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class PayloadGenerator:
    """Generates security test payloads for MCP testing."""
    
    def __init__(self):
        self.category_map = {
            PayloadCategory.PROMPT_INJECTION: PromptInjectionPayloads,
            PayloadCategory.COMMAND_INJECTION: CommandInjectionPayloads,
            PayloadCategory.PATH_TRAVERSAL: PathTraversalPayloads,
            PayloadCategory.CODE_INJECTION: CodeInjectionPayloads,
            PayloadCategory.SQL_INJECTION: SQLInjectionPayloads,
            PayloadCategory.XSS: XSSPayloads,
            PayloadCategory.TOOL_MANIPULATION: ToolManipulationPayloads,
            PayloadCategory.DATA_EXFILTRATION: DataExfiltrationPayloads,
            PayloadCategory.PRIVILEGE_ESCALATION: PrivilegeEscalationPayloads,
        }
    
    def get_payloads_by_category(self, category: PayloadCategory) -> List[Dict[str, Any]]:
        """
        Get payloads for specific category.
        
        Args:
            category: Payload category
            
        Returns:
            List of payloads
        """
        if category in self.category_map:
            return self.category_map[category].get_all_payloads()
        return []
    
    def get_payloads_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """
        Get payloads filtered by severity.
        
        Args:
            severity: Severity level (critical, high, medium, low)
            
        Returns:
            List of payloads matching severity
        """
        all_payloads = self.get_all_payloads()
        return [p for p in all_payloads if p.get('severity') == severity]
    
    def get_random_payloads(self, count: int = 10,
                           category: Optional[PayloadCategory] = None) -> List[Dict[str, Any]]:
        """
        Get random payloads for testing.
        
        Args:
            count: Number of payloads to return
            category: Optional category filter
            
        Returns:
            Random selection of payloads
        """
        if category:
            payloads = self.get_payloads_by_category(category)
        else:
            payloads = self.get_all_payloads()
        
        return random.sample(payloads, min(count, len(payloads)))
    
    def get_all_payloads(self) -> List[Dict[str, Any]]:
        """Get all available payloads."""
        all_payloads = []
        
        for category_class in self.category_map.values():
            all_payloads.extend(category_class.get_all_payloads())
        
        return all_payloads
    
    def generate_variations(self, base_payload: str,
                           count: int = 5) -> List[Dict[str, Any]]:
        """
        Generate variations of a base payload.
        
        Args:
            base_payload: Base payload to vary
            count: Number of variations
            
        Returns:
            List of payload variations
        """
        variations = []
        
        for i in range(count):
            variation = self._apply_random_variation(base_payload)
            variations.append({
                "payload": variation,
                "description": f"Variation {i+1} of base payload",
                "severity": "medium",
                "technique": "automated_variation",
                "base_payload": base_payload
            })
        
        return variations
    
    def _apply_random_variation(self, payload: str) -> str:
        """Apply random variation technique to payload."""
        techniques = [
            self._case_variation,
            self._whitespace_variation,
            self._encoding_variation,
        ]
        
        technique = random.choice(techniques)
        return technique(payload)
    
    def _case_variation(self, payload: str) -> str:
        """Apply random case variation."""
        result = ""
        for char in payload:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
    
    def _whitespace_variation(self, payload: str) -> str:
        """Add random whitespace variations."""
        whitespace_chars = [' ', '\t', '\n']
        words = payload.split()
        
        result = []
        for word in words:
            result.append(word)
            if random.choice([True, False]):
                result.append(random.choice(whitespace_chars))
        
        return ''.join(result)
    
    def _encoding_variation(self, payload: str) -> str:
        """Apply encoding variation."""
        if random.choice([True, False]):
            # URL encode some characters
            encoded = ""
            for char in payload:
                if char in ['<', '>', '"', "'", '&'] and random.choice([True, False]):
                    encoded += f"%{ord(char):02x}"
                else:
                    encoded += char
            return encoded
        else:
            # Base64 encode (partial)
            if len(payload) > 10:
                start = random.randint(0, 5)
                end = start + random.randint(5, min(10, len(payload) - start))
                part = payload[start:end]
                b64_part = base64.b64encode(part.encode()).decode()
                return payload[:start] + b64_part + payload[end:]
        
        return payload