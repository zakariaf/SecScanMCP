"""Main payload library interface."""

from typing import List, Dict, Any, Optional

from .generators.payload_generator import PayloadGenerator, PayloadCategory


class AdvancedPayloadGenerator:
    """
    Main interface for advanced payload generation.
    
    Clean architecture replacement for the monolithic attack_payloads.py.
    Provides organized access to security testing payloads.
    """
    
    def __init__(self):
        self.generator = PayloadGenerator()
    
    def get_all_payloads(self) -> Dict[str, List[Dict[str, Any]]]:
        """
        Get all payloads organized by category.
        
        Returns:
            Dictionary with categories as keys and payload lists as values
        """
        result = {}
        
        for category in PayloadCategory:
            result[category.value] = self.generator.get_payloads_by_category(category)
        
        return result
    
    def get_critical_payloads(self) -> List[Dict[str, Any]]:
        """Get only critical severity payloads."""
        return self.generator.get_payloads_by_severity('critical')
    
    def get_testing_suite(self, count: int = 50) -> List[Dict[str, Any]]:
        """
        Get a balanced testing suite of payloads.
        
        Args:
            count: Total number of payloads
            
        Returns:
            Balanced selection of payloads for testing
        """
        # Get proportional samples from each category
        per_category = count // len(PayloadCategory)
        remaining = count % len(PayloadCategory)
        
        test_payloads = []
        
        for i, category in enumerate(PayloadCategory):
            category_count = per_category + (1 if i < remaining else 0)
            category_payloads = self.generator.get_random_payloads(
                category_count, category
            )
            test_payloads.extend(category_payloads)
        
        return test_payloads
    
    def generate_variations(self, base_payload: str,
                           count: int = 10) -> List[Dict[str, Any]]:
        """Generate variations of a specific payload."""
        return self.generator.generate_variations(base_payload, count)
    
    def get_prompt_injection_payloads(self) -> List[Dict[str, Any]]:
        """Get prompt injection specific payloads."""
        return self.generator.get_payloads_by_category(
            PayloadCategory.PROMPT_INJECTION
        )
    
    def get_command_injection_payloads(self) -> List[Dict[str, Any]]:
        """Get command injection specific payloads."""
        return self.generator.get_payloads_by_category(
            PayloadCategory.COMMAND_INJECTION
        )
    
    def get_path_traversal_payloads(self) -> List[Dict[str, Any]]:
        """Get path traversal specific payloads."""
        return self.generator.get_payloads_by_category(
            PayloadCategory.PATH_TRAVERSAL
        )