#!/usr/bin/env python3
"""
Test suite for attack payload generation
Verifies we have 1000+ unique attack payloads through variation generation
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import unittest
from analyzers.attack_payloads import AdvancedPayloadGenerator, PayloadCategory, PayloadValidator


class TestAttackPayloads(unittest.TestCase):
    """Test attack payload generation and validation"""
    
    def setUp(self):
        """Initialize payload generator"""
        self.generator = AdvancedPayloadGenerator()
        self.validator = PayloadValidator()
    
    def test_base_payload_counts(self):
        """Test that we have sufficient base payloads for each category"""
        min_payloads_per_category = 10
        
        for category in PayloadCategory:
            payloads = self.generator.get_payloads(category)
            self.assertGreaterEqual(
                len(payloads),
                min_payloads_per_category,
                f"Category {category.value} has only {len(payloads)} base payloads"
            )
    
    def test_payload_structure(self):
        """Test that all payloads have required fields"""
        required_fields = ['payload', 'expected_indicators', 'severity', 'description']
        
        for category in PayloadCategory:
            payloads = self.generator.get_payloads(category)
            for payload in payloads:
                for field in required_fields:
                    self.assertIn(field, payload, f"Payload missing field: {field}")
                
                # Validate severity levels
                self.assertIn(
                    payload['severity'],
                    ['critical', 'high', 'medium', 'low'],
                    f"Invalid severity: {payload['severity']}"
                )
                
                # Ensure expected_indicators is a list
                self.assertIsInstance(
                    payload['expected_indicators'],
                    list,
                    "expected_indicators must be a list"
                )
    
    def test_encoding_methods(self):
        """Test all encoding methods work correctly"""
        test_payload = "SELECT * FROM users WHERE id='1'"
        encodings = ["url", "double_url", "base64", "hex", "unicode", "html_entity", "mixed"]
        
        for encoding in encodings:
            encoded = self.generator.encode_payload(test_payload, encoding)
            self.assertIsNotNone(encoded, f"Encoding {encoding} returned None")
            self.assertNotEqual(encoded, test_payload, f"Encoding {encoding} didn't change payload")
    
    def test_mutation_variants(self):
        """Test payload mutation generation"""
        test_payload = "'; DROP TABLE users; --"
        variants = self.generator.generate_mutation_variants(test_payload, 20)
        
        # Should generate multiple unique variants
        self.assertGreater(len(variants), 5, "Not enough mutation variants generated")
        
        # All variants should be unique
        self.assertEqual(len(variants), len(set(variants)), "Duplicate variants found")
        
        # Original should be in variants
        self.assertIn(test_payload, variants, "Original payload not in variants")
    
    def test_1000_plus_unique_payloads(self):
        """Test that we can generate 1000+ unique payloads"""
        counts = self.generator.get_payload_count()
        
        print("\n" + "="*60)
        print("PAYLOAD GENERATION STATISTICS")
        print("="*60)
        
        # Print counts per category
        for category, count in sorted(counts.items()):
            if category != 'total':
                print(f"{category:25s}: {count:4d} unique payloads")
        
        print("-"*60)
        print(f"{'TOTAL UNIQUE PAYLOADS':25s}: {counts['total']:4d}")
        print("="*60)
        
        # Assert we have 1000+ total payloads
        self.assertGreaterEqual(
            counts['total'],
            1000,
            f"Only generated {counts['total']} unique payloads (target: 1000+)"
        )
    
    def test_dynamic_payload_generation(self):
        """Test context-aware dynamic payload generation"""
        # Test with file-related context
        file_context = {
            'tool_name': 'read_file',
            'param_name': 'path',
            'param_type': 'string'
        }
        
        payload = self.generator.generate_dynamic_payload(
            PayloadCategory.PATH_TRAVERSAL,
            file_context
        )
        
        self.assertIsNotNone(payload)
        self.assertIn('payload', payload)
        
        # Test with execution context
        exec_context = {
            'tool_name': 'execute_command',
            'param_name': 'cmd',
            'param_type': 'string'
        }
        
        payload = self.generator.generate_dynamic_payload(
            PayloadCategory.COMMAND_INJECTION,
            exec_context
        )
        
        self.assertIsNotNone(payload)
        self.assertIn('payload', payload)
    
    def test_payload_validation(self):
        """Test payload response validation"""
        # Test positive case - vulnerability detected
        test_payload = {
            "payload": "'; DROP TABLE users; --",
            "expected_indicators": ["drop", "table", "users"],
            "severity": "critical",
            "description": "SQL injection"
        }
        
        response = "Error: You have an error in your SQL syntax near 'DROP TABLE users'"
        result = self.validator.analyze_response(response, test_payload)
        
        self.assertTrue(result['vulnerable'])
        self.assertGreater(result['confidence'], 0.5)
        self.assertIn('drop', result['matched_indicators'])
        
        # Test negative case - no vulnerability
        safe_response = "Query executed successfully"
        result = self.validator.analyze_response(safe_response, test_payload)
        
        self.assertFalse(result['vulnerable'])
        self.assertLess(result['confidence'], 0.3)
    
    def test_error_pattern_detection(self):
        """Test error pattern detection in responses"""
        error_response = """
        Traceback (most recent call last):
          File "app.py", line 42, in execute
            cursor.execute(query)
        mysql.connector.errors.ProgrammingError: SQL syntax error
        """
        
        errors = self.validator.detect_error_patterns(error_response)
        
        self.assertIn('traceback', errors)
        self.assertIn('sql syntax', errors)
        self.assertGreater(len(errors), 0)
    
    def test_polymorphic_payloads(self):
        """Test polymorphic payload generation"""
        polymorphic = self.generator._generate_polymorphic_payloads()
        
        # Should generate many variations
        self.assertGreater(len(polymorphic), 50, "Not enough polymorphic payloads")
        
        # Check for expected patterns
        has_command_injection = any(';' in p or '&&' in p for p in polymorphic)
        has_sql_injection = any("' OR" in p or "UNION" in p.upper() for p in polymorphic)
        has_xss = any('<script>' in p or 'alert(' in p for p in polymorphic)
        
        self.assertTrue(has_command_injection, "Missing command injection payloads")
        self.assertTrue(has_sql_injection, "Missing SQL injection payloads")
        self.assertTrue(has_xss, "Missing XSS payloads")
    
    def test_evasion_techniques(self):
        """Test evasion technique application"""
        test_payload = "SELECT * FROM users"
        
        for technique in self.generator.evasion_techniques:
            try:
                evaded = technique['transform'](test_payload)
                self.assertIsNotNone(evaded, f"Technique {technique['name']} returned None")
                # Some techniques might not change the payload visibly but add invisible chars
                self.assertTrue(len(evaded) >= len(test_payload), 
                              f"Technique {technique['name']} shortened payload")
            except Exception as e:
                self.fail(f"Technique {technique['name']} raised exception: {e}")


if __name__ == '__main__':
    # Run tests with verbose output
    unittest.main(verbosity=2)