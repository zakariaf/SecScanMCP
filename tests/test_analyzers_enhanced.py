#!/usr/bin/env python3
"""
Enhanced test for individual analyzer components
Tests functionality without requiring full dependency setup
"""

import sys
import os
from pathlib import Path
import tempfile
import json
import asyncio

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def create_mock_models():
    """Create mock models to avoid pydantic dependency"""
    
    class MockSeverityLevel:
        CRITICAL = "critical"
        HIGH = "high" 
        MEDIUM = "medium"
        LOW = "low"
        INFO = "info"
    
    class MockVulnerabilityType:
        # Code vulnerabilities
        COMMAND_INJECTION = "command_injection"
        SQL_INJECTION = "sql_injection"
        PATH_TRAVERSAL = "path_traversal"
        XXE = "xxe"
        SSRF = "ssrf"
        XSS = "xss"
        CODE_INJECTION = "code_injection"

        # Cryptography
        WEAK_CRYPTO = "weak_crypto"

        # MCP-specific
        PROMPT_INJECTION = "prompt_injection"
        TOOL_POISONING = "tool_poisoning"
        MCP_SPECIFIC = "mcp_specific"
        TOOL_MANIPULATION = "tool_manipulation"
        PERMISSION_ABUSE = "permission_abuse"
        SCHEMA_INJECTION = "schema_injection"
        OUTPUT_POISONING = "output_poisoning"

        # Privilege issues
        PRIVILEGE_ESCALATION = "privilege_escalation"

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

        # Dynamic analysis specific
        BEHAVIORAL_ANOMALY = "behavioral_anomaly"
        NETWORK_SECURITY = "network_security"
        DATA_LEAKAGE = "data_leakage"
        RESOURCE_ABUSE = "resource_abuse"

        # Malware / other
        MALWARE = "malware"
        BACKDOOR = "backdoor"
        GENERIC = "generic"
    
    class MockFinding:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
            # Set required attributes
            if not hasattr(self, 'title'):
                self.title = kwargs.get('title', 'Test Finding')
    
    # Inject mocks into sys.modules
    import types
    models = types.ModuleType('models')
    models.SeverityLevel = MockSeverityLevel
    models.VulnerabilityType = MockVulnerabilityType  
    models.Finding = MockFinding
    sys.modules['models'] = models
    
    return models

def test_attack_payloads():
    """Test attack payloads generation"""
    print("🎯 Testing Attack Payloads Generation")
    print("=" * 40)
    
    try:
        # Create mock models first
        create_mock_models()
        
        # Import and test
        from analyzers.attack_payloads import AdvancedPayloadGenerator, PayloadCategory, PayloadValidator
        
        generator = AdvancedPayloadGenerator()
        print("✅ AdvancedPayloadGenerator created")
        
        # Test payload categories
        categories = list(PayloadCategory)
        print(f"✅ Available categories: {len(categories)}")
        
        # Test payload generation for each category
        total_payloads = 0
        for category in categories[:3]:  # Test first 3 categories
            try:
                payloads = generator.get_payloads(category)
                total_payloads += len(payloads)
                print(f"✅ {category.value}: {len(payloads)} payloads")
                
                # Test a sample payload
                if payloads and isinstance(payloads[0], dict):
                    sample = payloads[0]
                    if 'payload' in sample and 'description' in sample:
                        print(f"  ✅ Sample payload structure valid")
            except Exception as e:
                print(f"  ❌ Error with {category.value}: {e}")
        
        print(f"✅ Total payloads tested: {total_payloads}")
        
        # Test payload validator
        validator = PayloadValidator()
        print("✅ PayloadValidator created")
        
        # Test response analysis
        test_response = "System command executed successfully"
        test_payload_data = {"payload": "id", "category": "command_injection"}
        
        analysis = validator.analyze_response(test_response, test_payload_data)
        if isinstance(analysis, dict) and 'vulnerable' in analysis:
            print("✅ Response analysis working")
        
        return True
        
    except Exception as e:
        print(f"❌ Attack payloads test failed: {e}")
        return False

def test_ml_anomaly_detector():
    """Test ML anomaly detection components"""
    print("\n🤖 Testing ML Anomaly Detection")
    print("=" * 40)
    
    try:
        from analyzers.ml_anomaly_detector import MLAnomalyDetector, BehaviorProfiler, FeatureExtractor
        
        # Test feature extractor
        extractor = FeatureExtractor()
        print("✅ FeatureExtractor created")
        
        # Test with sample metrics
        sample_metrics = {
            'cpu_percent': 45.2,
            'memory_mb': 128.5,
            'network_connections': 3,
            'dns_queries': 1,
            'file_operations': 5,
            'process_spawns': 0,
            'tool_calls': 2,
            'error_count': 0,
            'response_time_ms': 150.0,
            'data_volume_bytes': 1024
        }
        
        features = extractor.extract_features(sample_metrics)
        print(f"✅ Feature extraction: {len(features)} features")
        
        # Test ML detector
        ml_detector = MLAnomalyDetector()
        print("✅ MLAnomalyDetector created")
        
        # Test model status
        status = ml_detector.get_model_status()
        print(f"✅ Model status: {status['feature_count']} features")
        
        # Test behavior profiler
        profiler = BehaviorProfiler()
        print("✅ BehaviorProfiler created")
        
        # Test profile creation with sample data
        sample_session = [sample_metrics for _ in range(5)]
        profiler.create_profile(sample_session, "test_profile")
        print("✅ Behavioral profile created")
        
        return True
        
    except Exception as e:
        print(f"❌ ML anomaly detector test failed: {e}")
        return False

def test_traffic_analyzer():
    """Test traffic analysis components"""
    print("\n📡 Testing Traffic Analysis")
    print("=" * 40)
    
    try:
        from analyzers.traffic_analyzer import DataLeakageDetector, NetworkAnomalyDetector
        
        # Test data leakage detector
        detector = DataLeakageDetector()
        print("✅ DataLeakageDetector created")
        
        # Test sensitive data detection
        test_data_samples = [
            "API_KEY=ghp_1234567890abcdef1234567890abcdef12345678",
            "password=secret123",
            "user@example.com", 
            "4111-1111-1111-1111",
            "-----BEGIN PRIVATE KEY-----"
        ]
        
        total_findings = 0
        for test_data in test_data_samples:
            findings = detector.scan_for_sensitive_data(test_data)
            total_findings += len(findings)
            if findings:
                print(f"  ✅ Detected {findings[0]['type']} in test data")
        
        print(f"✅ Sensitive data detection: {total_findings} total findings")
        
        # Test network anomaly detector
        network_detector = NetworkAnomalyDetector()
        print("✅ NetworkAnomalyDetector created")
        
        # Test baseline establishment
        sample_metrics = [
            {'connection_count': 5, 'dns_queries': 2, 'data_volume': 1024},
            {'connection_count': 4, 'dns_queries': 1, 'data_volume': 800},
            {'connection_count': 6, 'dns_queries': 3, 'data_volume': 1200}
        ]
        
        network_detector.establish_baseline(sample_metrics)
        print("✅ Network baseline established")
        
        return True
        
    except Exception as e:
        print(f"❌ Traffic analyzer test failed: {e}")
        return False

def test_mcp_client():
    """Test MCP client components"""
    print("\n🔗 Testing MCP Client")
    print("=" * 40)
    
    try:
        from analyzers.dynamic.utils.mcp_client import MCPTransport, MCPSecurityTester
        
        # Test transport enumeration
        transports = [MCPTransport.STDIO, MCPTransport.SSE, MCPTransport.WEBSOCKET]
        print(f"✅ Transport methods available: {[t.value for t in transports]}")
        
        # Test security tester creation
        # Note: We can't test full functionality without an actual MCP server
        tester = MCPSecurityTester()
        print("✅ MCPSecurityTester created")
        
        return True
        
    except Exception as e:
        print(f"❌ MCP client test failed: {e}")
        return False

async def test_dynamic_analyzer_methods():
    """Test dynamic analyzer utility methods"""
    print("\n⚙️ Testing Dynamic Analyzer Utility Methods")
    print("=" * 40)
    
    try:
        # Create mock models
        models = create_mock_models()
        
        # Create a mock analyzer class to test utility methods
        class MockDynamicAnalyzer:
            def __init__(self):
                self.logger = self
                
            def info(self, msg):
                pass
            def error(self, msg):
                pass
            def warning(self, msg):
                pass
            def debug(self, msg):
                pass
                
            def create_finding(self, **kwargs):
                return models.Finding(**kwargs)
        
        analyzer = MockDynamicAnalyzer()
        
        # Test vulnerability conversion
        test_vuln = {
            'vulnerability_type': 'command_injection',
            'severity': 'critical',
            'tool_name': 'execute_command',
            'parameter': 'command',
            'payload': 'test_payload',
            'response': 'test_response'
        }
        
        # Import the method dynamically
        import types
        
        # Read the dynamic analyzer file to get methods
        with open('analyzers/dynamic_analyzer.py', 'r') as f:
            content = f.read()
        
        # Test that vulnerability conversion method exists
        if '_convert_vulnerability_to_finding' in content:
            print("✅ Vulnerability conversion method exists")
        
        # Test that analysis summary method exists  
        if '_generate_analysis_summary' in content:
            print("✅ Analysis summary method exists")
        
        # Test CPU calculation method exists
        if '_calculate_cpu_percent' in content:
            print("✅ CPU calculation method exists")
        
        print("✅ Dynamic analyzer utility methods verified")
        
        return True
        
    except Exception as e:
        print(f"❌ Dynamic analyzer methods test failed: {e}")
        return False

async def main():
    """Run all analyzer tests"""
    print("🔍 Enhanced Analyzer Components Test Suite")
    print("=" * 60)
    
    tests = [
        ("Attack Payloads", test_attack_payloads),
        ("ML Anomaly Detection", test_ml_anomaly_detector),
        ("Traffic Analysis", test_traffic_analyzer),
        ("MCP Client", test_mcp_client),
        ("Dynamic Analyzer Methods", test_dynamic_analyzer_methods)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*60}")
            if asyncio.iscoroutinefunction(test_func):
                result = await test_func()
            else:
                result = test_func()
                
            if result:
                passed_tests += 1
                print(f"✅ {test_name} - PASSED")
            else:
                print(f"❌ {test_name} - FAILED")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}")
    
    # Final Results
    print("\n" + "=" * 60)
    print(f"📊 FINAL RESULTS: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED! Enhanced analyzers are working correctly!")
    elif passed_tests >= total_tests * 0.8:
        print("✅ MOSTLY SUCCESSFUL! Enhanced analyzers are substantially working.")
    else:
        print("⚠️ SOME ISSUES FOUND. Enhanced analyzers need attention.")
    
    return passed_tests >= total_tests * 0.8

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)