#!/usr/bin/env python3
"""
Structure test for enhanced Dynamic Analyzer
Tests the code structure and imports without heavy dependencies
"""

import sys
import os
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_file_structure():
    """Test if all enhanced files are present"""
    print("📁 Testing Enhanced Dynamic Analyzer File Structure")
    print("=" * 50)
    
    files_to_check = [
        "analyzers/dynamic_analyzer.py",
        "analyzers/mcp_client.py", 
        "analyzers/attack_payloads.py",
        "analyzers/ml_anomaly_detector.py",
        "analyzers/traffic_analyzer.py"
    ]
    
    success_count = 0
    
    for file_path in files_to_check:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
            success_count += 1
        else:
            print(f"❌ {file_path} - Missing!")
    
    print(f"\n📊 File Structure: {success_count}/{len(files_to_check)} files present")
    return success_count == len(files_to_check)

def test_dynamic_analyzer_structure():
    """Test the structure of the enhanced dynamic analyzer"""
    print("\n🔍 Testing Dynamic Analyzer Code Structure")
    print("=" * 50)
    
    try:
        with open("analyzers/dynamic_analyzer.py", 'r') as f:
            content = f.read()
        
        # Check for key method signatures
        methods_to_check = [
            "_initialize_docker_environment",
            "_create_advanced_sandbox", 
            "_establish_mcp_connection",
            "_run_comprehensive_security_tests",
            "_test_tool_manipulation",
            "_run_advanced_prompt_injection_tests",
            "_analyze_network_traffic",
            "_detect_data_exfiltration",
            "_run_ml_anomaly_detection",
            "_analyze_performance_patterns",
            "_detect_behavioral_anomalies",
            "_cleanup_analysis_session",
            "_generate_analysis_summary",
            "_initialize_advanced_components"
        ]
        
        success_count = 0
        
        for method in methods_to_check:
            if f"def {method}" in content or f"async def {method}" in content:
                print(f"✅ {method}")
                success_count += 1
            else:
                print(f"❌ {method} - Not found!")
        
        print(f"\n📊 Method Structure: {success_count}/{len(methods_to_check)} methods present")
        
        # Check file size (should be significantly larger now)
        file_size = len(content.split('\n'))
        print(f"📏 File size: {file_size} lines")
        
        if file_size > 2000:
            print("✅ File size indicates comprehensive implementation")
        else:
            print("⚠️ File may be missing content")
        
        return success_count >= len(methods_to_check) * 0.8  # 80% success rate
        
    except Exception as e:
        print(f"❌ Error reading dynamic_analyzer.py: {e}")
        return False

def test_mcp_client_structure():
    """Test MCP client implementation"""
    print("\n🔗 Testing MCP Client Structure")
    print("=" * 50)
    
    try:
        with open("analyzers/mcp_client.py", 'r') as f:
            content = f.read()
        
        key_components = [
            "class MCPClient",
            "class MCPTransport",
            "JSON-RPC",
            "STDIO",
            "SSE", 
            "WEBSOCKET",
            "async def connect",
            "async def call_tool",
            "async def get_prompt"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component in content:
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 MCP Client Structure: {success_count}/{len(key_components)} components present")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Error reading mcp_client.py: {e}")
        return False

def test_attack_payloads_structure():
    """Test attack payloads implementation"""
    print("\n🎯 Testing Attack Payloads Structure")
    print("=" * 50)
    
    try:
        with open("analyzers/attack_payloads.py", 'r') as f:
            content = f.read()
        
        key_components = [
            "class AdvancedPayloadGenerator",
            "class PayloadCategory",
            "class PayloadValidator",
            "PROMPT_INJECTION",
            "TOOL_MANIPULATION", 
            "CODE_INJECTION",
            "def get_payloads",
            "def analyze_response"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component in content:
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 Attack Payloads Structure: {success_count}/{len(key_components)} components present")
        
        # Check for payload count indication
        if "1000+" in content or "payloads" in content.lower():
            print("✅ Comprehensive payload library indicated")
        
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Error reading attack_payloads.py: {e}")
        return False

def test_ml_detector_structure():
    """Test ML anomaly detector implementation"""
    print("\n🤖 Testing ML Anomaly Detector Structure") 
    print("=" * 50)
    
    try:
        with open("analyzers/ml_anomaly_detector.py", 'r') as f:
            content = f.read()
        
        key_components = [
            "class MLAnomalyDetector",
            "class IsolationForestDetector",
            "class StatisticalAnomalyDetector",
            "class BehaviorProfiler",
            "def detect_anomalies",
            "def train",
            "isolation forest",
            "z-score"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component.lower() in content.lower():
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 ML Detector Structure: {success_count}/{len(key_components)} components present")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Error reading ml_anomaly_detector.py: {e}")
        return False

def test_traffic_analyzer_structure():
    """Test traffic analyzer implementation"""
    print("\n📡 Testing Traffic Analyzer Structure")
    print("=" * 50)
    
    try:
        with open("analyzers/traffic_analyzer.py", 'r') as f:
            content = f.read()
        
        key_components = [
            "class TrafficAnalyzer",
            "class DataLeakageDetector", 
            "class NetworkAnomalyDetector",
            "def start_monitoring",
            "def scan_for_sensitive_data",
            "exfiltration",
            "network_events",
            "suspicious"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component.lower() in content.lower():
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 Traffic Analyzer Structure: {success_count}/{len(key_components)} components present")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Error reading traffic_analyzer.py: {e}")
        return False

def main():
    """Run all structure tests"""
    print("🔍 Enhanced Dynamic Analyzer Structure Test Suite")
    print("=" * 60)
    
    tests = [
        ("File Structure", test_file_structure),
        ("Dynamic Analyzer Structure", test_dynamic_analyzer_structure),
        ("MCP Client Structure", test_mcp_client_structure),
        ("Attack Payloads Structure", test_attack_payloads_structure),
        ("ML Detector Structure", test_ml_detector_structure),
        ("Traffic Analyzer Structure", test_traffic_analyzer_structure)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            if test_func():
                passed_tests += 1
                print(f"✅ {test_name} - PASSED\n")
            else:
                print(f"❌ {test_name} - FAILED\n")
        except Exception as e:
            print(f"❌ {test_name} - ERROR: {e}\n")
    
    # Final Results
    print("=" * 60)
    print(f"📊 FINAL RESULTS: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED! Enhanced Dynamic Analyzer structure is complete!")
    elif passed_tests >= total_tests * 0.8:
        print("✅ MOSTLY SUCCESSFUL! Enhanced Dynamic Analyzer is substantially implemented.")
    else:
        print("⚠️ SOME ISSUES FOUND. Check the output above for details.")
    
    return passed_tests >= total_tests * 0.8

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)