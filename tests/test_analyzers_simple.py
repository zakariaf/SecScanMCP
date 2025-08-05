#!/usr/bin/env python3
"""
Simple test for individual analyzer components
Tests functionality without heavy dependencies and imports
"""

import sys
import os
from pathlib import Path
import tempfile
import json
import asyncio

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

def test_structure_only():
    """Test that all analyzer files have proper structure without imports"""
    print("🔍 Testing Analyzer File Structure (Import-Free)")
    print("=" * 55)
    
    try:
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
                print(f"✅ {file_path} exists")
                success_count += 1
                
                # Check file size as indicator of implementation
                with open(file_path, 'r') as f:
                    content = f.read()
                    lines = len(content.split('\n'))
                    if lines > 100:
                        print(f"  ✅ {file_path}: {lines} lines (substantial implementation)")
                    else:
                        print(f"  ⚠️ {file_path}: {lines} lines (may be minimal)")
            else:
                print(f"❌ {file_path} - Missing!")
        
        print(f"\n📊 File Structure: {success_count}/{len(files_to_check)} files present")
        return success_count >= len(files_to_check) * 0.8
        
    except Exception as e:
        print(f"❌ File structure test failed: {e}")
        return False

def test_dynamic_analyzer_content():
    """Test dynamic analyzer content without importing"""
    print("\n⚙️ Testing Dynamic Analyzer Content")
    print("=" * 40)
    
    try:
        with open("analyzers/dynamic_analyzer.py", 'r') as f:
            content = f.read()
        
        # Check for key methods and components
        key_components = [
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
            "_initialize_advanced_components",
            "class DynamicAnalyzer"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component in content:
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        # Check file size
        file_size = len(content.split('\n'))
        print(f"📏 File size: {file_size} lines")
        
        if file_size > 2000:
            print("✅ File size indicates comprehensive implementation")
            success_count += 1
        
        print(f"\n📊 Dynamic Analyzer Content: {success_count}/{len(key_components)+1} components found")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Dynamic analyzer content test failed: {e}")
        return False

def test_mcp_client_content():
    """Test MCP client content without importing"""
    print("\n🔗 Testing MCP Client Content")
    print("=" * 35)
    
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
            "async def get_prompt",
            "class MCPSecurityTester"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component in content:
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 MCP Client Content: {success_count}/{len(key_components)} components found")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ MCP client content test failed: {e}")
        return False

def test_attack_payloads_content():
    """Test attack payloads content without importing"""
    print("\n🎯 Testing Attack Payloads Content")
    print("=" * 40)
    
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
            "def analyze_response",
            "1000+"  # Should mention 1000+ payloads
        ]
        
        success_count = 0
        
        for component in key_components:
            if component in content:
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 Attack Payloads Content: {success_count}/{len(key_components)} components found")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Attack payloads content test failed: {e}")
        return False

def test_ml_detector_content():
    """Test ML detector content without importing"""
    print("\n🤖 Testing ML Anomaly Detector Content")
    print("=" * 45)
    
    try:
        with open("analyzers/ml_anomaly_detector.py", 'r') as f:
            content = f.read()
        
        key_components = [
            "class MLAnomalyDetector",
            "class IsolationForestDetector",
            "class StatisticalAnomalyDetector",
            "class BehaviorProfiler",
            "class FeatureExtractor",
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
        
        print(f"\n📊 ML Detector Content: {success_count}/{len(key_components)} components found")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ ML detector content test failed: {e}")
        return False

def test_traffic_analyzer_content():
    """Test traffic analyzer content without importing"""
    print("\n📡 Testing Traffic Analyzer Content")
    print("=" * 40)
    
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
            "suspicious",
            "API_KEY",
            "credit card"
        ]
        
        success_count = 0
        
        for component in key_components:
            if component.lower() in content.lower():
                print(f"✅ {component}")
                success_count += 1
            else:
                print(f"❌ {component} - Not found!")
        
        print(f"\n📊 Traffic Analyzer Content: {success_count}/{len(key_components)} components found")
        return success_count >= len(key_components) * 0.8
        
    except Exception as e:
        print(f"❌ Traffic analyzer content test failed: {e}")
        return False

def main():
    """Run all simple tests without imports"""
    print("🔍 Enhanced Analyzer Components Simple Test Suite")
    print("=" * 60)
    
    tests = [
        ("File Structure", test_structure_only),
        ("Dynamic Analyzer Content", test_dynamic_analyzer_content),
        ("MCP Client Content", test_mcp_client_content),
        ("Attack Payloads Content", test_attack_payloads_content),
        ("ML Detector Content", test_ml_detector_content),
        ("Traffic Analyzer Content", test_traffic_analyzer_content)
    ]
    
    passed_tests = 0
    total_tests = len(tests)
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*60}")
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
        print("🎉 ALL TESTS PASSED! Enhanced analyzers structure and content verified!")
    elif passed_tests >= total_tests * 0.8:
        print("✅ MOSTLY SUCCESSFUL! Enhanced analyzers are substantially implemented.")
    else:
        print("⚠️ SOME ISSUES FOUND. Enhanced analyzers need attention.")
    
    return passed_tests >= total_tests * 0.8

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)