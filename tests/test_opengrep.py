#!/usr/bin/env python3
"""
Quick test to verify OpenGrep analyzer works correctly
"""

import tempfile
import asyncio
from pathlib import Path
from analyzers.opengrep_analyzer import OpenGrepAnalyzer

async def test_opengrep_analyzer():
    """Test OpenGrep analyzer with a simple vulnerable file"""
    
    # Create a test file with a known vulnerability
    test_code = '''
# Test file with intentional vulnerabilities
import os

def vulnerable_function(user_input):
    # This should trigger command injection detection
    os.system(user_input)
    
    # This should trigger hardcoded secret detection
    api_key = "sk-1234567890abcdef"
    oauth_token = "ya29.A0ARrdaM91xSampleTokenHere123456789"
    
    return "done"

@tool
def mcp_tool(params):
    command = params.get('command', '')
    # This should trigger MCP-specific command injection
    os.system(command)
'''

    with tempfile.TemporaryDirectory() as temp_dir:
        # Write test file
        test_file = Path(temp_dir) / "test_vulnerable.py"
        test_file.write_text(test_code)
        
        # Initialize analyzer
        analyzer = OpenGrepAnalyzer()
        
        # Run analysis
        try:
            findings = await analyzer.analyze(temp_dir, {'language': 'python'})
            
            print(f"✅ OpenGrep analyzer test completed")
            print(f"📊 Found {len(findings)} vulnerabilities")
            
            if findings:
                print("\n🔍 Sample findings:")
                for i, finding in enumerate(findings[:3], 1):
                    print(f"  {i}. {finding.severity.value.upper()}: {finding.title}")
                    print(f"     Type: {finding.vulnerability_type.value}")
                    print(f"     Tool: {finding.tool}")
                    print()
            
            return len(findings) > 0
            
        except Exception as e:
            print(f"❌ OpenGrep analyzer test failed: {e}")
            return False

if __name__ == "__main__":
    success = asyncio.run(test_opengrep_analyzer())
    if success:
        print("🎉 OpenGrep analyzer is working!")
    else:
        print("⚠️ OpenGrep analyzer needs attention")