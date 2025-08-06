#!/usr/bin/env python3
"""
Test script for MCP Security Scanner using local vulnerable examples
"""

import os
import tempfile
import shutil
import subprocess
import requests
import json
import time
from pathlib import Path

def test_local_examples():
    """Test scanner with local vulnerable examples"""
    
    examples_dir = Path(__file__).parent / "examples"
    scanner_url = "http://localhost:8000"
    
    print("🔍 Testing MCP Security Scanner with Local Examples")
    print("=" * 60)
    
    # Check if scanner is running
    try:
        health = requests.get(f"{scanner_url}/health", timeout=5)
        print(f"✅ Scanner is running: {health.json()['status']}")
    except Exception as e:
        print(f"❌ Scanner not accessible: {e}")
        print("💡 Start the scanner first: make restart")
        return False
    
    test_files = [
        "vulnerable-mcp-server.py",
        "vulnerable-mcp-server.js", 
        "test_vulnerable_mcp.js"
    ]
    
    results = {}
    
    for test_file in test_files:
        file_path = examples_dir / test_file
        if not file_path.exists():
            print(f"⚠️  Test file not found: {test_file}")
            continue
            
        print(f"\n🧪 Testing: {test_file}")
        print("-" * 40)
        
        # Create temporary git repo for the file
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            
            # Initialize git repo
            subprocess.run(["git", "init"], cwd=temp_dir, capture_output=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=temp_dir, capture_output=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=temp_dir, capture_output=True)
            
            # Copy test file
            shutil.copy2(file_path, temp_path / test_file)
            
            # Add requirements.txt for Python files to test dependency scanning
            if test_file.endswith('.py'):
                with open(temp_path / "requirements.txt", "w") as f:
                    f.write("""
# Intentionally vulnerable dependencies for testing
requests==2.20.0
pyyaml==3.13
django==2.2.0
flask==0.12.2
""")
            
            # Add package.json for JS files
            if test_file.endswith('.js'):
                with open(temp_path / "package.json", "w") as f:
                    json.dump({
                        "name": "vulnerable-mcp-test",
                        "version": "1.0.0",
                        "dependencies": {
                            "lodash": "4.17.4",  # Has known vulnerabilities
                            "axios": "0.18.0",   # Has known vulnerabilities
                            "@modelcontextprotocol/sdk": "^0.1.0"
                        }
                    }, f, indent=2)
            
            # Commit files
            subprocess.run(["git", "add", "."], cwd=temp_dir, capture_output=True)
            subprocess.run(["git", "commit", "-m", "Add vulnerable test file"], cwd=temp_dir, capture_output=True)
            
            # Test with file:// URL (local scanning)
            file_url = f"file://{temp_path.absolute()}"
            
            try:
                start_time = time.time()
                response = requests.post(f"{scanner_url}/scan", json={
                    "repository_url": file_url,
                    "options": {
                        "enable_mcp_rules": True,
                        "comprehensive": True
                    }
                }, timeout=300)
                
                scan_time = time.time() - start_time
                
                if response.status_code == 200:
                    result = response.json()
                    results[test_file] = result
                    
                    print(f"✅ Scan completed in {scan_time:.1f}s")
                    print(f"📊 Security Score: {result['security_score']}/100 (Grade: {result['security_grade']})")
                    print(f"🔍 Total Findings: {result['total_findings']}")
                    
                    # Breakdown by severity
                    severity_breakdown = result['summary']['severity_breakdown']
                    for severity, count in severity_breakdown.items():
                        if count > 0:
                            emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(severity, '⚪')
                            print(f"  {emoji} {severity.upper()}: {count}")
                    
                    # Show top findings
                    critical_high = [f for f in result['findings'] if f['severity'] in ['critical', 'high']]
                    if critical_high:
                        print(f"\n🚨 Top {min(3, len(critical_high))} Critical/High Findings:")
                        for i, finding in enumerate(critical_high[:3], 1):
                            print(f"  {i}. {finding['title']} ({finding['vulnerability_type']})")
                            print(f"     Location: {finding['location']}")
                
                else:
                    print(f"❌ Scan failed: {response.status_code} - {response.text[:200]}")
                    
            except Exception as e:
                print(f"❌ Scan error: {e}")
    
    # Summary
    print(f"\n{'=' * 60}")
    print("📋 TEST SUMMARY")
    print(f"{'=' * 60}")
    
    total_files = len([f for f in test_files if (examples_dir / f).exists()])
    successful_scans = len(results)
    
    print(f"Files tested: {successful_scans}/{total_files}")
    
    if results:
        avg_score = sum(r['security_score'] for r in results.values()) / len(results)
        total_findings = sum(r['total_findings'] for r in results.values())
        
        print(f"Average security score: {avg_score:.1f}/100")
        print(f"Total vulnerabilities found: {total_findings}")
        
        # Expected vs actual findings
        expected_critical = 5  # Per file
        expected_high = 8
        
        actual_critical = sum(r['summary']['severity_breakdown'].get('critical', 0) for r in results.values())
        actual_high = sum(r['summary']['severity_breakdown'].get('high', 0) for r in results.values())
        
        print(f"\n🎯 Detection Effectiveness:")
        print(f"  Critical: {actual_critical} found (expected ~{expected_critical * successful_scans})")
        print(f"  High: {actual_high} found (expected ~{expected_high * successful_scans})")
        
        if actual_critical >= expected_critical * successful_scans * 0.8:
            print("✅ Critical vulnerability detection: GOOD")
        else:
            print("⚠️  Critical vulnerability detection: NEEDS IMPROVEMENT")
    
    return results

def test_real_repositories():
    """Test scanner with real vulnerable repositories"""
    
    scanner_url = "http://localhost:8000"
    
    # Known vulnerable repositories (for educational/testing purposes)
    vulnerable_repos = [
        {
            "name": "DVWA (Damn Vulnerable Web Application)",
            "url": "https://github.com/digininja/DVWA",
            "expected_findings": "50+",
            "description": "Intentionally vulnerable PHP web application"
        },
        {
            "name": "NodeGoat",
            "url": "https://github.com/OWASP/NodeGoat", 
            "expected_findings": "30+",
            "description": "Vulnerable Node.js application"
        },
        {
            "name": "WebGoat",
            "url": "https://github.com/WebGoat/WebGoat",
            "expected_findings": "40+", 
            "description": "Intentionally insecure Java application"
        }
    ]
    
    print(f"\n🌐 Testing with Real Vulnerable Repositories")
    print("=" * 60)
    print("⚠️  These are intentionally vulnerable educational projects")
    
    for repo in vulnerable_repos:
        print(f"\n🧪 Testing: {repo['name']}")
        print(f"📍 URL: {repo['url']}")
        print(f"📊 Expected: {repo['expected_findings']} findings")
        print("-" * 40)
        
        try:
            start_time = time.time()
            response = requests.post(f"{scanner_url}/scan", json={
                "repository_url": repo['url'],
                "options": {
                    "enable_mcp_rules": False,  # These aren't MCP repos
                    "comprehensive": True
                }
            }, timeout=600)  # 10 minute timeout for real repos
            
            scan_time = time.time() - start_time
            
            if response.status_code == 200:
                result = response.json()
                print(f"✅ Scan completed in {scan_time:.1f}s")
                print(f"📊 Security Score: {result['security_score']}/100")
                print(f"🔍 Total Findings: {result['total_findings']}")
                
                # Show breakdown
                severity_breakdown = result['summary']['severity_breakdown']
                for severity, count in severity_breakdown.items():
                    if count > 0:
                        emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵', 'info': '⚪'}.get(severity, '⚪')
                        print(f"  {emoji} {severity.upper()}: {count}")
                        
            else:
                print(f"❌ Scan failed: {response.status_code}")
                
        except requests.exceptions.Timeout:
            print("⏰ Scan timed out (>10 minutes)")
        except Exception as e:
            print(f"❌ Scan error: {e}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--real-repos":
        test_real_repositories()
    else:
        test_local_examples()
        
    print(f"\n🎉 Testing completed!")
    print("💡 To test with real vulnerable repos: python test_scanner.py --real-repos")