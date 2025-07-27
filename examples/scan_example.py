#!/usr/bin/env python3
"""
Example of using the MCP Security Scanner API
"""

import requests
import json
import time
from datetime import datetime


def scan_repository(repo_url: str, scanner_url: str = "http://localhost:8000"):
    """
    Scan a repository using the MCP Security Scanner

    Args:
        repo_url: GitHub repository URL to scan
        scanner_url: URL of the scanner service
    """

    print(f"\n{'='*60}")
    print(f"MCP Security Scanner - Example Usage")
    print(f"{'='*60}")
    print(f"Repository: {repo_url}")
    print(f"Scanner: {scanner_url}")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")

    # Check scanner health
    print("Checking scanner health...")
    try:
        health_response = requests.get(f"{scanner_url}/health")
        health_response.raise_for_status()
        print(f"✓ Scanner is healthy: {health_response.json()['status']}")
    except Exception as e:
        print(f"✗ Scanner health check failed: {e}")
        return

    # Submit scan request
    print(f"\nSubmitting scan request...")
    scan_request = {
        "repository_url": repo_url,
        "options": {
            "enable_dynamic_analysis": True,
            "skip_dependencies": False
        }
    }

    try:
        start_time = time.time()
        response = requests.post(
            f"{scanner_url}/scan",
            json=scan_request,
            timeout=600  # 10 minute timeout
        )
        response.raise_for_status()
        scan_time = time.time() - start_time

        result = response.json()
        print(f"✓ Scan completed in {scan_time:.1f} seconds")

    except requests.exceptions.Timeout:
        print("✗ Scan timed out after 10 minutes")
        return
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        return

    # Display results
    print(f"\n{'='*60}")
    print("SCAN RESULTS")
    print(f"{'='*60}")

    print(f"\nRepository: {result['repository_url']}")
    print(f"Project Type: {result['project_type']}")
    print(f"Is MCP Server: {result['is_mcp_server']}")
    print(f"Scan Timestamp: {result['scan_timestamp']}")

    # Security Score
    print(f"\n{'─'*40}")
    print(f"SECURITY SCORE: {result['security_score']}/100 (Grade: {result['security_grade']})")
    print(f"Risk Level: {result['summary']['risk_level'].upper()}")
    print(f"{'─'*40}")

    # Summary
    summary = result['summary']
    print(f"\nTotal Findings: {summary['total_findings']}")
    print("\nSeverity Breakdown:")
    for severity, count in summary['severity_breakdown'].items():
        if count > 0:
            emoji = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🔵',
                'info': '⚪'
            }.get(severity, '⚪')
            print(f"  {emoji} {severity.upper()}: {count}")

    # Vulnerability Types
    print("\nVulnerability Types Found:")
    for vuln_type, count in summary['vulnerability_types'].items():
        print(f"  • {vuln_type.replace('_', ' ').title()}: {count}")

    # Top Risks
    if summary['top_risks']:
        print(f"\n{'─'*40}")
        print("TOP SECURITY RISKS:")
        print(f"{'─'*40}")
        for i, risk in enumerate(summary['top_risks'], 1):
            print(f"\n{i}. {risk['title']}")
            print(f"   Severity: {risk['severity'].upper()}")
            print(f"   Type: {risk['type'].replace('_', ' ').title()}")
            print(f"   Location: {risk['location']}")

    # Detailed Findings
    if result['findings']:
        print(f"\n{'─'*40}")
        print("DETAILED FINDINGS:")
        print(f"{'─'*40}")

        # Group by severity
        findings_by_severity = {}
        for finding in result['findings']:
            severity = finding['severity']
            if severity not in findings_by_severity:
                findings_by_severity[severity] = []
            findings_by_severity[severity].append(finding)

        # Display by severity (critical first)
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in findings_by_severity:
                findings = findings_by_severity[severity]
                print(f"\n{severity.upper()} ({len(findings)} findings):")
                print("─" * 30)

                for finding in findings[:3]:  # Show first 3 of each severity
                    print(f"\n• {finding['title']}")
                    print(f"  Tool: {finding['tool']}")
                    print(f"  Location: {finding['location']}")
                    print(f"  Confidence: {finding['confidence']*100:.0f}%")
                    print(f"  Description: {finding['description'][:100]}...")
                    print(f"  Recommendation: {finding['recommendation'][:100]}...")

                if len(findings) > 3:
                    print(f"\n  ... and {len(findings) - 3} more {severity} findings")

    # Recommendations
    print(f"\n{'='*60}")
    print("RECOMMENDATIONS:")
    print(f"{'='*60}")

    if result['security_score'] >= 90:
        print("✓ Excellent security posture! Only minor improvements needed.")
    elif result['security_score'] >= 75:
        print("⚠️  Good security posture, but address high-severity issues:")
        print("   1. Fix all critical and high severity vulnerabilities")
        print("   2. Review and update dependencies")
        print("   3. Remove any hardcoded secrets")
    elif result['security_score'] >= 60:
        print("⚠️  Fair security posture. Significant improvements needed:")
        print("   1. Immediately address all critical vulnerabilities")
        print("   2. Implement proper input validation")
        print("   3. Update all vulnerable dependencies")
        print("   4. Remove hardcoded secrets and use environment variables")
    else:
        print("❌ Poor security posture! Immediate action required:")
        print("   1. DO NOT deploy this code to production")
        print("   2. Fix all critical and high severity issues immediately")
        print("   3. Conduct thorough security review")
        print("   4. Consider security training for development team")

    # Save detailed report
    report_filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_filename, 'w') as f:
        json.dump(result, f, indent=2)
    print(f"\n📄 Detailed report saved to: {report_filename}")

    print(f"\n{'='*60}\n")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python scan_example.py <repository_url> [scanner_url]")
        print("\nExamples:")
        print("  python scan_example.py https://github.com/user/mcp-server")
        print("  python scan_example.py https://github.com/user/repo http://scanner:8000")
        sys.exit(1)

    repo_url = sys.argv[1]
    scanner_url = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8000"

    scan_repository(repo_url, scanner_url)