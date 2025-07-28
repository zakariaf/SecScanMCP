#!/usr/bin/env python3
"""
Example of using the MCP Security Scanner API with Universal Scanners
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
    print(f"MCP Security Scanner - Universal Scanner Edition")
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
            "comprehensive": True  # Use all scanners
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

    # SBOM Summary (from Syft)
    if 'sbom_summary' in result.get('scan_metadata', {}):
        sbom = result['scan_metadata']['sbom_summary']
        print(f"\n{'─'*40}")
        print("SOFTWARE COMPOSITION:")
        print(f"{'─'*40}")
        print(f"Total Packages: {sbom['total_packages']}")
        print("Languages Detected:")
        for lang, count in sbom.get('languages', {}).items():
            print(f"  • {lang.title()}: {count} packages")

    # High-Risk Vulnerabilities (NEW: with EPSS/KEV data)
    print(f"\n{'─'*40}")
    print("HIGH-RISK VULNERABILITIES:")
    print(f"{'─'*40}")

    high_risk_findings = []
    for finding in result['findings']:
        evidence = finding.get('evidence', {})

        # Prioritize by multiple factors
        is_high_risk = (
            finding['severity'] in ['critical', 'high'] or
            evidence.get('is_known_exploited', False) or
            evidence.get('epss_score', 0) > 0.7
        )

        if is_high_risk:
            high_risk_findings.append(finding)

    # Sort by risk
    high_risk_findings.sort(
        key=lambda f: (
            f['severity'] == 'critical',
            f.get('evidence', {}).get('is_known_exploited', False),
            f.get('evidence', {}).get('epss_score', 0)
        ),
        reverse=True
    )

    # Display top high-risk findings
    for i, finding in enumerate(high_risk_findings[:5], 1):
        evidence = finding.get('evidence', {})
        print(f"\n{i}. {finding['title']}")
        print(f"   Severity: {finding['severity'].upper()}")
        print(f"   Type: {finding['vulnerability_type'].replace('_', ' ').title()}")
        print(f"   Location: {finding['location']}")

        # Show risk indicators
        risk_factors = []
        if evidence.get('is_known_exploited'):
            risk_factors.append("🚨 ACTIVELY EXPLOITED")
        if evidence.get('epss_score', 0) > 0:
            epss = evidence['epss_score']
            percentile = evidence.get('epss_percentile', 0)
            risk_factors.append(f"📊 EPSS: {epss:.2%} (top {(1-percentile)*100:.0f}%)")
        if evidence.get('cvss_max', 0) > 0:
            risk_factors.append(f"💯 CVSS: {evidence['cvss_max']}")

        if risk_factors:
            print(f"   Risk Indicators: {' | '.join(risk_factors)}")

        print(f"   Recommendation: {finding['recommendation'][:100]}...")

    if len(high_risk_findings) > 5:
        print(f"\n... and {len(high_risk_findings) - 5} more high-risk findings")

    # Tool Performance
    print(f"\n{'─'*40}")
    print("SCANNER PERFORMANCE:")
    print(f"{'─'*40}")

    analyzers_run = result.get('scan_metadata', {}).get('analyzers_run', [])
    print(f"Tools Used: {', '.join(analyzers_run)}")
    print(f"Total Scan Time: {scan_time:.1f} seconds")

    # Note about caching
    if scan_time < 10:
        print("✓ Fast scan achieved through SBOM caching")

    # Recommendations
    print(f"\n{'='*60}")
    print("RECOMMENDATIONS:")
    print(f"{'='*60}")

    if result['security_score'] >= 90:
        print("✓ Excellent security posture! Only minor improvements needed.")
        print("  • Continue regular scanning")
        print("  • Keep dependencies updated")
    elif result['security_score'] >= 75:
        print("⚠️  Good security posture, but address high-severity issues:")
        print("   1. Fix all critical and high severity vulnerabilities")
        print("   2. Prioritize known exploited vulnerabilities (KEV)")
        print("   3. Address high EPSS score vulnerabilities")
        print("   4. Review and update dependencies")
    elif result['security_score'] >= 60:
        print("⚠️  Fair security posture. Significant improvements needed:")
        print("   1. Immediately address all critical vulnerabilities")
        print("   2. Fix actively exploited vulnerabilities (KEV) first")
        print("   3. Update all vulnerable dependencies")
        print("   4. Remove hardcoded secrets")
        print("   5. Implement security scanning in CI/CD")
    else:
        print("❌ Poor security posture! Immediate action required:")
        print("   1. DO NOT deploy this code to production")
        print("   2. Create security task force")
        print("   3. Fix all critical/high severity issues")
        print("   4. Prioritize by exploitation risk (EPSS/KEV)")
        print("   5. Consider security training for team")

    # Universal Scanner Benefits
    print(f"\n📌 Universal Scanner Benefits:")
    print("  • Comprehensive coverage for all languages")
    print("  • Risk-based prioritization with EPSS/KEV")
    print("  • Faster scanning with SBOM caching")
    print("  • Unified vulnerability database")

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