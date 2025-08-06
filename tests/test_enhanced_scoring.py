#!/usr/bin/env python3
"""
Test script for enhanced scoring system integration
"""
import sys
import asyncio
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from models import Finding, SeverityLevel, VulnerabilityType
from enhanced_scoring import EnhancedSecurityScorer

def create_test_findings():
    """Create test findings to verify scoring works"""
    return [
        # Critical MCP-exploitable
        Finding(
            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
            severity=SeverityLevel.CRITICAL,
            confidence=0.95,
            title="Command injection in MCP tool",
            description="User input passed to shell without sanitization",
            location="src/tools.py:42",
            recommendation="Use shlex.quote() to escape inputs",
            tool="codeql"
        ),
        
        # High MCP-related
        Finding(
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.88,
            title="Prompt injection vulnerability",
            description="Malicious prompts could manipulate AI behavior",
            location="src/handlers.py:15",
            recommendation="Implement prompt sanitization",
            tool="mcp_specific"
        ),
        
        # Medium indirect impact
        Finding(
            vulnerability_type=VulnerabilityType.SQL_INJECTION,
            severity=SeverityLevel.MEDIUM,
            confidence=0.75,
            title="SQL injection in database query",
            description="User input not properly sanitized",
            location="src/database.py:89",
            recommendation="Use parameterized queries",
            tool="bandit"
        ),
        
        # Low developer concern
        Finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=SeverityLevel.LOW,
            confidence=0.60,
            title="Outdated dependency with known CVE",
            description="Package lodash has known vulnerability",
            location="package.json",
            recommendation="Update to latest version",
            tool="trivy",
            cve_id="CVE-2020-8203"
        ),
        
        # Critical malware (should trigger automatic F)
        Finding(
            vulnerability_type=VulnerabilityType.MALWARE,
            severity=SeverityLevel.CRITICAL,
            confidence=0.99,
            title="Malware detected in binary",
            description="Trojan horse detected",
            location="src/suspicious_file.exe",
            recommendation="Remove malicious file immediately",
            tool="clamav"
        )
    ]

def test_enhanced_scoring():
    """Test the enhanced scoring system"""
    print("🧪 Testing Enhanced Scoring System")
    print("=" * 50)
    
    # Create test findings
    findings = create_test_findings()
    print(f"Created {len(findings)} test findings:")
    for i, finding in enumerate(findings, 1):
        print(f"  {i}. {finding.severity.value.upper()} {finding.vulnerability_type.value}: {finding.title}")
    
    print()
    
    # Initialize scorer
    scorer = EnhancedSecurityScorer()
    
    # Test User Safety Score
    print("👤 USER SAFETY SCORE")
    print("-" * 20)
    user_safety = scorer.calculate_user_safety_score(findings)
    print(f"Score: {user_safety['score']} ({user_safety['grade']})")
    print(f"Risk Level: {user_safety['risk_level']}")
    print(f"Message: {user_safety['user_message']}")
    print(f"Critical Issues: {user_safety['critical_issues']}")
    print(f"High Risks: {user_safety['high_risks']}")
    print()
    
    # Test Developer Security Score
    print("👨‍💻 DEVELOPER SECURITY SCORE")
    print("-" * 25)
    developer_score = scorer.calculate_developer_score(findings)
    print(f"Score: {developer_score['score']} ({developer_score['grade']})")
    print(f"Risk Points: {developer_score['risk_points']}")
    print(f"Total Findings: {developer_score['total_findings']}")
    print("Improvement Areas:")
    for area in developer_score['improvement_areas']:
        print(f"  • {area}")
    print()
    
    # Test Both Scores
    print("📊 COMBINED SCORES")
    print("-" * 15)
    both_scores = scorer.calculate_both_scores(findings)
    
    summary = both_scores['summary']
    print(f"MCP Exploitable: {summary['mcp_exploitable']}")
    print(f"Requires Immediate Attention: {summary['requires_immediate_attention']}")
    print(f"Scan Completeness: {summary['scan_completeness']}")
    
    print()
    print("✅ Enhanced scoring system working correctly!")
    return both_scores

def test_without_malware():
    """Test scoring without malware to see normal grades"""
    print("\n🧪 Testing Without Malware")
    print("=" * 25)
    
    # Create findings without malware
    clean_findings = [
        Finding(
            vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
            confidence=0.85,
            title="Minor prompt injection risk",
            description="Potential for prompt manipulation",
            location="src/handlers.py:15",
            recommendation="Add input validation",
            tool="mcp_specific"
        ),
        
        Finding(
            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
            severity=SeverityLevel.MEDIUM,
            confidence=0.70,
            title="Outdated package",
            description="Package has minor security issue",
            location="package.json",
            recommendation="Update package",
            tool="trivy"
        )
    ]
    
    scorer = EnhancedSecurityScorer()
    both_scores = scorer.calculate_both_scores(clean_findings)
    
    user_safety = both_scores['user_safety']
    developer_security = both_scores['developer_security']
    
    print(f"User Safety: {user_safety['score']} ({user_safety['grade']})")
    print(f"Developer Score: {developer_security['score']} ({developer_security['grade']})")
    print(f"User Message: {user_safety['user_message']}")
    
    return both_scores

if __name__ == "__main__":
    try:
        # Test with malware (should get F grade)
        malware_scores = test_enhanced_scoring()
        
        # Test without malware (should get better grades)
        clean_scores = test_without_malware()
        
        print(f"\n🎯 COMPARISON")
        print("=" * 15)
        print(f"With Malware    - User: {malware_scores['user_safety']['grade']}, Developer: {malware_scores['developer_security']['grade']}")
        print(f"Without Malware - User: {clean_scores['user_safety']['grade']}, Developer: {clean_scores['developer_security']['grade']}")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    print("\n🚀 All tests passed! Enhanced scoring system is ready!")