"""
Security scoring algorithm for scan results
"""

from typing import List, Dict, Any
from models import Finding, SeverityLevel


class SecurityScorer:
    """
    Calculates security scores based on findings
    Uses OWASP-style weighted scoring
    """

    # Base weights for severity levels
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10,
        SeverityLevel.HIGH: 7,
        SeverityLevel.MEDIUM: 4,
        SeverityLevel.LOW: 1,
        SeverityLevel.INFO: 0
    }

    # Multipliers for specific vulnerability types
    VULNERABILITY_MULTIPLIERS = {
        'malware': 2.0,               # Malware is extremely serious
        'tool_poisoning': 1.8,        # MCP tool poisoning is very serious
        'prompt_injection': 1.5,      # Very serious for MCP
        'command_injection': 1.5,     # Can compromise system
        'apt': 1.4,                   # Advanced Persistent Threats
        'backdoor': 1.4,              # Backdoors are critical
        'webshell': 1.3,              # Web shells are serious
        'cryptominer': 1.2,           # Resource hijacking
        'hardcoded_secret': 1.2,      # Immediate risk
        'vulnerable_dependency': 1.1,  # Depends on specific CVE
        'permission_abuse': 1.1,      # Privilege escalation risk
        'generic': 1.0
    }

    # Confidence thresholds
    MIN_CONFIDENCE_THRESHOLD = 0.5  # Ignore findings below this confidence

    def calculate_score(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate security score from findings

        Returns:
            Dictionary with score, grade, and breakdown
        """
        if not findings:
            return {
                'score': 100.0,
                'grade': 'A',
                'risk_points': 0,
                'max_possible_points': 0,
                'findings_by_severity': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }

        # Filter findings by confidence
        confident_findings = [
            f for f in findings
            if f.confidence >= self.MIN_CONFIDENCE_THRESHOLD
        ]

        # Calculate risk points
        total_risk_points = 0
        findings_by_severity = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }

        for finding in confident_findings:
            # Get base weight
            base_weight = self.SEVERITY_WEIGHTS.get(finding.severity, 0)

            # Apply vulnerability type multiplier
            multiplier = self.VULNERABILITY_MULTIPLIERS.get(
                finding.vulnerability_type.value,
                1.0
            )

            # Apply confidence factor
            confidence_factor = finding.confidence

            # Calculate final points for this finding
            risk_points = base_weight * multiplier * confidence_factor
            total_risk_points += risk_points

            # Count by severity
            findings_by_severity[finding.severity.value] += 1

        # Calculate maximum possible risk points
        # (if all findings were critical with max confidence)
        max_possible_points = len(confident_findings) * self.SEVERITY_WEIGHTS[SeverityLevel.CRITICAL]

        # Calculate score (0-100 scale)
        if max_possible_points > 0:
            risk_ratio = min(total_risk_points / max_possible_points, 1.0)
            score = (1 - risk_ratio) * 100
        else:
            score = 100.0

        # Apply deductions for specific conditions
        score = self._apply_special_deductions(score, confident_findings)

        # Ensure score is within bounds
        score = max(0.0, min(100.0, score))

        # Calculate grade
        grade = self._calculate_grade(score)

        return {
            'score': round(score, 1),
            'grade': grade,
            'risk_points': round(total_risk_points, 2),
            'max_possible_points': max_possible_points,
            'findings_by_severity': findings_by_severity,
            'confidence_threshold_used': self.MIN_CONFIDENCE_THRESHOLD,
            'total_findings': len(findings),
            'confident_findings': len(confident_findings)
        }

    def _apply_special_deductions(self, score: float, findings: List[Finding]) -> float:
        """Apply special deductions for critical issues"""

        # Major deduction for any malware detection
        malware_findings = [
            f for f in findings
            if f.vulnerability_type.value == 'malware'
        ]
        if malware_findings:
            score *= 0.5  # 50% deduction for any malware

        # Major deduction for APT patterns
        apt_findings = [
            f for f in findings
            if 'APT' in f.title or 'apt' in f.evidence.get('category', '')
        ]
        if apt_findings:
            score *= 0.6  # 40% deduction for APT patterns

        # Deduction for tool poisoning (YARA-detected)
        tool_poisoning = [
            f for f in findings
            if f.vulnerability_type.value == 'tool_poisoning'
            and f.severity == SeverityLevel.CRITICAL
        ]
        if tool_poisoning:
            score *= 0.65  # 35% deduction

        # Major deduction for any critical prompt injection
        critical_prompt_injections = [
            f for f in findings
            if f.vulnerability_type.value == 'prompt_injection'
            and f.severity == SeverityLevel.CRITICAL
        ]
        if critical_prompt_injections:
            score *= 0.7  # 30% deduction

        # Deduction for backdoors
        backdoor_findings = [
            f for f in findings
            if 'backdoor' in f.title.lower() or
            f.evidence.get('category', '') == 'backdoor'
        ]
        if backdoor_findings:
            score *= 0.6  # 40% deduction for backdoors

        # Deduction for hardcoded secrets
        secrets = [
            f for f in findings
            if f.vulnerability_type.value in ['hardcoded_secret', 'api_key_exposure']
            and f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]
        if secrets:
            score *= 0.85  # 15% deduction

        # Deduction for multiple high-severity issues
        high_severity_count = sum(
            1 for f in findings
            if f.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        )
        if high_severity_count >= 5:
            score *= 0.9  # 10% deduction

        # Extra deduction for polymorphic/obfuscated code
        obfuscation_findings = [
            f for f in findings
            if 'polymorphic' in f.title.lower() or
            'obfuscat' in f.title.lower()
        ]
        if obfuscation_findings:
            score *= 0.8  # 20% deduction

        return score

    def _calculate_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 95:
            return 'A+'
        elif score >= 90:
            return 'A'
        elif score >= 85:
            return 'A-'
        elif score >= 80:
            return 'B+'
        elif score >= 75:
            return 'B'
        elif score >= 70:
            return 'B-'
        elif score >= 65:
            return 'C+'
        elif score >= 60:
            return 'C'
        elif score >= 55:
            return 'C-'
        elif score >= 50:
            return 'D'
        else:
            return 'F'

    def get_risk_level(self, score: float) -> str:
        """Determine risk level from score"""
        if score >= 90:
            return 'low'
        elif score >= 75:
            return 'medium'
        elif score >= 60:
            return 'high'
        else:
            return 'critical'

    def get_recommendation(self, score_data: Dict[str, Any]) -> str:
        """Get overall recommendation based on score"""
        score = score_data['score']
        grade = score_data['grade']

        if score >= 90:
            return f"Excellent security posture (Grade: {grade}). Minor improvements recommended."
        elif score >= 75:
            return f"Good security posture (Grade: {grade}). Address high-severity issues."
        elif score >= 60:
            return f"Fair security posture (Grade: {grade}). Significant improvements needed."
        else:
            return f"Poor security posture (Grade: {grade}). Critical security issues require immediate attention."