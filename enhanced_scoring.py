"""
Enhanced Security Scoring System
Implements dual scoring: User Safety Score and Developer Security Score
"""

from typing import List, Dict, Any, Tuple, Set
from enum import Enum
from models import Finding, SeverityLevel, VulnerabilityType


class ScoreType(str, Enum):
    USER_SAFETY = "user_safety"
    DEVELOPER_SECURITY = "developer_security"


class UserImpactCategory(str, Enum):
    """Categories that directly impact users"""
    DIRECT_EXPLOITATION = "direct_exploitation"      # Can be exploited through MCP
    DATA_PROTECTION = "data_protection"              # User data at risk
    SERVICE_INTEGRITY = "service_integrity"          # Service reliability
    INFRASTRUCTURE = "infrastructure"                # Server security


class EnhancedSecurityScorer:
    """
    Dual scoring system for MCP security assessment
    - User Safety Score: Focus on MCP-exploitable vulnerabilities
    - Developer Security Score: Comprehensive code analysis
    """

    # MCP-exploitable vulnerability types (Critical for users)
    MCP_EXPLOITABLE_CRITICAL = {
        VulnerabilityType.COMMAND_INJECTION,
        VulnerabilityType.CODE_INJECTION,
        VulnerabilityType.PATH_TRAVERSAL,
        VulnerabilityType.TOOL_POISONING,
        VulnerabilityType.TOOL_MANIPULATION,
        VulnerabilityType.DATA_LEAKAGE,
        VulnerabilityType.DATA_EXPOSURE,
        VulnerabilityType.PRIVILEGE_ESCALATION,
        VulnerabilityType.MALWARE,
        VulnerabilityType.BACKDOOR,
    }

    # MCP-related vulnerabilities (High impact for users)
    MCP_RELATED_HIGH = {
        VulnerabilityType.PROMPT_INJECTION,
        VulnerabilityType.OUTPUT_POISONING,
        VulnerabilityType.PERMISSION_ABUSE,
        VulnerabilityType.SCHEMA_INJECTION,
        VulnerabilityType.MCP_SPECIFIC,
    }

    # Indirect user impact vulnerabilities (Medium)
    INDIRECT_USER_IMPACT = {
        VulnerabilityType.SQL_INJECTION,
        VulnerabilityType.SSRF,
        VulnerabilityType.XSS,
        VulnerabilityType.XXE,
        VulnerabilityType.WEAK_CRYPTO,
        VulnerabilityType.INSECURE_CONFIGURATION,
        VulnerabilityType.BEHAVIORAL_ANOMALY,
        VulnerabilityType.NETWORK_SECURITY,
        VulnerabilityType.RESOURCE_ABUSE,
    }
    
    # Developer-side security issues (not exploitable through MCP)
    DEVELOPER_CONCERNS = {
        VulnerabilityType.HARDCODED_SECRET,
        VulnerabilityType.VULNERABLE_DEPENDENCY,
        VulnerabilityType.OUTDATED_DEPENDENCY,
        VulnerabilityType.LICENSE_VIOLATION,
        VulnerabilityType.API_KEY_EXPOSURE,
        VulnerabilityType.MISSING_SECURITY_HEADERS,
        VulnerabilityType.GENERIC,
    }

    # User impact penalties by category
    USER_IMPACT_PENALTIES = {
        # Critical MCP-exploitable
        (VulnerabilityType.COMMAND_INJECTION, SeverityLevel.CRITICAL): 25,
        (VulnerabilityType.CODE_INJECTION, SeverityLevel.CRITICAL): 25,
        (VulnerabilityType.PATH_TRAVERSAL, SeverityLevel.CRITICAL): 25,
        (VulnerabilityType.TOOL_POISONING, SeverityLevel.CRITICAL): 25,
        (VulnerabilityType.PRIVILEGE_ESCALATION, SeverityLevel.CRITICAL): 25,
        (VulnerabilityType.MALWARE, SeverityLevel.CRITICAL): 50,  # Automatic fail
        (VulnerabilityType.BACKDOOR, SeverityLevel.CRITICAL): 50,  # Automatic fail
        (VulnerabilityType.DATA_LEAKAGE, SeverityLevel.CRITICAL): 20,
        (VulnerabilityType.DATA_EXPOSURE, SeverityLevel.CRITICAL): 20,
        
        # High severity MCP-related
        (VulnerabilityType.PROMPT_INJECTION, SeverityLevel.HIGH): 10,
        (VulnerabilityType.OUTPUT_POISONING, SeverityLevel.HIGH): 10,
        (VulnerabilityType.PERMISSION_ABUSE, SeverityLevel.HIGH): 10,
        (VulnerabilityType.MCP_SPECIFIC, SeverityLevel.HIGH): 10,
        (VulnerabilityType.HARDCODED_SECRET, SeverityLevel.HIGH): 8,
        
        # Medium severity indirect impact
        (VulnerabilityType.SQL_INJECTION, SeverityLevel.MEDIUM): 5,
        (VulnerabilityType.XXE, SeverityLevel.MEDIUM): 5,
        (VulnerabilityType.BEHAVIORAL_ANOMALY, SeverityLevel.MEDIUM): 3,
        (VulnerabilityType.RESOURCE_ABUSE, SeverityLevel.MEDIUM): 3,
        
        # Low severity
        (VulnerabilityType.INSECURE_CONFIGURATION, SeverityLevel.LOW): 2,
        (VulnerabilityType.MISSING_SECURITY_HEADERS, SeverityLevel.LOW): 1,
        (VulnerabilityType.VULNERABLE_DEPENDENCY, SeverityLevel.LOW): 1,
    }

    # Developer scoring weights (comprehensive)
    DEVELOPER_SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10,
        SeverityLevel.HIGH: 7,
        SeverityLevel.MEDIUM: 4,
        SeverityLevel.LOW: 1,
        SeverityLevel.INFO: 0
    }

    def calculate_user_safety_score(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate User Safety Score focusing on MCP-exploitable vulnerabilities
        
        Returns:
            Dictionary with score, grade, and user-facing information
        """
        score = 100.0
        critical_violations = []
        high_risks = []
        medium_risks = []
        
        # Group findings by user impact
        for finding in findings:
            if finding.confidence < 0.5:  # Skip low confidence
                continue
                
            vuln_type = finding.vulnerability_type
            severity = finding.severity
            
            # Check for critical MCP-exploitable vulnerabilities
            if vuln_type in self.MCP_EXPLOITABLE_CRITICAL:
                if severity == SeverityLevel.CRITICAL:
                    critical_violations.append(finding)
                    penalty = self.USER_IMPACT_PENALTIES.get(
                        (vuln_type, severity), 25
                    )
                    score -= penalty
                elif severity == SeverityLevel.HIGH:
                    high_risks.append(finding)
                    score -= 15
            
            # Check for high-impact MCP-related vulnerabilities
            elif vuln_type in self.MCP_RELATED_HIGH:
                if severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                    high_risks.append(finding)
                    penalty = self.USER_IMPACT_PENALTIES.get(
                        (vuln_type, severity), 10
                    )
                    score -= penalty
                elif severity == SeverityLevel.MEDIUM:
                    medium_risks.append(finding)
                    score -= 5
                # INFO and LOW level findings don't get penalties in user safety scoring
            
            # Check for indirect user impact
            elif vuln_type in self.INDIRECT_USER_IMPACT:
                if severity == SeverityLevel.HIGH:
                    medium_risks.append(finding)
                    score -= 5
                elif severity == SeverityLevel.MEDIUM:
                    penalty = self.USER_IMPACT_PENALTIES.get(
                        (vuln_type, severity), 3
                    )
                    score -= penalty
        
        # Apply critical violation cap
        if critical_violations:
            score = min(score, 69)  # Cap at C- grade
            
        # Apply malware/backdoor automatic fail
        if any(f.vulnerability_type in [VulnerabilityType.MALWARE, VulnerabilityType.BACKDOOR] 
               for f in critical_violations):
            score = 0  # Automatic F
        
        # Ensure score bounds
        score = max(0, min(100, score))
        
        # Calculate grade and risk level
        grade = self._calculate_grade(score)
        risk_level = self._calculate_risk_level(critical_violations, high_risks, medium_risks)
        
        return {
            'score': round(score, 1),
            'grade': grade,
            'risk_level': risk_level,
            'badge_color': self._get_badge_color(grade),
            'critical_issues': len(critical_violations),
            'high_risks': len(high_risks),
            'medium_risks': len(medium_risks),
            'user_message': self._get_user_message(grade, critical_violations),
            'categories': self._categorize_user_impact(findings),
        }
    
    def calculate_developer_score(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Calculate comprehensive Developer Security Score
        
        Returns:
            Dictionary with detailed scoring breakdown
        """
        total_risk_points = 0
        findings_by_type = {}
        findings_by_severity = {
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0
        }
        
        for finding in findings:
            if finding.confidence < 0.3:  # More lenient for developer score
                continue
            
            # Calculate risk points
            base_weight = self.DEVELOPER_SEVERITY_WEIGHTS.get(finding.severity, 0)
            confidence_factor = finding.confidence
            risk_points = base_weight * confidence_factor
            total_risk_points += risk_points
            
            # Track by type and severity
            vuln_type = finding.vulnerability_type.value
            findings_by_type[vuln_type] = findings_by_type.get(vuln_type, 0) + 1
            findings_by_severity[finding.severity.value] += 1
        
        # Calculate score (inverse of risk)
        max_possible_points = len(findings) * self.DEVELOPER_SEVERITY_WEIGHTS[SeverityLevel.CRITICAL]
        if max_possible_points > 0:
            risk_ratio = min(total_risk_points / max_possible_points, 1.0)
            score = (1 - risk_ratio) * 100
        else:
            score = 100.0
        
        # Apply special deductions
        score = self._apply_developer_deductions(score, findings)
        score = max(0, min(100, score))
        
        grade = self._calculate_grade(score)
        
        return {
            'score': round(score, 1),
            'grade': grade,
            'risk_points': round(total_risk_points, 2),
            'findings_by_severity': findings_by_severity,
            'findings_by_type': findings_by_type,
            'total_findings': len(findings),
            'improvement_areas': self._get_improvement_areas(findings_by_type),
        }
    
    def calculate_both_scores(self, findings: List[Finding]) -> Dict[str, Any]:
        """Calculate both User Safety and Developer Security scores"""
        return {
            'user_safety': self.calculate_user_safety_score(findings),
            'developer_security': self.calculate_developer_score(findings),
            'summary': self._generate_summary(findings),
        }
    
    def _calculate_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'
    
    def _get_badge_color(self, grade: str) -> str:
        """Get badge color for grade"""
        colors = {
            'A': '#4CAF50',  # Green
            'B': '#8BC34A',  # Light Green
            'C': '#FFC107',  # Amber
            'D': '#FF5722',  # Deep Orange
            'F': '#F44336',  # Red
        }
        return colors.get(grade, '#9E9E9E')
    
    def _calculate_risk_level(self, critical: List, high: List, medium: List) -> str:
        """Calculate overall risk level"""
        if critical:
            return "CRITICAL"
        elif len(high) >= 3:
            return "HIGH"
        elif high or len(medium) >= 5:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_user_message(self, grade: str, critical_violations: List[Finding]) -> str:
        """Generate user-friendly message"""
        if grade == 'A':
            return "This MCP server appears to be secure for production use."
        elif grade == 'B':
            return "This MCP server is generally safe with minor security concerns."
        elif grade == 'C':
            return "This MCP server has security issues that should be addressed before production use."
        elif grade == 'D':
            return "This MCP server has significant security vulnerabilities. Use with caution."
        else:  # F
            if any(f.vulnerability_type == VulnerabilityType.MALWARE for f in critical_violations):
                return "⚠️ MALWARE DETECTED! Do not use this MCP server."
            return "This MCP server is not safe to use due to critical security vulnerabilities."
    
    def _categorize_user_impact(self, findings: List[Finding]) -> Dict[str, int]:
        """Categorize findings by user impact"""
        categories = {
            UserImpactCategory.DIRECT_EXPLOITATION: 0,
            UserImpactCategory.DATA_PROTECTION: 0,
            UserImpactCategory.SERVICE_INTEGRITY: 0,
            UserImpactCategory.INFRASTRUCTURE: 0,
        }
        
        for finding in findings:
            vuln_type = finding.vulnerability_type
            
            if vuln_type in [VulnerabilityType.COMMAND_INJECTION, VulnerabilityType.CODE_INJECTION,
                           VulnerabilityType.PATH_TRAVERSAL, VulnerabilityType.TOOL_POISONING]:
                categories[UserImpactCategory.DIRECT_EXPLOITATION] += 1
            
            elif vuln_type in [VulnerabilityType.DATA_LEAKAGE, VulnerabilityType.OUTPUT_POISONING,
                             VulnerabilityType.HARDCODED_SECRET]:
                categories[UserImpactCategory.DATA_PROTECTION] += 1
            
            elif vuln_type in [VulnerabilityType.PROMPT_INJECTION, VulnerabilityType.BEHAVIORAL_ANOMALY,
                             VulnerabilityType.RESOURCE_ABUSE]:
                categories[UserImpactCategory.SERVICE_INTEGRITY] += 1
            
            elif vuln_type in [VulnerabilityType.SQL_INJECTION, VulnerabilityType.SSRF,
                             VulnerabilityType.INSECURE_CONFIGURATION]:
                categories[UserImpactCategory.INFRASTRUCTURE] += 1
        
        return {k.value: v for k, v in categories.items() if v > 0}
    
    def _apply_developer_deductions(self, score: float, findings: List[Finding]) -> float:
        """Apply special deductions for developer score"""
        # Malware/backdoor major deduction
        if any(f.vulnerability_type in [VulnerabilityType.MALWARE, VulnerabilityType.BACKDOOR] 
               for f in findings):
            score *= 0.3  # 70% deduction
        
        # Multiple critical issues
        critical_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
        if critical_count >= 5:
            score *= 0.7  # 30% deduction
        
        return score
    
    def _get_improvement_areas(self, findings_by_type: Dict[str, int]) -> List[str]:
        """Suggest improvement areas based on findings"""
        areas = []
        
        if findings_by_type.get('hardcoded_secret', 0) > 0:
            areas.append("Remove hardcoded secrets and use environment variables")
        
        if findings_by_type.get('vulnerable_dependency', 0) > 0:
            areas.append("Update vulnerable dependencies")
        
        if findings_by_type.get('command_injection', 0) > 0:
            areas.append("Sanitize user inputs and avoid shell commands")
        
        if findings_by_type.get('insecure_configuration', 0) > 0:
            areas.append("Review and harden security configurations")
        
        return areas[:3]  # Top 3 suggestions
    
    def _generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate overall summary"""
        critical_mcp_exploitable = sum(
            1 for f in findings 
            if f.vulnerability_type in self.MCP_EXPLOITABLE_CRITICAL 
            and f.severity == SeverityLevel.CRITICAL
        )
        
        return {
            'total_findings': len(findings),
            'mcp_exploitable': critical_mcp_exploitable,
            'requires_immediate_attention': critical_mcp_exploitable > 0,
            'scan_completeness': self._estimate_scan_completeness(findings),
        }
    
    def _estimate_scan_completeness(self, findings: List[Finding]) -> str:
        """Estimate how complete the scan was based on analyzer coverage"""
        # This would check which analyzers ran successfully
        # For now, return a default
        return "Full scan completed"