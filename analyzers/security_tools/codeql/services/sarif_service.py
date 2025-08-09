"""
SARIF Parsing Service for CodeQL Analysis

Parses CodeQL SARIF output and creates Finding objects
Following clean architecture with single responsibility
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class SarifService:
    """Parses CodeQL SARIF output into Finding objects"""
    
    def __init__(self, base_analyzer):
        self.base_analyzer = base_analyzer
    
    def parse_sarif_results(self, sarif_file: Path, repo_root: Path) -> List[Finding]:
        """Parse SARIF file into Finding objects"""
        findings: List[Finding] = []
        
        try:
            with open(sarif_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            for run in data.get("runs", []):
                # Extract rules mapping
                rules_by_id = self._extract_rules_mapping(run)
                
                # Process each result
                for result in run.get("results", []) or []:
                    finding = self._convert_sarif_result(result, rules_by_id, repo_root)
                    if finding:
                        findings.append(finding)
                        
        except Exception as e:
            logger.error(f"Failed to parse SARIF results: {e}")
        
        return findings
    
    def _extract_rules_mapping(self, run: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        """Extract rules mapping from SARIF run"""
        rules_by_id = {}
        
        driver = run.get("tool", {}).get("driver", {})
        for rule in driver.get("rules", []) or []:
            rule_id = rule.get("id")
            if rule_id:
                rules_by_id[rule_id] = rule
        
        return rules_by_id
    
    def _convert_sarif_result(self, result: Dict[str, Any], rules: Dict[str, Any], repo_root: Path) -> Optional[Finding]:
        """Convert single SARIF result to Finding object"""
        try:
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            
            # Extract location information
            location = self._extract_location(result)
            
            return self.base_analyzer.create_finding(
                vulnerability_type=self._determine_vuln_type(rule, result),
                severity=self._determine_severity(rule, result),
                confidence=self._extract_confidence(rule, result),
                title=rule.get("name", result.get("message", {}).get("text", "Unknown issue")),
                description=self._build_description(rule, result),
                location=location,
                recommendation=self._extract_recommendation(rule, result),
                references=self._build_references(rule, rule.get("properties", {}) or {}),
                evidence={
                    "rule_id": rule_id,
                    "level": result.get("level", "warning"),
                    "message": result.get("message", {}).get("text", ""),
                    "fingerprint": result.get("fingerprints", {}) or {},
                },
            )
            
        except Exception as e:
            logger.error(f"Failed to convert SARIF result: {e}")
            return None
    
    def _extract_location(self, result: Dict[str, Any]) -> str:
        """Extract location from SARIF result"""
        locations = result.get("locations", []) or []
        
        if locations:
            physical_location = locations[0].get("physicalLocation", {}) or {}
            artifact = physical_location.get("artifactLocation", {}) or {}
            uri = artifact.get("uri", "unknown")
            region = physical_location.get("region", {}) or {}
            line = region.get("startLine", 0)
            return f"{uri}:{line}"
        
        return "unknown"
    
    def _determine_vuln_type(self, rule: Dict[str, Any], result: Dict[str, Any]) -> VulnerabilityType:
        """Determine vulnerability type from rule and result"""
        props = rule.get("properties", {}) or {}
        tags = [t.lower() for t in (props.get("tags", []) or [])]
        rule_id = (rule.get("id", "") or "").lower()
        
        # Check tags first
        tag_mapping = {
            "sql-injection": VulnerabilityType.SQL_INJECTION,
            "command-injection": VulnerabilityType.COMMAND_INJECTION,
            "xss": VulnerabilityType.XSS,
            "cross-site-scripting": VulnerabilityType.XSS,
            "path-traversal": VulnerabilityType.PATH_TRAVERSAL,
            "ssrf": VulnerabilityType.SSRF,
            "crypto": VulnerabilityType.WEAK_CRYPTO,
            "cryptography": VulnerabilityType.WEAK_CRYPTO,
            "hardcoded-secret": VulnerabilityType.HARDCODED_SECRET,
            "credential": VulnerabilityType.HARDCODED_SECRET,
        }
        
        for tag in tags:
            if tag in tag_mapping:
                return tag_mapping[tag]
        
        # Check rule ID patterns
        rule_patterns = {
            "inject": VulnerabilityType.COMMAND_INJECTION,
            "sql": VulnerabilityType.SQL_INJECTION,
            "xss": VulnerabilityType.XSS,
            "xxe": VulnerabilityType.XXE,
        }
        
        for pattern, vuln_type in rule_patterns.items():
            if pattern in rule_id:
                return vuln_type
        
        # Special case for path traversal
        if "path" in rule_id and "traversal" in rule_id:
            return VulnerabilityType.PATH_TRAVERSAL
        
        return VulnerabilityType.GENERIC
    
    def _determine_severity(self, rule: Dict[str, Any], result: Dict[str, Any]) -> SeverityLevel:
        """Determine severity from rule and result"""
        # Check security-severity score first
        security_severity = (rule.get("properties", {}) or {}).get("security-severity")
        if security_severity:
            try:
                score = float(security_severity)
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                if score >= 7.0:
                    return SeverityLevel.HIGH
                if score >= 4.0:
                    return SeverityLevel.MEDIUM
                return SeverityLevel.LOW
            except Exception:
                pass
        
        # Fall back to result level
        level = (result.get("level", "warning") or "").lower()
        level_mapping = {
            "error": SeverityLevel.HIGH,
            "warning": SeverityLevel.MEDIUM,
            "note": SeverityLevel.LOW,
            "none": SeverityLevel.INFO,
        }
        
        return level_mapping.get(level, SeverityLevel.MEDIUM)
    
    def _extract_confidence(self, rule: Dict[str, Any], result: Dict[str, Any]) -> float:
        """Extract confidence from rule precision"""
        precision = ((rule.get("properties", {}) or {}).get("precision", "medium") or "").lower()
        
        precision_mapping = {
            "very-high": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }
        
        return precision_mapping.get(precision, 0.70)
    
    def _build_description(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        """Build comprehensive description from rule and result"""
        parts: List[str] = []
        
        # Add rule description
        if rule.get("fullDescription"):
            parts.append(rule["fullDescription"].get("text", ""))
        elif rule.get("shortDescription"):
            parts.append(rule["shortDescription"].get("text", ""))
        
        # Add result message if different
        msg = (result.get("message", {}) or {}).get("text", "")
        if msg and msg not in parts:
            parts.append(f"\n\nDetails: {msg}")
        
        return "\n".join(filter(None, parts))
    
    def _extract_recommendation(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        """Extract or generate recommendation"""
        # Try to get help text from rule
        help_text = ((rule.get("help", {}) or {}).get("text", "") or "").strip()
        if help_text:
            return help_text
        
        # Generate recommendation based on rule ID
        rule_id = (rule.get("id", "") or "").lower()
        
        if "sql" in rule_id:
            return "Use parameterized queries or prepared statements."
        if "injection" in rule_id:
            return "Sanitize and validate all user input before use."
        if "xss" in rule_id:
            return "Encode output and validate input to prevent XSS."
        if "crypto" in rule_id:
            return "Use strong, modern cryptographic algorithms."
        
        return "Review the code and apply security best practices."
    
    def _build_references(self, rule: Dict[str, Any], properties: Dict[str, Any]) -> List[str]:
        """Build reference URLs from rule properties"""
        refs: List[str] = []
        
        # Extract CWE references
        for tag in properties.get("tags", []) or []:
            if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                try:
                    cwe_num = tag.split("-", 1)[1]
                    refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
                except (IndexError, ValueError):
                    pass
        
        return refs