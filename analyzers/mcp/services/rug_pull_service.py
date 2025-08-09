"""Rug pull vulnerability analysis service for MCP servers."""

import re
import ast
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class RugPullService:
    """Detects rug pull vulnerabilities in MCP server implementations."""
    
    def __init__(self):
        self.rug_pull_indicators = self._build_rug_pull_patterns()
    
    def _build_rug_pull_patterns(self) -> List[Dict[str, Any]]:
        """Build patterns for detecting rug pull vulnerabilities."""
        return [
            {
                'pattern': r'(?i)(backdoor|malicious|exploit|payload)\s*=',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Suspicious Variable Names'
            },
            {
                'pattern': r'(?i)import\s+(urllib|requests|socket)\s*;?\s*exec',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Malicious Import and Execute Pattern'
            },
            {
                'pattern': r'(?i)(eval|exec)\s*\(\s*(input|raw_input|sys\.argv)',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Dynamic Code Execution from Input'
            },
            {
                'pattern': r'(?i)base64\.b64decode\([\'"][A-Za-z0-9+/=]{20,}[\'"]',
                'severity': SeverityLevel.HIGH,
                'title': 'Suspicious Base64 Payload'
            },
        ]
    
    async def analyze_rug_pull_vulnerabilities(self, repo_path: str) -> List[Finding]:
        """
        Analyze for rug pull vulnerabilities.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of rug pull findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Check for suspicious patterns in source code
        findings.extend(self._check_suspicious_patterns(repo))
        
        # Check for obfuscated code
        findings.extend(self._check_obfuscated_code(repo))
        
        # Check for unusual network activity
        findings.extend(self._check_network_activity(repo))
        
        # Check for unexpected file operations
        findings.extend(self._check_file_operations(repo))
        
        return findings
    
    def _check_suspicious_patterns(self, repo: Path) -> List[Finding]:
        """Check for suspicious code patterns."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(
                    self._scan_file_patterns(py_file)
                )
        
        return findings
    
    def _check_obfuscated_code(self, repo: Path) -> List[Finding]:
        """Check for code obfuscation indicators."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(
                    self._check_obfuscation_in_file(py_file)
                )
        
        return findings
    
    def _check_network_activity(self, repo: Path) -> List[Finding]:
        """Check for suspicious network activity patterns."""
        findings = []
        
        network_patterns = [
            r'(?i)(requests|urllib|socket)\..*\.(get|post|connect)\s*\([\'"][^\'"]*(attacker|malicious|evil|hack)',
            r'(?i)socket\.socket\(\).*\.connect\(\s*\([\'"][^\'\"]*\d+\.\d+\.\d+\.\d+',
            r'(?i)(curl|wget)\s+.*\|\s*(bash|sh|python)',
        ]
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(
                    self._scan_file_for_patterns(py_file, network_patterns, 'Suspicious Network Activity')
                )
        
        return findings
    
    def _check_file_operations(self, repo: Path) -> List[Finding]:
        """Check for unexpected file operations."""
        findings = []
        
        file_patterns = [
            r'(?i)(open|write|delete).*\.(ssh|shadow|passwd|hosts)',
            r'(?i)os\.system\s*\(\s*[\'"]rm\s+-rf',
            r'(?i)shutil\.rmtree\s*\(\s*[\'"]/',
        ]
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(
                    self._scan_file_for_patterns(py_file, file_patterns, 'Suspicious File Operations')
                )
        
        return findings
    
    def _scan_file_patterns(self, file_path: Path) -> List[Finding]:
        """Scan file for rug pull patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern_info in self.rug_pull_indicators:
                matches = re.finditer(pattern_info['pattern'], content)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Rug Pull Risk: {pattern_info['title']}",
                        description=f"Suspicious pattern detected in {file_path.name}",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.MALICIOUS_CODE,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.85
                    ))
        
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _check_obfuscation_in_file(self, file_path: Path) -> List[Finding]:
        """Check individual file for code obfuscation."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for excessive string manipulation
            if self._has_excessive_obfuscation(content):
                findings.append(Finding(
                    title="Code Obfuscation Detected",
                    description="File contains suspicious code obfuscation patterns",
                    severity=SeverityLevel.HIGH,
                    vulnerability_type=VulnerabilityType.MALICIOUS_CODE,
                    location=str(file_path),
                    confidence=0.7
                ))
        
        except Exception as e:
            logger.warning(f"Error checking obfuscation in {file_path}: {e}")
        
        return findings
    
    def _scan_file_for_patterns(self, file_path: Path, patterns: List[str], 
                               category: str) -> List[Finding]:
        """Scan file for specific patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern in patterns:
                matches = re.finditer(pattern, content)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Rug Pull Risk: {category}",
                        description=f"Suspicious {category.lower()} pattern in {file_path.name}",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.MALICIOUS_CODE,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.8
                    ))
        
        except Exception as e:
            logger.warning(f"Error scanning patterns in {file_path}: {e}")
        
        return findings
    
    def _has_excessive_obfuscation(self, content: str) -> bool:
        """Check if content has excessive obfuscation."""
        # Count base64/hex strings
        b64_matches = len(re.findall(r'[A-Za-z0-9+/]{20,}=*', content))
        hex_matches = len(re.findall(r'\\x[0-9a-fA-F]{2}', content))
        
        # Count string concatenations
        concat_matches = len(re.findall(r'[\'"][^\'\"]*[\'\"]\s*\+', content))
        
        # Thresholds for suspicious activity
        return (b64_matches > 3 or hex_matches > 10 or concat_matches > 15)
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        exclude_patterns = [
            'test_', 'tests/', '__pycache__/',
            'node_modules/', '.git/', 'venv/'
        ]
        
        file_str = str(file_path)
        return not any(pattern in file_str for pattern in exclude_patterns)
    
    def _extract_context(self, content: str, position: int, 
                        context_chars: int = 100) -> str:
        """Extract context around match position."""
        start = max(0, position - context_chars // 2)
        end = min(len(content), position + context_chars // 2)
        return content[start:end].strip()