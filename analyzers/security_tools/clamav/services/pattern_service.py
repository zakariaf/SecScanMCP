"""
ClamAV Pattern Service

Handles additional malware pattern detection beyond ClamAV signatures
Following clean architecture with single responsibility
"""

import re
import logging
from pathlib import Path
from typing import List

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class PatternService:
    """Handles additional malware pattern detection"""
    
    # Known malware patterns that ClamAV might miss
    ADDITIONAL_PATTERNS = [
        # MCP-specific backdoors
        {
            'pattern': rb'exec\s*\(\s*base64\.b64decode',
            'name': 'MCP.Backdoor.ExecBase64',
            'severity': SeverityLevel.CRITICAL
        },
        {
            'pattern': rb'__import__\s*\(\s*["\']os["\']\s*\)\.system',
            'name': 'MCP.Backdoor.ImportSystem',
            'severity': SeverityLevel.CRITICAL
        },
        {
            'pattern': rb'subprocess\.Popen\s*\([^)]*shell\s*=\s*True',
            'name': 'MCP.Suspicious.ShellExec',
            'severity': SeverityLevel.HIGH
        },
        # Cryptominer signatures
        {
            'pattern': rb'stratum\+tcp://|monero|xmrig|coinhive',
            'name': 'MCP.Miner.Generic',
            'severity': SeverityLevel.HIGH
        },
        # Obfuscated code patterns
        {
            'pattern': rb'eval\s*\(\s*compile\s*\(',
            'name': 'MCP.Obfuscation.EvalCompile',
            'severity': SeverityLevel.HIGH
        }
    ]
    
    def __init__(self, base_analyzer):
        self.base_analyzer = base_analyzer
    
    async def scan_for_patterns(self, repo_path: str) -> List[Finding]:
        """Scan for additional malware patterns that ClamAV might miss"""
        findings = []
        
        for file_path in Path(repo_path).rglob('*'):
            if self._should_scan_file(file_path):
                file_findings = await self._scan_file_patterns(file_path, repo_path)
                findings.extend(file_findings)
        
        return findings
    
    async def _scan_file_patterns(self, file_path: Path, repo_path: str) -> List[Finding]:
        """Scan single file for malware patterns"""
        findings = []
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            for pattern_info in self.ADDITIONAL_PATTERNS:
                if re.search(pattern_info['pattern'], content):
                    finding = self._create_pattern_finding(
                        file_path, repo_path, pattern_info
                    )
                    findings.append(finding)
                    break  # Only report first matching pattern per file
                    
        except Exception as e:
            logger.debug(f"Failed to scan patterns in {file_path}: {e}")
        
        return findings
    
    def _create_pattern_finding(self, file_path: Path, repo_path: str, 
                               pattern_info: dict) -> Finding:
        """Create Finding object for detected pattern"""
        return self.base_analyzer.create_finding(
            vulnerability_type=VulnerabilityType.MALWARE,
            severity=pattern_info['severity'],
            confidence=0.8,
            title=f"Suspicious Pattern: {pattern_info['name']}",
            description=f"Detected suspicious pattern that matches {pattern_info['name']} signature",
            location=str(file_path.relative_to(repo_path)),
            recommendation="Review the code for potential malicious behavior",
            references=[
                "https://docs.python.org/3/library/security_warnings.html",
                "https://owasp.org/www-community/attacks/Code_Injection"
            ],
            evidence={
                'pattern_name': pattern_info['name'],
                'file_type': file_path.suffix,
                'detection_method': 'pattern_matching'
            }
        )
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned for patterns"""
        if not file_path.is_file():
            return False
        
        # Only scan executable/script files
        scan_extensions = {'.py', '.js', '.sh', '.bat', '.ps1', '.php', '.rb'}
        return file_path.suffix.lower() in scan_extensions