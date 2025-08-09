"""OAuth token and credential security analysis service."""

import re
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class TokenSecurityService:
    """Detects OAuth token exposure and credential security issues."""
    
    def __init__(self):
        self.token_patterns = self._build_token_patterns()
    
    def _build_token_patterns(self) -> List[Dict[str, Any]]:
        """Build comprehensive token detection patterns."""
        return [
            {
                'pattern': r'(?i)(oauth_token|access_token|bearer_token|api_key)\s*[=:]\s*["\'][^"\']+["\']',
                'severity': SeverityLevel.CRITICAL,
                'title': 'OAuth Token Exposure in Configuration'
            },
            {
                'pattern': r'(?i)bearer\s+[a-zA-Z0-9\-_]{20,}',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Bearer Token Exposure'
            },
            {
                'pattern': r'(?i)(client_secret|api_secret)\s*[=:]\s*["\'][^"\']{10,}["\']',
                'severity': SeverityLevel.CRITICAL,
                'title': 'API Secret Exposure'
            },
            {
                'pattern': r'(?i)Authorization:\s*Bearer\s+[a-zA-Z0-9\-_]{20,}',
                'severity': SeverityLevel.HIGH,
                'title': 'Authorization Header Token Exposure'
            },
        ]
    
    async def analyze_oauth_exposure(self, repo_path: str) -> List[Finding]:
        """
        Analyze repository for OAuth token exposure.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of token exposure findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Check configuration files
        findings.extend(self._check_config_files(repo))
        
        # Check source code files
        findings.extend(self._check_source_files(repo))
        
        # Check environment files
        findings.extend(self._check_env_files(repo))
        
        return findings
    
    def _check_config_files(self, repo: Path) -> List[Finding]:
        """Check configuration files for token exposure."""
        findings = []
        
        config_patterns = [
            '*.json', '*.yaml', '*.yml', '*.toml',
            '*.cfg', '*.ini', 'mcp.*'
        ]
        
        for pattern in config_patterns:
            for config_file in repo.glob(f'**/{pattern}'):
                if config_file.is_file():
                    findings.extend(
                        self._scan_file_for_tokens(config_file)
                    )
        
        return findings
    
    def _check_source_files(self, repo: Path) -> List[Finding]:
        """Check source code files for hardcoded tokens."""
        findings = []
        
        source_patterns = ['*.py', '*.js', '*.ts', '*.go', '*.java']
        
        for pattern in source_patterns:
            for source_file in repo.glob(f'**/{pattern}'):
                if self._should_scan_file(source_file):
                    findings.extend(
                        self._scan_file_for_tokens(source_file)
                    )
        
        return findings
    
    def _check_env_files(self, repo: Path) -> List[Finding]:
        """Check environment files for token exposure."""
        findings = []
        
        env_patterns = [
            '.env*', '*.env', 'environment*',
            'secrets*', 'credentials*'
        ]
        
        for pattern in env_patterns:
            for env_file in repo.glob(f'**/{pattern}'):
                if env_file.is_file():
                    findings.extend(
                        self._scan_file_for_tokens(env_file)
                    )
        
        return findings
    
    def _scan_file_for_tokens(self, file_path: Path) -> List[Finding]:
        """Scan individual file for token patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern_info in self.token_patterns:
                matches = re.finditer(pattern_info['pattern'], content)
                
                for match in matches:
                    findings.append(Finding(
                        title=pattern_info['title'],
                        description=f"Potential token exposure in {file_path.name}",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.9
                    ))
        
        except Exception as e:
            logger.warning(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if file should be scanned."""
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