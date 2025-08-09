"""
Trivy Scanning Service

Handles Trivy command execution and filesystem scanning
Following clean architecture with single responsibility
"""

import json
import asyncio
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class ScanningService:
    """Handles Trivy scanning operations"""
    
    def __init__(self):
        pass
    
    async def scan_repository(self, repo_path: str, output_file: str) -> Optional[Dict[str, Any]]:
        """Scan repository with Trivy and return results"""
        ignore_file = None
        
        try:
            # Create ignore file for filtering
            ignore_file = self._create_ignore_file(repo_path)
            
            # Build Trivy command
            cmd = self._build_scan_command(repo_path, output_file, ignore_file)
            
            # Execute scan
            success = await self._execute_scan(cmd)
            
            if success:
                return self._load_results(output_file)
            
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
        
        finally:
            # Clean up ignore file
            if ignore_file and Path(ignore_file).exists():
                try:
                    Path(ignore_file).unlink()
                    logger.debug(f"Cleaned up ignore file: {ignore_file}")
                except Exception as e:
                    logger.warning(f"Failed to cleanup ignore file: {e}")
        
        return None
    
    def _build_scan_command(self, repo_path: str, output_file: str, ignore_file: Optional[str]) -> List[str]:
        """Build Trivy scan command with all options"""
        cmd = [
            'trivy',
            'fs',  # Filesystem scan
            repo_path,
            '--format', 'json',
            '--output', output_file,
            '--scanners', 'vuln,secret',  # Enable vulnerability and secret scanners
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            '--quiet',
            '--timeout', '10m',
            '--include-non-failures'  # Include all findings
        ]
        
        # Add ignore patterns if available
        if ignore_file:
            cmd.extend(['--ignorefile', ignore_file])
        
        # Add cache directory for better performance
        cache_dir = tempfile.gettempdir() + '/.trivy_cache'
        cmd.extend(['--cache-dir', cache_dir])
        
        return cmd
    
    async def _execute_scan(self, cmd: List[str]) -> bool:
        """Execute Trivy scan command"""
        try:
            logger.debug(f"Running Trivy: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True
            else:
                logger.error(f"Trivy failed with return code {process.returncode}")
                if stderr:
                    logger.error(f"Trivy stderr: {stderr.decode()}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to execute Trivy: {e}")
            return False
    
    def _load_results(self, output_file: str) -> Optional[Dict[str, Any]]:
        """Load and parse Trivy JSON results"""
        try:
            with open(output_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load Trivy results: {e}")
            return None
    
    def _create_ignore_file(self, repo_path: str) -> Optional[str]:
        """Create ignore file using base analyzer patterns"""
        try:
            # Import here to avoid circular dependency
            from analyzers.base import BaseAnalyzer
            from analyzers.utils.ignore_patterns import IgnorePatterns
            
            # Use centralized ignore patterns from base analyzer
            ignore_patterns = IgnorePatterns.create_gitignore_style_list("TrivyAnalyzer")
            
            ignore_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.trivyignore')
            for pattern in ignore_patterns:
                ignore_file.write(f"{pattern}\n")
            ignore_file.flush()
            ignore_file.close()
            
            logger.debug(f"Created Trivy ignore file: {ignore_file.name}")
            return ignore_file.name
            
        except Exception as e:
            logger.warning(f"Failed to create ignore file: {e}")
            return None