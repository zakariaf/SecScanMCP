"""
Bandit Scan Service

Handles Bandit command execution and result parsing
Following clean architecture with single responsibility
"""

import json
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ScanService:
    """Handles Bandit scan execution"""
    
    # Base Bandit command template
    BASE_COMMAND_PREFIX = ['python3', '-m', 'bandit', '-r']
    BASE_COMMAND_SUFFIX = ['-f', 'json', '-ll', '--quiet']
    
    async def run_scan(self, repo_path: str, ignore_file: Optional[str] = None) -> Dict[str, Any]:
        """Run Bandit scan and return parsed results"""
        try:
            cmd = self._build_command(repo_path, ignore_file)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Bandit returns non-zero if issues found, which is expected
            return self._parse_results(stdout, stderr)
            
        except Exception as e:
            logger.error(f"Bandit scan execution failed: {e}")
            return {}
    
    def _build_command(self, repo_path: str, ignore_file: Optional[str] = None) -> list:
        """Build Bandit command with correct argument order"""
        # Build command with repo_path in correct position (after -r)
        cmd = self.BASE_COMMAND_PREFIX.copy()
        cmd.append(repo_path)
        cmd.extend(self.BASE_COMMAND_SUFFIX)
        
        # Add ignore patterns if provided
        if ignore_file:
            cmd.extend(['--exclude', ignore_file])
        
        return cmd
    
    def _parse_results(self, stdout: bytes, stderr: bytes) -> Dict[str, Any]:
        """Parse Bandit JSON output"""
        if not stdout:
            if stderr:
                logger.warning(f"Bandit stderr: {stderr.decode()}")
            return {}
        
        try:
            return json.loads(stdout.decode())
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Bandit output: {e}")
            return {}