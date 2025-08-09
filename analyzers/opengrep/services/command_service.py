"""
Command Service for OpenGrep Analysis

Handles OpenGrep command execution and process management
Following clean architecture with single responsibility
"""

import asyncio
import logging
from typing import List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


class CommandService:
    """Handles OpenGrep command execution"""
    
    def __init__(self):
        self.opengrep_available = None
        self.semgrep_fallback = None
    
    async def get_opengrep_command(self) -> Optional[List[str]]:
        """Get OpenGrep command, with fallback to Semgrep"""
        if self.opengrep_available is None:
            await self._check_tool_availability()
        
        if self.opengrep_available:
            return ['opengrep']
        elif self.semgrep_fallback:
            logger.info("OpenGrep not available, using Semgrep fallback")
            return ['semgrep']
        else:
            logger.warning("Neither OpenGrep nor Semgrep available")
            return None
    
    async def run_with_ruleset(self, repo_path: str, ruleset: str, 
                              ignore_file: str = None) -> Tuple[bool, str]:
        """Run OpenGrep with specific ruleset"""
        cmd = await self.get_opengrep_command()
        if not cmd:
            return False, "No analysis tool available"
        
        # Build command
        full_cmd = cmd + [
            '--config', ruleset,
            '--json',
            '--no-git-ignore',
            '--timeout', '300'
        ]
        
        if ignore_file:
            full_cmd.extend(['--exclude-file', ignore_file])
        
        full_cmd.append(repo_path)
        
        return await self._execute_command(full_cmd)
    
    async def run_with_custom_rules(self, repo_path: str, rules_file: str,
                                   ignore_file: str = None) -> Tuple[bool, str]:
        """Run OpenGrep with custom rules file"""
        cmd = await self.get_opengrep_command()
        if not cmd:
            return False, "No analysis tool available"
        
        # Build command  
        full_cmd = cmd + [
            '--config', rules_file,
            '--json',
            '--no-git-ignore',
            '--timeout', '300'
        ]
        
        if ignore_file:
            full_cmd.extend(['--exclude-file', ignore_file])
        
        full_cmd.append(repo_path)
        
        return await self._execute_command(full_cmd)
    
    async def _check_tool_availability(self):
        """Check if OpenGrep or Semgrep are available"""
        # Check OpenGrep
        try:
            result = await asyncio.create_subprocess_exec(
                'opengrep', '--version',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await result.wait()
            self.opengrep_available = (result.returncode == 0)
        except FileNotFoundError:
            self.opengrep_available = False
        
        # Check Semgrep fallback if OpenGrep not available
        if not self.opengrep_available:
            try:
                result = await asyncio.create_subprocess_exec(
                    'semgrep', '--version',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                await result.wait()
                self.semgrep_fallback = (result.returncode == 0)
            except FileNotFoundError:
                self.semgrep_fallback = False
    
    async def _execute_command(self, cmd: List[str]) -> Tuple[bool, str]:
        """Execute OpenGrep command and return results"""
        try:
            logger.debug(f"Executing: {' '.join(cmd)}")
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True, stdout.decode('utf-8', errors='ignore')
            else:
                logger.warning(f"Command failed with code {process.returncode}")
                logger.debug(f"stderr: {stderr.decode('utf-8', errors='ignore')}")
                return False, stdout.decode('utf-8', errors='ignore')
                
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            return False, ""