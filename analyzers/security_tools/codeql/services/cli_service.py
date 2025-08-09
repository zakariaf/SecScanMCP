"""
CLI Service for CodeQL Analysis

Manages CodeQL CLI discovery, validation, and command execution
Following clean architecture with single responsibility
"""

import os
import asyncio
import subprocess
import logging
from typing import Optional, List, Dict, Any
from pathlib import Path

logger = logging.getLogger(__name__)


class CLIService:
    """Handles CodeQL CLI management and command execution"""
    
    def __init__(self):
        self.cli_path: Optional[str] = None
        self._discovery_attempted = False
    
    def discover_cli(self) -> bool:
        """Find and validate CodeQL CLI"""
        if self._discovery_attempted and self.cli_path:
            return True
            
        self._discovery_attempted = True
        
        # Try system PATH first
        if self._try_system_path():
            return True
            
        # Try known locations
        if self._try_known_locations():
            return True
            
        logger.error("CodeQL CLI not found in PATH or known locations")
        return False
    
    def validate_cli(self) -> bool:
        """Validate CodeQL CLI installation"""
        if not self.cli_path:
            logger.error("CodeQL CLI not found")
            return False
            
        try:
            result = subprocess.run(
                [self.cli_path, "--version"], 
                capture_output=True, 
                text=True, 
                timeout=15
            )
            
            if result.returncode == 0:
                logger.info(f"CodeQL version: {result.stdout.strip()}")
                return True
            else:
                logger.error(f"CodeQL validation failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to validate CodeQL: {e}")
            return False
    
    def is_available(self) -> bool:
        """Check if CodeQL CLI is available and validated"""
        return self.cli_path is not None
    
    async def run_command(self, cmd: List[str], timeout: int = 300, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        """Execute CodeQL command asynchronously"""
        if not self.cli_path:
            raise RuntimeError("CodeQL CLI not available")
            
        full_cmd = [self.cli_path] + cmd
        logger.debug(f"Running CodeQL command: {' '.join(full_cmd)}")
        
        try:
            process = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return subprocess.CompletedProcess(
                args=full_cmd,
                returncode=process.returncode,
                stdout=stdout.decode('utf-8', errors='ignore'),
                stderr=stderr.decode('utf-8', errors='ignore')
            )
            
        except asyncio.TimeoutError:
            logger.error(f"CodeQL command timed out after {timeout}s")
            if 'process' in locals():
                process.kill()
                await process.wait()
            raise
        except Exception as e:
            logger.error(f"CodeQL command failed: {e}")
            raise
    
    def _try_system_path(self) -> bool:
        """Try to find CodeQL in system PATH"""
        try:
            result = subprocess.run(
                ["which", "codeql"], 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0 and result.stdout.strip():
                self.cli_path = result.stdout.strip()
                logger.info(f"Found CodeQL CLI in PATH: {self.cli_path}")
                return True
                
        except Exception:
            pass
            
        return False
    
    def _try_known_locations(self) -> bool:
        """Try known CodeQL installation locations"""
        known_locations = [
            "/opt/codeql/codeql",
            "/usr/local/bin/codeql", 
            "/usr/bin/codeql"
        ]
        
        for location in known_locations:
            if os.path.exists(location) and os.access(location, os.X_OK):
                self.cli_path = location
                logger.info(f"Found CodeQL CLI at: {self.cli_path}")
                return True
                
        return False