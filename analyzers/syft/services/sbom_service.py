"""
SBOM Service

Handles Syft SBOM generation and file management
Following clean architecture with single responsibility
"""

import json
import asyncio
import tempfile
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SBOMService:
    """Handles SBOM generation using Syft"""
    
    def __init__(self):
        self.command_template = [
            'syft',
            '--quiet',
            '--scope', 'all-layers',
            '--catalogers', 'all'
        ]
    
    async def generate_sbom(self, repo_path: str) -> Optional[Dict[str, Any]]:
        """Generate SBOM for repository using Syft"""
        try:
            sbom_path = tempfile.mktemp(suffix='.json')
            
            # Build command
            cmd = self.command_template + [
                repo_path,
                '-o', f'json={sbom_path}'
            ]
            
            # Execute Syft
            success = await self._execute_syft(cmd)
            if not success:
                return None
            
            # Read and return SBOM data
            sbom_data = self._read_sbom_file(sbom_path)
            
            # Cleanup
            self._cleanup_file(sbom_path)
            
            return sbom_data
            
        except FileNotFoundError:
            logger.warning("Syft not found, skipping SBOM analysis")
            return None
        except Exception as e:
            logger.error(f"SBOM generation failed: {e}")
            return None
    
    async def _execute_syft(self, cmd: list) -> bool:
        """Execute Syft command"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"Syft execution failed: {stderr.decode()}")
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to execute Syft: {e}")
            return False
    
    def _read_sbom_file(self, sbom_path: str) -> Optional[Dict[str, Any]]:
        """Read SBOM data from file"""
        try:
            if not Path(sbom_path).exists():
                logger.error("SBOM file not created")
                return None
            
            with open(sbom_path, 'r') as f:
                return json.load(f)
                
        except Exception as e:
            logger.error(f"Failed to read SBOM file: {e}")
            return None
    
    def _cleanup_file(self, file_path: str):
        """Clean up temporary file"""
        try:
            if Path(file_path).exists():
                Path(file_path).unlink()
        except Exception as e:
            logger.debug(f"Failed to cleanup file {file_path}: {e}")