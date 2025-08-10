"""
Grype Scan Service

Handles Grype command execution and result parsing
Following clean architecture with single responsibility
"""

import json
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class ScanService:
    """Handles Grype scan execution"""
    
    # Base command options
    BASE_COMMAND = ['grype', '-o', 'json', '--quiet']
    ADDITIONAL_OPTIONS = [
        '--add-cpes-if-none',  # Generate CPEs if missing
        '--by-cve',           # Organize by CVE
        '--scope', 'all-layers'  # Scan all layers if container
    ]
    
    # Exclusion patterns for direct filesystem scans
    EXCLUSIONS = [
        '--exclude', '.git/**',
        '--exclude', '**/node_modules/**',
        '--exclude', '**/__pycache__/**'
    ]
    
    async def run_scan(self, repo_path: str, sbom_path: Optional[str] = None) -> Dict[str, Any]:
        """Run Grype scan with optimal strategy"""
        try:
            if sbom_path:
                # Scan using SBOM (faster)
                cmd = self._build_sbom_command(sbom_path)
            else:
                # Direct filesystem scan
                cmd = self._build_filesystem_command(repo_path)
            
            # Execute scan
            stdout, stderr, return_code = await self._execute_command(cmd)
            
            # Parse results
            return self._parse_results(stdout, stderr, return_code)
            
        except Exception as e:
            logger.error(f"Grype scan execution failed: {e}")
            return {}
    
    def _build_sbom_command(self, sbom_path: str) -> list:
        """Build command for SBOM-based scan"""
        cmd = self.BASE_COMMAND.copy()
        cmd.append(f'sbom:{sbom_path}')
        cmd.extend(self.ADDITIONAL_OPTIONS)
        return cmd
    
    def _build_filesystem_command(self, repo_path: str) -> list:
        """Build command for direct filesystem scan"""
        cmd = self.BASE_COMMAND.copy()
        cmd.append(f'dir:{repo_path}')
        cmd.extend(self.EXCLUSIONS)
        cmd.extend(self.ADDITIONAL_OPTIONS)
        return cmd
    
    async def _execute_command(self, cmd: list) -> tuple:
        """Execute Grype command"""
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        return stdout, stderr, process.returncode
    
    def _parse_results(self, stdout: bytes, stderr: bytes, return_code: int) -> Dict[str, Any]:
        """Parse Grype scan results"""
        if stdout:
            try:
                return json.loads(stdout.decode())
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Grype output: {e}")
        
        if return_code != 0 and stderr:
            logger.error(f"Grype scan failed: {stderr.decode()}")
        
        return {}