"""
SBOM Service for Grype

Manages SBOM discovery and creation for optimized Grype scanning
Following clean architecture with single responsibility
"""

import asyncio
import tempfile
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class SBOMService:
    """Manages SBOM files for Grype scanning optimization"""
    
    # SBOM file patterns to look for
    SBOM_PATTERNS = ['*sbom*.json', '*sbom*.spdx', '*sbom*.cdx']
    
    # Syft command for SBOM generation
    SYFT_COMMAND = ['syft', '--quiet']
    
    async def get_or_create_sbom(self, repo_path: str) -> Optional[str]:
        """Get existing SBOM or create one with Syft"""
        # First, try to find existing SBOM
        existing_sbom = self._find_existing_sbom(repo_path)
        if existing_sbom:
            return existing_sbom
        
        # Try to create SBOM with Syft
        return await self._create_sbom_with_syft(repo_path)
    
    def cleanup_temp_sbom(self, sbom_path: str):
        """Clean up temporary SBOM file"""
        if sbom_path and self._is_temp_file(sbom_path):
            try:
                Path(sbom_path).unlink()
                logger.debug(f"Cleaned up temporary SBOM: {sbom_path}")
            except Exception as e:
                logger.debug(f"Failed to cleanup SBOM {sbom_path}: {e}")
    
    def _find_existing_sbom(self, repo_path: str) -> Optional[str]:
        """Look for existing SBOM files in repository"""
        repo = Path(repo_path)
        
        for pattern in self.SBOM_PATTERNS:
            for sbom_file in repo.glob(pattern):
                if sbom_file.is_file():
                    logger.info(f"Found existing SBOM: {sbom_file}")
                    return str(sbom_file)
        
        return None
    
    async def _create_sbom_with_syft(self, repo_path: str) -> Optional[str]:
        """Generate SBOM with Syft if available"""
        try:
            sbom_path = tempfile.mktemp(suffix='.json')
            
            cmd = self.SYFT_COMMAND + [
                repo_path,
                '-o', f'json={sbom_path}'
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await process.communicate()
            
            if process.returncode == 0 and Path(sbom_path).exists():
                logger.info("Generated SBOM with Syft for faster scanning")
                return sbom_path
            
        except FileNotFoundError:
            logger.debug("Syft not available for SBOM generation")
        except Exception as e:
            logger.debug(f"Failed to create SBOM: {e}")
        
        return None
    
    def _is_temp_file(self, file_path: str) -> bool:
        """Check if file is a temporary file that should be cleaned up"""
        return file_path.startswith('/tmp/') or 'tmp' in file_path.lower()