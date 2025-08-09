"""Repository management service for cloning and analyzing repositories."""

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Dict, Any, Optional

from ..utils.url_parser import GitHubURLParser
from mcp_detector import MCPDetector

logger = logging.getLogger(__name__)


class RepositoryService:
    """Handles repository cloning and initial analysis."""
    
    def __init__(self):
        self.url_parser = GitHubURLParser()
        self.mcp_detector = MCPDetector()
    
    async def clone_repository(self, repo_url: str, target_dir: str) -> str:
        """
        Clone repository with security constraints and subdirectory support.
        
        Args:
            repo_url: Repository URL to clone
            target_dir: Target directory for cloning
            
        Returns:
            Path to cloned repository or subdirectory
        """
        try:
            url_info = self.url_parser.parse(repo_url)
            git_url = url_info['git_url']
            subdirectory = url_info.get('subdirectory')
            specified_branch = url_info.get('branch') if 'tree/' in repo_url else None
            
            # Clone with or without branch specification
            if not specified_branch:
                await self._clone_default_branch(git_url, target_dir)
            else:
                await self._clone_specific_branch(git_url, target_dir, specified_branch)
            
            # Handle subdirectory focus if specified
            if subdirectory:
                return self._resolve_subdirectory(target_dir, subdirectory)
            
            logger.info(f"Successfully cloned repository to {target_dir}")
            return target_dir
            
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            raise
    
    async def _clone_default_branch(self, git_url: str, target_dir: str) -> None:
        """Clone repository using default branch."""
        clone_cmd = [
            'git', 'clone',
            '--depth', '1',
            '--single-branch',
            '--no-tags',
            git_url,
            target_dir
        ]
        
        process = await asyncio.create_subprocess_exec(
            *clone_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            logger.info("Successfully cloned repository using default branch")
        else:
            error_msg = stderr.decode()
            raise RuntimeError(f"Git clone failed: {error_msg}")
    
    async def _clone_specific_branch(self, git_url: str, target_dir: str, 
                                    branch: str) -> None:
        """Clone repository with specific branch."""
        clone_cmd = [
            'git', 'clone',
            '--depth', '1',
            '--single-branch',
            '--branch', branch,
            '--no-tags',
            git_url,
            target_dir
        ]
        
        process = await asyncio.create_subprocess_exec(
            *clone_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if process.returncode == 0:
            logger.info(f"Successfully cloned repository using branch '{branch}'")
        else:
            error_msg = stderr.decode()
            logger.warning(f"Clone failed with branch '{branch}': {error_msg}")
            logger.info("Attempting to clone with repository's default branch as fallback")
            
            # Clean up failed attempt
            if Path(target_dir).exists():
                shutil.rmtree(target_dir, ignore_errors=True)
            
            # Fallback to default branch
            await self._clone_default_branch(git_url, target_dir)
            logger.info("Successfully cloned repository using default branch (fallback)")
    
    def _resolve_subdirectory(self, target_dir: str, subdirectory: str) -> str:
        """Resolve subdirectory path if specified."""
        subdir_path = Path(target_dir) / subdirectory
        
        if subdir_path.exists() and subdir_path.is_dir():
            logger.info(f"Focusing analysis on subdirectory: {subdirectory}")
            return str(subdir_path)
        else:
            logger.warning(f"Subdirectory {subdirectory} not found, analyzing full repository")
            return target_dir
    
    async def analyze_project(self, repo_path: str) -> Dict[str, Any]:
        """
        Detect project type and MCP configuration.
        
        Args:
            repo_path: Path to repository
            
        Returns:
            Project information dictionary
        """
        try:
            project_info = await self.mcp_detector.analyze_project(repo_path)
            
            # Log detection results
            if project_info.get('is_mcp'):
                confidence_explanation = self.mcp_detector.get_detection_confidence_explanation(project_info)
                logger.info(f"MCP server detected: {confidence_explanation}")
                
                detected_packages = project_info.get('detected_packages', [])
                if detected_packages:
                    logger.info(f"Detected MCP packages: {detected_packages}")
            else:
                logger.info(
                    f"Project type: {project_info['type']} "
                    f"({project_info['language'] or 'unknown language'}), MCP: No"
                )
            
            return project_info
            
        except Exception as e:
            logger.error(f"Project analysis failed: {e}")
            return self._default_project_info()
    
    def _default_project_info(self) -> Dict[str, Any]:
        """Return default project info on analysis failure."""
        return {
            'type': 'unknown',
            'language': None,
            'is_mcp': False,
            'mcp_config': None,
            'dependencies': [],
            'detection_method': 'analysis_failed',
            'confidence': 0.0
        }