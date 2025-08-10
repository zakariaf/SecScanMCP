"""Docker container management for dynamic analysis."""

import docker
import tempfile
import logging
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class DockerManager:
    """Manages Docker containers for dynamic analysis."""
    
    def __init__(self):
        self.docker_client = None
        self.containers = []
    
    async def initialize_environment(self) -> bool:
        """
        Initialize Docker environment for analysis.
        
        Returns:
            True if initialization successful, False otherwise
        """
        try:
            self.docker_client = docker.from_env()
            
            # Test Docker connection
            version_info = self.docker_client.version()
            logger.info(f"Docker initialized: {version_info['Version']}")
            
            return True
            
        except docker.errors.DockerException as e:
            logger.error(f"Docker initialization failed: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during Docker init: {e}")
            return False
    
    async def create_sandbox(self, repo_path: str, 
                           runtime_info: Dict[str, Any]) -> Optional:
        """
        Create secure sandbox container for MCP server.
        
        Args:
            repo_path: Path to repository
            runtime_info: Runtime configuration
            
        Returns:
            Docker container or None if creation failed
        """
        if not self.docker_client:
            logger.error("Docker client not initialized")
            return None
        
        try:
            # Determine base image
            base_image = self._get_base_image(runtime_info)
            
            # Create container configuration
            container_config = self._build_container_config(
                repo_path, runtime_info, base_image
            )
            
            # Create container
            container = self.docker_client.containers.run(
                **container_config
            )
            
            self.containers.append(container)
            logger.info(f"Created sandbox container: {container.short_id}")
            
            # Setup container environment
            await self._setup_container(container, repo_path, runtime_info)
            
            return container
            
        except Exception as e:
            logger.error(f"Failed to create sandbox: {e}")
            return None
    
    def _get_base_image(self, runtime_info: Dict[str, Any]) -> str:
        """Determine appropriate base image."""
        language = runtime_info.get('language', 'python')
        
        images = {
            'python': 'python:3.11-slim',
            'node': 'node:18-alpine',
            'typescript': 'node:18-alpine'
        }
        
        return images.get(language, 'python:3.11-slim')
    
    def _build_container_config(self, repo_path: str, 
                               runtime_info: Dict[str, Any],
                               base_image: str) -> Dict[str, Any]:
        """Build container configuration."""
        # Check if advanced analysis is requested
        advanced_mode = runtime_info.get('advanced_analysis', False)
        
        if advanced_mode:
            return self._build_advanced_container_config(repo_path, runtime_info, base_image)
        else:
            return self._build_basic_container_config(repo_path, runtime_info, base_image)
    
    def _build_basic_container_config(self, repo_path: str,
                                     runtime_info: Dict[str, Any],
                                     base_image: str) -> Dict[str, Any]:
        """Build basic container configuration."""
        return {
            'image': base_image,
            'detach': True,
            'network_mode': 'bridge',
            'volumes': {
                repo_path: {'bind': '/workspace', 'mode': 'ro'}
            },
            'working_dir': '/workspace',
            'command': ['tail', '-f', '/dev/null'],  # Keep container alive
            'mem_limit': '512m',
            'cpu_quota': 50000,  # 50% CPU limit
            'security_opt': ['no-new-privileges:true'],
            'cap_drop': ['ALL'],
            'cap_add': ['SETGID', 'SETUID'],  # Minimal required caps
            'read_only': False,
            'tmpfs': {'/tmp': 'noexec,nosuid,size=100m'}
        }
    
    def _build_advanced_container_config(self, repo_path: str,
                                        runtime_info: Dict[str, Any], 
                                        base_image: str) -> Dict[str, Any]:
        """Build advanced container configuration with enhanced monitoring."""
        import time
        
        return {
            'image': base_image,
            'detach': True,
            'network_mode': 'bridge',  # Allow monitored network access
            'volumes': {
                repo_path: {'bind': '/workspace', 'mode': 'ro'}  # Read-only mount
            },
            'working_dir': '/workspace',
            'command': '/bin/sh -c "sleep 3600"',  # Keep alive for analysis
            'environment': {
                **runtime_info.get('environment', {}),
                'MCP_ANALYSIS_MODE': 'true',
                'PYTHONUNBUFFERED': '1'
            },
            
            # Enhanced resources for analysis
            'mem_limit': '1024m',  # Increased for analysis
            'cpu_quota': 100000,  # 1.0 CPU
            
            # Enhanced security constraints
            'security_opt': [
                'no-new-privileges:true',
                'seccomp=unconfined'  # Allow system call monitoring
            ],
            'cap_drop': ['ALL'],
            'cap_add': ['NET_ADMIN'],  # For network monitoring
            'user': 'root',  # Temporary for advanced monitoring
            
            # Monitoring and logging labels
            'labels': {
                'mcp.analysis': 'true',
                'mcp.analyzer': 'dynamic',
                'mcp.session': str(int(time.time()))
            },
            
            'read_only': False,
            'tmpfs': {'/tmp': 'noexec,nosuid,size=100m'}
        }
    
    async def _setup_container(self, container, repo_path: str,
                             runtime_info: Dict[str, Any]) -> None:
        """Setup container environment for MCP server."""
        try:
            # Install monitoring tools first for advanced analysis
            await self._install_monitoring_tools(container)
            
            # Install dependencies based on language
            language = runtime_info.get('language', 'python')
            
            if language == 'python':
                await self._setup_python_environment(container)
            elif language in ['node', 'typescript']:
                await self._setup_node_environment(container)
            
            # Set up working directory permissions
            container.exec_run(
                'chmod -R 755 /workspace',
                privileged=False
            )
            
            logger.info(f"Container {container.short_id} setup completed")
            
        except Exception as e:
            logger.error(f"Container setup failed: {e}")
    
    async def _install_monitoring_tools(self, container) -> None:
        """Install system monitoring tools for advanced analysis"""
        try:
            # Install monitoring and network analysis tools
            monitoring_setup = """
            apt-get update && apt-get install -y --no-install-recommends \
                netstat-nat ss lsof strace tcpdump procfs \
                curl wget nc-openbsd psmisc \
                && rm -rf /var/lib/apt/lists/*
            """
            
            result = container.exec_run(f'/bin/sh -c "{monitoring_setup}"', detach=False)
            if result.exit_code == 0:
                logger.info("Monitoring tools installed successfully")
            else:
                logger.warning(f"Some monitoring tools may not have installed: {result.output}")
                
        except Exception as e:
            logger.warning(f"Monitoring tools installation failed: {e}")
    
    async def _setup_python_environment(self, container) -> None:
        """Setup Python environment in container."""
        try:
            # Check if requirements.txt exists
            result = container.exec_run('test -f /workspace/requirements.txt')
            
            if result.exit_code == 0:
                # Install requirements
                install_result = container.exec_run(
                    'pip install -r /workspace/requirements.txt',
                    workdir='/workspace'
                )
                
                if install_result.exit_code == 0:
                    logger.info("Python dependencies installed successfully")
                else:
                    logger.warning(f"Dependency installation issues: {install_result.output}")
            else:
                logger.info("No requirements.txt found, skipping dependency installation")
            
        except Exception as e:
            logger.error(f"Python environment setup failed: {e}")
    
    async def _setup_node_environment(self, container) -> None:
        """Setup Node.js environment in container."""
        try:
            # Check if package.json exists
            result = container.exec_run('test -f /workspace/package.json')
            
            if result.exit_code == 0:
                # Install dependencies
                install_result = container.exec_run(
                    'npm install --production',
                    workdir='/workspace'
                )
                
                if install_result.exit_code == 0:
                    logger.info("Node.js dependencies installed successfully")
                else:
                    logger.warning(f"Dependency installation issues: {install_result.output}")
            else:
                logger.info("No package.json found, skipping dependency installation")
            
        except Exception as e:
            logger.error(f"Node.js environment setup failed: {e}")
    
    async def cleanup_container(self, container_id: str) -> None:
        """
        Clean up container resources.
        
        Args:
            container_id: Container ID to cleanup
        """
        try:
            container = self.docker_client.containers.get(container_id)
            
            if container.status == 'running':
                container.stop(timeout=10)
            
            container.remove()
            
            # Remove from tracking list
            self.containers = [c for c in self.containers if c.id != container_id]
            
            logger.info(f"Cleaned up container: {container_id[:12]}")
            
        except docker.errors.NotFound:
            logger.warning(f"Container {container_id[:12]} not found for cleanup")
        except Exception as e:
            logger.error(f"Container cleanup failed: {e}")
    
    async def cleanup_all(self) -> None:
        """Clean up all managed containers."""
        for container in self.containers.copy():
            await self.cleanup_container(container.id)