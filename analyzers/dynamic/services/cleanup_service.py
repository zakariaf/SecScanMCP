"""Cleanup service for dynamic analysis."""

import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class CleanupService:
    """Handles cleanup of analysis resources."""

    def __init__(self, docker_manager, connection_manager):
        self.docker_manager = docker_manager
        self.connection_manager = connection_manager

    async def cleanup(self, session: Dict[str, Any]):
        """Clean up analysis resources."""
        try:
            if session.get('mcp_client'):
                await self.connection_manager.cleanup_connection(
                    session['mcp_client']
                )
            if session.get('container_id'):
                await self.docker_manager.cleanup_container(
                    session['container_id']
                )
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

    async def emergency_cleanup(self, session: Dict[str, Any]):
        """Handle emergency cleanup on failure."""
        if session.get('container_id'):
            try:
                await self.docker_manager.cleanup_container(
                    session['container_id']
                )
            except Exception as e:
                logger.error(f"Emergency cleanup failed: {e}")
