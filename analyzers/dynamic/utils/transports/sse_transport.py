"""SSE transport for MCP communication."""

import logging
from typing import Optional
from dataclasses import asdict

import aiohttp

from .base_transport import BaseTransport, MCPRequest, MCPResponse

logger = logging.getLogger(__name__)


class SSETransport(BaseTransport):
    """Server-Sent Events transport for MCP."""

    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        self.session = None
        self.base_url = None

    async def connect(self, url: str, **kwargs) -> bool:
        """Connect via SSE."""
        try:
            self.session = aiohttp.ClientSession()
            self.base_url = url.rstrip('/')
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"SSE connection failed: {e}")
            return False

    async def send(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Send request via SSE."""
        if not self.session or not self.base_url:
            return None
        try:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            async with self.session.post(
                f"{self.base_url}/mcp",
                json=asdict(request),
                timeout=timeout
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return MCPResponse(**data)
            return None
        except Exception as e:
            logger.error(f"SSE send failed: {e}")
            return None

    async def disconnect(self) -> None:
        """Disconnect SSE transport."""
        if self.session:
            try:
                await self.session.close()
            except Exception as e:
                logger.error(f"SSE disconnect error: {e}")
            finally:
                self.session = None
                self.base_url = None
                self.connected = False
