"""WebSocket transport for MCP communication."""

import asyncio
import json
import logging
from typing import Optional
from dataclasses import asdict

import websockets

from .base_transport import BaseTransport, MCPRequest, MCPResponse

logger = logging.getLogger(__name__)


class WebSocketTransport(BaseTransport):
    """WebSocket transport for MCP."""

    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        self.websocket = None

    async def connect(self, url: str, **kwargs) -> bool:
        """Connect via WebSocket."""
        try:
            self.websocket = await websockets.connect(url, **kwargs)
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"WebSocket connection failed: {e}")
            return False

    async def send(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Send request via WebSocket."""
        if not self.websocket:
            return None
        try:
            await self.websocket.send(json.dumps(asdict(request)))

            if request.id is not None:
                response_msg = await asyncio.wait_for(
                    self.websocket.recv(),
                    timeout=self.timeout
                )
                data = json.loads(response_msg)
                return MCPResponse(**data)
            return None
        except asyncio.TimeoutError:
            logger.error(f"WebSocket timeout for {request.method}")
            return None
        except Exception as e:
            logger.error(f"WebSocket send failed: {e}")
            return None

    async def disconnect(self) -> None:
        """Disconnect WebSocket transport."""
        if self.websocket:
            try:
                await self.websocket.close()
            except Exception as e:
                logger.error(f"WebSocket disconnect error: {e}")
            finally:
                self.websocket = None
                self.connected = False
