"""STDIO transport for MCP communication."""

import asyncio
import json
import logging
from typing import Optional
from dataclasses import asdict

from .base_transport import BaseTransport, MCPRequest, MCPResponse

logger = logging.getLogger(__name__)


class StdioTransport(BaseTransport):
    """STDIO subprocess transport for MCP."""

    def __init__(self, timeout: float = 30.0):
        super().__init__(timeout)
        self.process = None

    async def connect(self, command: str, **kwargs) -> bool:
        """Connect via STDIO subprocess."""
        try:
            self.process = await asyncio.create_subprocess_shell(
                command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **kwargs
            )
            self.connected = True
            return True
        except Exception as e:
            logger.error(f"STDIO connection failed: {e}")
            return False

    async def send(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Send request via STDIO."""
        if not self.process:
            return None
        try:
            request_json = json.dumps(asdict(request)) + "\n"
            self.process.stdin.write(request_json.encode())
            await self.process.stdin.drain()

            if request.id is not None:
                response_line = await asyncio.wait_for(
                    self.process.stdout.readline(),
                    timeout=self.timeout
                )
                if response_line:
                    data = json.loads(response_line.decode().strip())
                    return MCPResponse(**data)
            return None
        except asyncio.TimeoutError:
            logger.error(f"STDIO timeout for {request.method}")
            return None
        except Exception as e:
            logger.error(f"STDIO send failed: {e}")
            return None

    async def disconnect(self) -> None:
        """Disconnect STDIO transport."""
        if self.process:
            try:
                self.process.terminate()
                await self.process.wait()
            except Exception as e:
                logger.error(f"STDIO disconnect error: {e}")
            finally:
                self.process = None
                self.connected = False
