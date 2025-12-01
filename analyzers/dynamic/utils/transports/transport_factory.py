"""Factory for creating MCP transports."""

from .base_transport import BaseTransport, MCPTransport
from .stdio_transport import StdioTransport
from .sse_transport import SSETransport
from .websocket_transport import WebSocketTransport


class TransportFactory:
    """Factory for creating transport instances."""

    @staticmethod
    def create(transport_type: MCPTransport, timeout: float = 30.0) -> BaseTransport:
        """Create transport instance based on type."""
        transports = {
            MCPTransport.STDIO: StdioTransport,
            MCPTransport.SSE: SSETransport,
            MCPTransport.WEBSOCKET: WebSocketTransport,
        }
        transport_class = transports.get(transport_type, StdioTransport)
        return transport_class(timeout)
