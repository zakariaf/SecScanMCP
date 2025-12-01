"""Tests for MCP transport services."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import json

from analyzers.dynamic.utils.transports import (
    MCPTransport, MCPRequest, MCPResponse,
    StdioTransport, SSETransport, WebSocketTransport,
    TransportFactory
)


class TestMCPRequest:
    """Tests for MCPRequest dataclass."""

    def test_request_default_values(self):
        """Test request has default values."""
        req = MCPRequest(method="test")
        assert req.jsonrpc == "2.0"
        assert req.id is not None
        assert req.method == "test"
        assert req.params is None

    def test_request_with_params(self):
        """Test request with parameters."""
        req = MCPRequest(method="tools/call", params={"name": "test_tool"})
        assert req.params == {"name": "test_tool"}

    def test_request_to_dict(self):
        """Test request serialization."""
        req = MCPRequest(method="test", id="test-id")
        result = req.to_dict()
        assert result["method"] == "test"
        assert result["jsonrpc"] == "2.0"


class TestStdioTransport:
    """Tests for STDIO transport."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful STDIO connection."""
        transport = StdioTransport()
        with patch('asyncio.create_subprocess_shell') as mock_create:
            mock_process = MagicMock()
            mock_create.return_value = mock_process
            result = await transport.connect("python server.py")
            assert result is True
            assert transport.connected is True

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test failed STDIO connection."""
        transport = StdioTransport()
        with patch('asyncio.create_subprocess_shell', side_effect=Exception("Failed")):
            result = await transport.connect("invalid command")
            assert result is False

    @pytest.mark.asyncio
    async def test_send_without_connection(self):
        """Test send without connection returns None."""
        transport = StdioTransport()
        req = MCPRequest(method="test")
        result = await transport.send(req)
        assert result is None

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test STDIO disconnect."""
        transport = StdioTransport()
        transport.process = MagicMock()
        transport.process.terminate = MagicMock()
        transport.process.wait = AsyncMock()
        await transport.disconnect()
        assert transport.process is None
        assert transport.connected is False


class TestSSETransport:
    """Tests for SSE transport."""

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful SSE connection."""
        transport = SSETransport()
        with patch('aiohttp.ClientSession') as mock_session:
            result = await transport.connect("http://localhost:8080")
            assert result is True
            assert transport.base_url == "http://localhost:8080"

    @pytest.mark.asyncio
    async def test_send_without_session(self):
        """Test send without session returns None."""
        transport = SSETransport()
        req = MCPRequest(method="test")
        result = await transport.send(req)
        assert result is None

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test SSE disconnect."""
        transport = SSETransport()
        transport.session = MagicMock()
        transport.session.close = AsyncMock()
        await transport.disconnect()
        assert transport.session is None


class TestWebSocketTransport:
    """Tests for WebSocket transport."""

    @pytest.mark.asyncio
    async def test_send_without_websocket(self):
        """Test send without websocket returns None."""
        transport = WebSocketTransport()
        req = MCPRequest(method="test")
        result = await transport.send(req)
        assert result is None

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test WebSocket disconnect."""
        transport = WebSocketTransport()
        transport.websocket = MagicMock()
        transport.websocket.close = AsyncMock()
        await transport.disconnect()
        assert transport.websocket is None


class TestTransportFactory:
    """Tests for TransportFactory."""

    def test_create_stdio_transport(self):
        """Test creating STDIO transport."""
        transport = TransportFactory.create(MCPTransport.STDIO)
        assert isinstance(transport, StdioTransport)

    def test_create_sse_transport(self):
        """Test creating SSE transport."""
        transport = TransportFactory.create(MCPTransport.SSE)
        assert isinstance(transport, SSETransport)

    def test_create_websocket_transport(self):
        """Test creating WebSocket transport."""
        transport = TransportFactory.create(MCPTransport.WEBSOCKET)
        assert isinstance(transport, WebSocketTransport)

    def test_create_with_timeout(self):
        """Test creating transport with custom timeout."""
        transport = TransportFactory.create(MCPTransport.STDIO, timeout=60.0)
        assert transport.timeout == 60.0
