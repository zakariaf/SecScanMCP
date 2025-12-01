"""Tests for MCP client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from analyzers.dynamic.utils.mcp_client import MCPClient, MCPSecurityTester
from analyzers.dynamic.utils.transports import MCPTransport, MCPResponse


class TestMCPClient:
    """Tests for MCPClient class."""

    def test_init_default_transport(self):
        """Test client initialization with default transport."""
        client = MCPClient()
        assert client.transport_type == MCPTransport.STDIO
        assert client.tools == []
        assert client.resources == []
        assert client.prompts == []

    def test_init_custom_transport(self):
        """Test client initialization with custom transport."""
        client = MCPClient(transport=MCPTransport.WEBSOCKET)
        assert client.transport_type == MCPTransport.WEBSOCKET

    @pytest.mark.asyncio
    async def test_connect_success(self):
        """Test successful connection."""
        client = MCPClient()
        with patch.object(client, '_perform_handshake', new_callable=AsyncMock):
            with patch('analyzers.dynamic.utils.mcp_client.TransportFactory') as mock_factory:
                mock_transport = MagicMock()
                mock_transport.connect = AsyncMock(return_value=True)
                mock_factory.create.return_value = mock_transport
                result = await client.connect("python server.py")
                assert result is True

    @pytest.mark.asyncio
    async def test_connect_failure(self):
        """Test failed connection."""
        client = MCPClient()
        with patch('analyzers.dynamic.utils.mcp_client.TransportFactory') as mock_factory:
            mock_transport = MagicMock()
            mock_transport.connect = AsyncMock(return_value=False)
            mock_factory.create.return_value = mock_transport
            result = await client.connect("invalid")
            assert result is False

    @pytest.mark.asyncio
    async def test_call_tool(self):
        """Test calling a tool."""
        client = MCPClient()
        client.transport = MagicMock()
        client.transport.send = AsyncMock(return_value=MCPResponse(
            jsonrpc="2.0", id="1", result={"content": "success"}
        ))
        result = await client.call_tool("test_tool", {"arg": "value"})
        assert result.result == {"content": "success"}

    @pytest.mark.asyncio
    async def test_get_resource(self):
        """Test getting a resource."""
        client = MCPClient()
        client.transport = MagicMock()
        client.transport.send = AsyncMock(return_value=MCPResponse(
            jsonrpc="2.0", id="1", result={"contents": [{"text": "data"}]}
        ))
        result = await client.get_resource("file:///test.txt")
        assert result.result is not None

    @pytest.mark.asyncio
    async def test_get_prompt(self):
        """Test getting a prompt."""
        client = MCPClient()
        client.transport = MagicMock()
        client.transport.send = AsyncMock(return_value=MCPResponse(
            jsonrpc="2.0", id="1", result={"messages": []}
        ))
        result = await client.get_prompt("test_prompt", {"input": "test"})
        assert result.result is not None

    @pytest.mark.asyncio
    async def test_disconnect(self):
        """Test disconnecting."""
        client = MCPClient()
        client.transport = MagicMock()
        client.transport.disconnect = AsyncMock()
        await client.disconnect()
        assert client.transport is None

    def test_get_available_tools(self):
        """Test getting available tools."""
        client = MCPClient()
        client.tools = [{"name": "tool1"}]
        assert client.get_available_tools() == [{"name": "tool1"}]

    def test_get_server_capabilities(self):
        """Test getting server capabilities."""
        client = MCPClient()
        client.capabilities = {"tools": {"listChanged": True}}
        assert client.get_server_capabilities() == {"tools": {"listChanged": True}}


class TestMCPSecurityTester:
    """Tests for MCPSecurityTester class."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.get_available_tools.return_value = []
        client.get_available_prompts.return_value = []
        client.get_available_resources.return_value = []
        return client

    def test_init(self, mock_client):
        """Test security tester initialization."""
        tester = MCPSecurityTester(mock_client)
        assert tester.client == mock_client
        assert tester.tool_tester is not None
        assert tester.prompt_tester is not None
        assert tester.resource_tester is not None

    @pytest.mark.asyncio
    async def test_run_comprehensive_tests_no_items(self, mock_client):
        """Test comprehensive tests with no tools/prompts/resources."""
        tester = MCPSecurityTester(mock_client)
        result = await tester.run_comprehensive_tests()
        assert result == []

    @pytest.mark.asyncio
    async def test_run_comprehensive_tests_with_tools(self, mock_client):
        """Test comprehensive tests with tools."""
        mock_client.get_available_tools.return_value = [
            {"name": "test_tool", "inputSchema": {"properties": {}}}
        ]
        tester = MCPSecurityTester(mock_client)
        result = await tester.run_comprehensive_tests()
        assert isinstance(result, list)
