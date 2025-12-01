"""
MCP Protocol Client for Dynamic Analysis
Implements proper JSON-RPC 2.0 communication with MCP servers
"""

import logging
from typing import Dict, Any, List, Optional

from .transports import (
    MCPTransport, MCPRequest, MCPResponse, BaseTransport, TransportFactory
)
from .testers import (
    ToolSecurityTester, PromptSecurityTester, ResourceSecurityTester
)

logger = logging.getLogger(__name__)


class MCPClient:
    """Advanced MCP Protocol Client with multiple transports."""

    def __init__(self, transport: MCPTransport = MCPTransport.STDIO):
        self.transport_type = transport
        self.transport: Optional[BaseTransport] = None
        self.capabilities = {}
        self.tools = []
        self.resources = []
        self.prompts = []

    async def connect(self, endpoint: str, **kwargs) -> bool:
        """Connect to MCP server with specified transport."""
        try:
            self.transport = TransportFactory.create(self.transport_type)
            if await self.transport.connect(endpoint, **kwargs):
                await self._perform_handshake()
                return True
            return False
        except Exception as e:
            logger.error(f"MCP connection failed: {e}")
            return False

    async def _perform_handshake(self) -> None:
        """Perform MCP protocol handshake."""
        init_request = self._create_init_request()
        response = await self._send_request(init_request)
        if response and response.result:
            self.capabilities = response.result.get("capabilities", {})

        await self._send_notification("notifications/initialized")
        await self._discover_all()

    def _create_init_request(self) -> MCPRequest:
        """Create initialization request."""
        return MCPRequest(
            method="initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                "clientInfo": {"name": "MCP Security Scanner", "version": "1.0.0"}
            }
        )

    async def _send_notification(self, method: str) -> None:
        """Send a notification (no response expected)."""
        notification = MCPRequest(method=method, id=None)
        await self._send_request(notification)

    async def _discover_all(self) -> None:
        """Discover tools, resources, and prompts."""
        self.tools = await self._discover("tools/list", "tools")
        self.resources = await self._discover("resources/list", "resources")
        self.prompts = await self._discover("prompts/list", "prompts")

    async def _discover(self, method: str, key: str) -> List[Dict]:
        """Discover items from server."""
        response = await self._send_request(MCPRequest(method=method))
        return response.result.get(key, []) if response and response.result else []

    async def call_tool(self, name: str, arguments: Dict) -> Optional[MCPResponse]:
        """Call a specific tool with arguments."""
        return await self._send_request(MCPRequest(
            method="tools/call", params={"name": name, "arguments": arguments}
        ))

    async def get_resource(self, uri: str) -> Optional[MCPResponse]:
        """Get a specific resource."""
        return await self._send_request(MCPRequest(
            method="resources/read", params={"uri": uri}
        ))

    async def get_prompt(self, name: str, args: Dict = None) -> Optional[MCPResponse]:
        """Get a specific prompt."""
        params = {"name": name}
        if args:
            params["arguments"] = args
        return await self._send_request(MCPRequest(method="prompts/get", params=params))

    async def _send_request(self, request: MCPRequest) -> Optional[MCPResponse]:
        """Send request using configured transport."""
        if not self.transport:
            return None
        return await self.transport.send(request)

    async def disconnect(self) -> None:
        """Disconnect from MCP server."""
        if self.transport:
            await self.transport.disconnect()
            self.transport = None

    def get_available_tools(self) -> List[Dict]: return self.tools
    def get_available_resources(self) -> List[Dict]: return self.resources
    def get_available_prompts(self) -> List[Dict]: return self.prompts
    def get_server_capabilities(self) -> Dict: return self.capabilities


class MCPSecurityTester:
    """Advanced security testing suite for MCP servers."""

    def __init__(self, client: MCPClient):
        self.client = client
        self.tool_tester = ToolSecurityTester(client)
        self.prompt_tester = PromptSecurityTester(client)
        self.resource_tester = ResourceSecurityTester(client)

    async def run_comprehensive_tests(self) -> List[Dict[str, Any]]:
        """Run all security tests."""
        vulnerabilities = []

        for tool in self.client.get_available_tools():
            vulnerabilities.extend(await self.tool_tester.test_tool(tool))

        for prompt in self.client.get_available_prompts():
            vulnerabilities.extend(await self.prompt_tester.test_prompt(prompt))

        for resource in self.client.get_available_resources():
            vulnerabilities.extend(await self.resource_tester.test_resource(resource))

        return vulnerabilities

    async def test_tool_security(self, tool: Dict) -> List[Dict]:
        """Test a specific tool for vulnerabilities."""
        return await self.tool_tester.test_tool(tool)

    async def test_prompt_security(self, prompt: Dict) -> List[Dict]:
        """Test prompt for injection vulnerabilities."""
        return await self.prompt_tester.test_prompt(prompt)

    async def test_resource_security(self, resource: Dict) -> List[Dict]:
        """Test resource access security."""
        return await self.resource_tester.test_resource(resource)
