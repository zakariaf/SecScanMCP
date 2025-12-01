"""Tests for MCP security tester services."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from analyzers.dynamic.utils.transports import MCPResponse
from analyzers.dynamic.utils.testers import (
    VulnerabilityChecker, ToolSecurityTester,
    PromptSecurityTester, ResourceSecurityTester
)


class TestVulnerabilityChecker:
    """Tests for VulnerabilityChecker."""

    def test_check_command_injection_detected(self):
        """Test command injection detection."""
        response = MCPResponse(jsonrpc="2.0", id="1", result={"output": "uid=1000"})
        assert VulnerabilityChecker.check_response(response, "command_injection")

    def test_check_command_injection_not_detected(self):
        """Test normal response not flagged."""
        response = MCPResponse(jsonrpc="2.0", id="1", result={"output": "success"})
        assert not VulnerabilityChecker.check_response(response, "command_injection")

    def test_check_path_traversal_detected(self):
        """Test path traversal detection."""
        response = MCPResponse(jsonrpc="2.0", id="1", result={"content": "root:x:0:0"})
        assert VulnerabilityChecker.check_response(response, "path_traversal")

    def test_check_code_injection_detected(self):
        """Test code injection detection."""
        response = MCPResponse(jsonrpc="2.0", id="1", error={"message": "Traceback"})
        assert VulnerabilityChecker.check_response(response, "code_injection")

    def test_check_prompt_injection_detected(self):
        """Test prompt injection detection."""
        response = MCPResponse(jsonrpc="2.0", id="1", result={"text": "PWNED"})
        assert VulnerabilityChecker.check_response(response, "prompt_injection")

    def test_check_unauthorized_access_detected(self):
        """Test unauthorized access detection."""
        response = MCPResponse(jsonrpc="2.0", id="1", result={"data": "api_key=secret"})
        assert VulnerabilityChecker.check_response(response, "unauthorized_resource_access")

    def test_check_none_response(self):
        """Test None response handling."""
        assert not VulnerabilityChecker.check_response(None, "command_injection")


class TestToolSecurityTester:
    """Tests for ToolSecurityTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.call_tool = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_test_tool_no_vulnerabilities(self, mock_client):
        """Test tool with no vulnerabilities."""
        mock_client.call_tool.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"output": "safe result"}
        )
        tool = {"name": "safe_tool", "inputSchema": {"properties": {"input": {"type": "string"}}}}
        tester = ToolSecurityTester(mock_client)
        result = await tester.test_tool(tool)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_test_tool_command_injection(self, mock_client):
        """Test tool vulnerable to command injection."""
        mock_client.call_tool.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"output": "uid=1000 gid=1000"}
        )
        tool = {"name": "vuln_tool", "inputSchema": {"properties": {"cmd": {"type": "string"}}}}
        tester = ToolSecurityTester(mock_client)
        result = await tester.test_tool(tool)
        assert len(result) > 0
        assert result[0]["vulnerability_type"] == "command_injection"

    @pytest.mark.asyncio
    async def test_test_tool_without_properties(self, mock_client):
        """Test tool without input properties."""
        tool = {"name": "no_input_tool", "inputSchema": {}}
        tester = ToolSecurityTester(mock_client)
        result = await tester.test_tool(tool)
        assert len(result) == 0


class TestPromptSecurityTester:
    """Tests for PromptSecurityTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.get_prompt = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_test_prompt_no_vulnerabilities(self, mock_client):
        """Test prompt with no vulnerabilities."""
        mock_client.get_prompt.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"messages": [{"content": "Safe response"}]}
        )
        prompt = {"name": "safe_prompt"}
        tester = PromptSecurityTester(mock_client)
        result = await tester.test_prompt(prompt)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_test_prompt_injection_detected(self, mock_client):
        """Test prompt vulnerable to injection."""
        mock_client.get_prompt.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"messages": [{"content": "PWNED! Admin mode activated"}]}
        )
        prompt = {"name": "vuln_prompt"}
        tester = PromptSecurityTester(mock_client)
        result = await tester.test_prompt(prompt)
        assert len(result) > 0
        assert result[0]["vulnerability_type"] == "prompt_injection"


class TestResourceSecurityTester:
    """Tests for ResourceSecurityTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.get_resource = AsyncMock()
        return client

    @pytest.mark.asyncio
    async def test_test_resource_no_vulnerabilities(self, mock_client):
        """Test resource with no vulnerabilities."""
        mock_client.get_resource.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"contents": [{"text": "normal content"}]}
        )
        resource = {"uri": "file:///data/safe.txt"}
        tester = ResourceSecurityTester(mock_client)
        result = await tester.test_resource(resource)
        assert len(result) == 0

    @pytest.mark.asyncio
    async def test_test_resource_unauthorized_access(self, mock_client):
        """Test resource with unauthorized access."""
        mock_client.get_resource.return_value = MCPResponse(
            jsonrpc="2.0", id="1", result={"contents": [{"text": "root:x:0:0:root"}]}
        )
        resource = {"uri": "file:///data/file.txt"}
        tester = ResourceSecurityTester(mock_client)
        result = await tester.test_resource(resource)
        assert len(result) > 0
        assert result[0]["vulnerability_type"] == "unauthorized_resource_access"
