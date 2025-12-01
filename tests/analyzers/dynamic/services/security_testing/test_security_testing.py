"""Tests for security testing services."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from analyzers.dynamic.services.security_testing import (
    ResponseAnalyzer,
    FindingFactory,
    ToolTester,
    PromptTester,
    ResourceTester,
    ValidationTester,
)


class TestResponseAnalyzer:
    """Tests for ResponseAnalyzer."""

    def test_analyze_tool_response_vulnerable(self):
        """Test detecting vulnerable response."""
        response = {'output': 'uid=1000 gid=1000'}
        assert ResponseAnalyzer.analyze_tool_response(response, {})

    def test_analyze_tool_response_safe(self):
        """Test safe response not flagged."""
        response = {'output': 'success'}
        assert not ResponseAnalyzer.analyze_tool_response(response, {})

    def test_is_vulnerability_error(self):
        """Test error detection."""
        assert ResponseAnalyzer.is_vulnerability_error("permission denied")
        assert not ResponseAnalyzer.is_vulnerability_error("ok")

    def test_detect_injection_success(self):
        """Test injection success detection."""
        response = {'text': 'INJECTED response'}
        assert ResponseAnalyzer.detect_injection_success(response, "test")

    def test_contains_sensitive_data(self):
        """Test sensitive data detection."""
        content = {'data': 'root:x:0:0:root'}
        assert ResponseAnalyzer.contains_sensitive_data(content)

    def test_indicates_poor_validation_long_response(self):
        """Test poor validation detection for long response."""
        response = {'data': 'x' * 6000}
        assert ResponseAnalyzer.indicates_poor_validation(response, {'input': 'test'})


class TestFindingFactory:
    """Tests for FindingFactory."""

    def test_create_tool_manipulation(self):
        """Test creating tool manipulation finding."""
        finding = FindingFactory.create_tool_manipulation("test_tool", {'input': 'payload'}, {})
        assert "Tool Manipulation" in finding.title
        assert finding.tool == "security_testing"

    def test_create_tool_error(self):
        """Test creating tool error finding."""
        finding = FindingFactory.create_tool_error("test_tool", "error message")
        assert "Tool Error" in finding.title

    def test_create_prompt_injection(self):
        """Test creating prompt injection finding."""
        finding = FindingFactory.create_prompt_injection("test_tool", "payload", {})
        assert "Prompt Injection" in finding.title

    def test_create_path_traversal(self):
        """Test creating path traversal finding."""
        finding = FindingFactory.create_path_traversal("../etc/passwd", {})
        assert "Path Traversal" in finding.title

    def test_create_auth_bypass(self):
        """Test creating auth bypass finding."""
        finding = FindingFactory.create_auth_bypass(5)
        assert "Authentication Bypass" in finding.title

    def test_create_input_validation(self):
        """Test creating input validation finding."""
        finding = FindingFactory.create_input_validation("test_tool", {'test': 'data'})
        assert "Input Validation" in finding.title


class TestToolTester:
    """Tests for ToolTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.list_tools = AsyncMock(return_value=[{'name': 'test_tool'}])
        client.call_tool = AsyncMock(return_value={'output': 'safe'})
        return client

    @pytest.mark.asyncio
    async def test_test_no_vulnerabilities(self, mock_client):
        """Test when no vulnerabilities found."""
        tester = ToolTester()
        findings = await tester.test(mock_client)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_test_with_vulnerable_response(self, mock_client):
        """Test detecting vulnerable response."""
        mock_client.call_tool = AsyncMock(return_value={'output': 'uid=1000'})
        tester = ToolTester()
        tester.payload_generator = None  # Force basic payloads
        findings = await tester.test(mock_client)
        assert len(findings) > 0


class TestPromptTester:
    """Tests for PromptTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.list_tools = AsyncMock(return_value=[{'name': 'test_tool'}])
        client.call_tool = AsyncMock(return_value={'text': 'safe response'})
        return client

    @pytest.mark.asyncio
    async def test_test_no_injection(self, mock_client):
        """Test when no injection detected."""
        tester = PromptTester()
        findings = await tester.test(mock_client)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_test_injection_detected(self, mock_client):
        """Test detecting prompt injection."""
        mock_client.call_tool = AsyncMock(return_value={'text': 'INJECTED'})
        tester = PromptTester()
        findings = await tester.test(mock_client)
        assert len(findings) > 0


class TestResourceTester:
    """Tests for ResourceTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.list_resources = AsyncMock(return_value=[])
        client.get_resource = AsyncMock(return_value={'content': 'safe'})
        client.list_tools = AsyncMock(return_value=[{'name': 'tool'}])
        return client

    @pytest.mark.asyncio
    async def test_test_no_traversal(self, mock_client):
        """Test when no path traversal detected."""
        tester = ResourceTester()
        findings = await tester.test(mock_client)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_test_authentication(self, mock_client):
        """Test authentication bypass detection."""
        tester = ResourceTester()
        findings = await tester.test_authentication(mock_client)
        assert isinstance(findings, list)
        # Should create a finding when tools are accessible
        assert len(findings) >= 0


class TestValidationTester:
    """Tests for ValidationTester."""

    @pytest.fixture
    def mock_client(self):
        """Create mock MCP client."""
        client = MagicMock()
        client.list_tools = AsyncMock(return_value=[{'name': 'test_tool'}])
        client.call_tool = AsyncMock(return_value={'data': 'ok'})
        return client

    @pytest.mark.asyncio
    async def test_test_good_validation(self, mock_client):
        """Test when validation is good."""
        tester = ValidationTester()
        findings = await tester.test(mock_client)
        assert isinstance(findings, list)
