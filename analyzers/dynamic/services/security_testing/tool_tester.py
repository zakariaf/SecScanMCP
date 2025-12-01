"""Tool manipulation testing service."""

import logging
from typing import List

from models import Finding
from .response_analyzer import ResponseAnalyzer
from .finding_factory import FindingFactory

logger = logging.getLogger(__name__)


class ToolTester:
    """Tests tools for manipulation vulnerabilities."""

    BASIC_PAYLOADS = [
        {'input': '; rm -rf / #'},
        {'input': '$(whoami)'},
        {'input': '`cat /etc/passwd`'},
        {'input': '../../../etc/shadow'}
    ]

    def __init__(self):
        self.payload_generator = self._try_load_payload_generator()

    def _try_load_payload_generator(self):
        """Try to load advanced payload generator."""
        try:
            from analyzers.payloads.generators.payload_generator import PayloadGenerator
            gen = PayloadGenerator()
            # Verify it has the required method
            if hasattr(gen, 'get_payloads'):
                return gen
            return None
        except (ImportError, AttributeError):
            return None

    async def test(self, mcp_client) -> List[Finding]:
        """Test tools for manipulation vulnerabilities."""
        findings = []
        try:
            tools = await mcp_client.list_tools()
            for tool in tools[:3]:
                tool_name = tool.get('name', 'unknown')
                if self.payload_generator:
                    findings.extend(await self._test_advanced(mcp_client, tool_name))
                else:
                    findings.extend(await self._test_basic(mcp_client, tool_name))
        except Exception as e:
            logger.error(f"Tool manipulation testing failed: {e}")
        return findings

    async def _test_basic(self, mcp_client, tool_name: str) -> List[Finding]:
        """Test tool with basic payloads."""
        findings = []
        for payload in self.BASIC_PAYLOADS:
            try:
                result = await mcp_client.call_tool(tool_name, payload)
                if ResponseAnalyzer.analyze_tool_response(result, payload):
                    findings.append(FindingFactory.create_tool_manipulation(
                        tool_name, payload, result
                    ))
            except Exception as e:
                if ResponseAnalyzer.is_vulnerability_error(str(e)):
                    findings.append(FindingFactory.create_tool_error(tool_name, str(e)))
        return findings

    async def _test_advanced(self, mcp_client, tool_name: str) -> List[Finding]:
        """Test tool with advanced payloads."""
        findings = []
        try:
            from analyzers.payloads.generators.payload_generator import PayloadCategory
            payloads = self.payload_generator.get_payloads(PayloadCategory.TOOL_MANIPULATION)
            for payload_data in payloads:
                try:
                    payload = {'input': payload_data['payload']}
                    result = await mcp_client.call_tool(tool_name, payload)
                    if ResponseAnalyzer.analyze_tool_response(result, payload):
                        findings.append(FindingFactory.create_tool_manipulation(
                            tool_name, payload_data, result
                        ))
                except Exception as e:
                    if ResponseAnalyzer.is_vulnerability_error(str(e)):
                        findings.append(FindingFactory.create_tool_error(tool_name, str(e)))
        except ImportError:
            findings.extend(await self._test_basic(mcp_client, tool_name))
        return findings
