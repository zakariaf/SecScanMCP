"""Input validation testing service."""

import logging
from typing import List

from models import Finding
from .response_analyzer import ResponseAnalyzer
from .finding_factory import FindingFactory

logger = logging.getLogger(__name__)


class ValidationTester:
    """Tests input validation mechanisms."""

    MALFORMED_INPUTS = [
        {'test': 'A' * 10000},  # Buffer overflow attempt
        {'test': None},  # Null value
        {'test': {'nested': {'very': {'deep': 'value'}}}},  # Deep nesting
        {'test': '<script>alert("xss")</script>'},  # XSS attempt
    ]

    async def test(self, mcp_client) -> List[Finding]:
        """Test input validation mechanisms."""
        findings = []
        try:
            tools = await mcp_client.list_tools()
            for tool in tools[:1]:
                tool_name = tool.get('name', 'unknown')
                for malformed in self.MALFORMED_INPUTS:
                    try:
                        result = await mcp_client.call_tool(tool_name, malformed)
                        if ResponseAnalyzer.indicates_poor_validation(result, malformed):
                            findings.append(FindingFactory.create_input_validation(
                                tool_name, malformed
                            ))
                    except Exception:
                        continue
        except Exception as e:
            logger.error(f"Input validation testing failed: {e}")
        return findings
