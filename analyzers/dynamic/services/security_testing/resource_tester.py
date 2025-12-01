"""Resource access testing service."""

import logging
from typing import List

from models import Finding
from .response_analyzer import ResponseAnalyzer
from .finding_factory import FindingFactory

logger = logging.getLogger(__name__)


class ResourceTester:
    """Tests for resource access vulnerabilities."""

    TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/shadow',
        'file:///etc/hosts',
        '\\\\server\\share\\secrets.txt'
    ]

    async def test(self, mcp_client) -> List[Finding]:
        """Test for resource access vulnerabilities."""
        findings = []
        try:
            await mcp_client.list_resources()
            for payload in self.TRAVERSAL_PAYLOADS:
                try:
                    result = await mcp_client.get_resource(payload)
                    if ResponseAnalyzer.contains_sensitive_data(result):
                        findings.append(FindingFactory.create_path_traversal(payload, result))
                except Exception:
                    continue
        except Exception as e:
            logger.error(f"Resource access testing failed: {e}")
        return findings

    async def test_authentication(self, mcp_client) -> List[Finding]:
        """Test for authentication bypass vulnerabilities."""
        findings = []
        try:
            tools = await mcp_client.list_tools()
            if len(tools) > 0:
                findings.append(FindingFactory.create_auth_bypass(len(tools)))
        except Exception as e:
            logger.error(f"Authentication testing failed: {e}")
        return findings
