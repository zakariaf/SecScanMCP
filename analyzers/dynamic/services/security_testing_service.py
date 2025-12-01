"""Security testing service for dynamic MCP analysis."""

import logging
from typing import List

from models import Finding
from .security_testing import (
    ToolTester, PromptTester, ResourceTester, ValidationTester
)

logger = logging.getLogger(__name__)


class SecurityTestingService:
    """Comprehensive security testing for MCP servers."""

    def __init__(self):
        self.tool_tester = ToolTester()
        self.prompt_tester = PromptTester()
        self.resource_tester = ResourceTester()
        self.validation_tester = ValidationTester()

    async def run_comprehensive_tests(self, mcp_client) -> List[Finding]:
        """Run comprehensive security tests on MCP server."""
        findings = []

        try:
            findings.extend(await self.tool_tester.test(mcp_client))
            findings.extend(await self.prompt_tester.test(mcp_client))
            findings.extend(await self.resource_tester.test(mcp_client))
            findings.extend(await self.resource_tester.test_authentication(mcp_client))
            findings.extend(await self.validation_tester.test(mcp_client))

            logger.info(f"Security testing completed with {len(findings)} findings")
        except Exception as e:
            logger.error(f"Security testing failed: {e}")

        return findings
