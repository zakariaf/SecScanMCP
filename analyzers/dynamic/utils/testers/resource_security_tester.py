"""Resource security testing service."""

import logging
from typing import Dict, Any, List

from .vulnerability_checker import VulnerabilityChecker

logger = logging.getLogger(__name__)


class ResourceSecurityTester:
    """Tests MCP resources for access vulnerabilities."""

    TRAVERSAL_SUFFIXES = [
        "/../../../etc/passwd",
        "/../../windows/system32/config/sam",
        "/../.env",
        "/../config/secrets.json",
    ]

    def __init__(self, client):
        self.client = client

    async def test_resource(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Test resource access security."""
        vulnerabilities = []
        resource_uri = resource.get("uri", "unknown")
        logger.info(f"Testing resource security: {resource_uri}")

        for suffix in self.TRAVERSAL_SUFFIXES:
            payload_uri = f"{resource_uri}{suffix}"
            try:
                response = await self.client.get_resource(payload_uri)
                if VulnerabilityChecker.check_response(
                    response, "unauthorized_resource_access"
                ):
                    vulnerabilities.append(self._create_finding(
                        resource_uri, payload_uri, response
                    ))
            except Exception as e:
                logger.debug(f"Resource test error for {resource_uri}: {e}")

        return vulnerabilities

    def _create_finding(
        self, resource_uri: str, payload_uri: str, response
    ) -> Dict[str, Any]:
        """Create vulnerability finding."""
        resp_text = str(response.result or response.error) if response else ""
        return {
            "resource_uri": resource_uri,
            "payload_uri": payload_uri,
            "vulnerability_type": "unauthorized_resource_access",
            "response": resp_text,
            "severity": "high",
        }
