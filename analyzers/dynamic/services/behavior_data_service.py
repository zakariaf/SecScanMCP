"""Behavior data collection service for MCP interactions."""

import logging
import time
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class BehaviorDataService:
    """Collects behavioral data from MCP interactions."""

    async def collect_behavior_data(self, mcp_client) -> Dict[str, Any]:
        """Collect behavioral data from MCP interactions."""
        behavior_data = {'response_times': [], 'tool_calls': [], 'resource_accesses': []}
        try:
            tools = await mcp_client.list_tools()
            for tool in tools[:3]:
                call_data = await self._test_tool_call(mcp_client, tool)
                behavior_data['tool_calls'].append(call_data)
                if call_data.get('success'):
                    behavior_data['response_times'].append(call_data['response_time'])
        except Exception as e:
            logger.error(f"Behavior data collection failed: {e}")
        return behavior_data

    async def _test_tool_call(self, mcp_client, tool) -> Dict[str, Any]:
        """Test a single tool call and measure response."""
        tool_name = tool.get('name', '')
        start_time = time.time()
        try:
            await mcp_client.call_tool(tool_name, {'test': 'behavioral_analysis'})
            return {
                'tool': tool_name,
                'response_time': time.time() - start_time,
                'success': True
            }
        except Exception as e:
            return {'tool': tool_name, 'error': str(e), 'success': False}

    def analyze_response_times(self, behavior_data: Dict[str, Any]) -> List[Finding]:
        """Detect anomalies in response times."""
        findings = []
        response_times = behavior_data.get('response_times', [])
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            if avg_time > 5.0:
                findings.append(Finding(
                    title="Behavioral Anomaly: Slow Response Times",
                    description=f"Average response time {avg_time:.2f}s exceeds threshold",
                    severity=SeverityLevel.LOW,
                    vulnerability_type=VulnerabilityType.RESOURCE_ABUSE,
                    location="behavioral_analysis",
                    confidence=0.5,
                    evidence={'average_response_time': avg_time}
                ))
        return findings

    def analyze_error_rates(self, behavior_data: Dict[str, Any]) -> List[Finding]:
        """Analyze tool call error rates."""
        findings = []
        tool_calls = behavior_data.get('tool_calls', [])
        if not tool_calls:
            return findings
        error_count = sum(1 for c in tool_calls if not c.get('success', True))
        error_rate = error_count / len(tool_calls)
        if error_rate > 0.5:
            findings.append(Finding(
                title="High Error Rate in Tool Calls",
                description=f"Error rate {error_count}/{len(tool_calls)} indicates instability",
                severity=SeverityLevel.LOW,
                vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                location="behavioral_analysis",
                confidence=0.4,
                evidence={'error_rate': error_rate}
            ))
        return findings
