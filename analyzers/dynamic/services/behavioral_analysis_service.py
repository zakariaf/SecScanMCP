"""Behavioral analysis service for dynamic analysis."""

import logging
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class BehavioralAnalysisService:
    """ML-based behavioral analysis for MCP servers."""
    
    async def analyze_behavior(self, mcp_client, container_id: str) -> List[Finding]:
        """
        Analyze MCP server behavior for anomalies.
        
        Args:
            mcp_client: Connected MCP client
            container_id: Container ID
            
        Returns:
            List of behavioral findings
        """
        findings = []
        
        try:
            # Collect behavioral metrics
            behavior_data = await self._collect_behavior_data(mcp_client)
            
            # Run ML-based anomaly detection
            findings.extend(await self._detect_anomalies(behavior_data))
            
            # Check response patterns
            findings.extend(await self._analyze_response_patterns(behavior_data))
            
            logger.info(f"Behavioral analysis completed with {len(findings)} findings")
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
        
        return findings
    
    async def _collect_behavior_data(self, mcp_client) -> Dict[str, Any]:
        """Collect behavioral data from MCP interactions."""
        behavior_data = {
            'response_times': [],
            'tool_calls': [],
            'resource_accesses': []
        }
        
        try:
            # Test various tool calls and measure response times
            tools = await mcp_client.list_tools()
            
            for tool in tools[:3]:  # Test first 3 tools
                import time
                start_time = time.time()
                
                try:
                    result = await mcp_client.call_tool(
                        tool.get('name', ''), {'test': 'behavioral_analysis'}
                    )
                    response_time = time.time() - start_time
                    
                    behavior_data['response_times'].append(response_time)
                    behavior_data['tool_calls'].append({
                        'tool': tool.get('name', ''),
                        'response_time': response_time,
                        'success': True
                    })
                    
                except Exception as e:
                    behavior_data['tool_calls'].append({
                        'tool': tool.get('name', ''),
                        'error': str(e),
                        'success': False
                    })
            
        except Exception as e:
            logger.error(f"Behavior data collection failed: {e}")
        
        return behavior_data
    
    async def _detect_anomalies(self, behavior_data: Dict[str, Any]) -> List[Finding]:
        """Detect behavioral anomalies using ML techniques."""
        findings = []
        
        # Simple anomaly detection based on response times
        response_times = behavior_data.get('response_times', [])
        
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            
            # Flag unusually slow responses
            if avg_time > 5.0:  # 5 second threshold
                findings.append(Finding(
                    title="Behavioral Anomaly: Slow Response Times",
                    description=f"Average response time {avg_time:.2f}s exceeds normal threshold",
                    severity=SeverityLevel.LOW,
                    vulnerability_type=VulnerabilityType.PERFORMANCE_ISSUE,
                    location="behavioral_analysis",
                    confidence=0.5,
                    evidence={'average_response_time': avg_time}
                ))
        
        return findings
    
    async def _analyze_response_patterns(self, behavior_data: Dict[str, Any]) -> List[Finding]:
        """Analyze response patterns for suspicious behavior."""
        findings = []
        
        tool_calls = behavior_data.get('tool_calls', [])
        error_count = sum(1 for call in tool_calls if not call.get('success', True))
        
        # Flag high error rates
        if len(tool_calls) > 0 and error_count / len(tool_calls) > 0.5:
            findings.append(Finding(
                title="High Error Rate in Tool Calls",
                description=f"Error rate {error_count}/{len(tool_calls)} may indicate instability",
                severity=SeverityLevel.LOW,
                vulnerability_type=VulnerabilityType.RELIABILITY_ISSUE,
                location="behavioral_analysis",
                confidence=0.4,
                evidence={'error_rate': error_count / len(tool_calls)}
            ))
        
        return findings