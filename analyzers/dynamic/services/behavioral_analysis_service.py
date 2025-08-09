"""Behavioral analysis service for dynamic analysis."""

import logging
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class BehavioralAnalysisService:
    """ML-based behavioral analysis for MCP servers."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.analysis_session = {}
    
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
    
    async def run_ml_anomaly_detection(self, metrics_history: List[Dict[str, Any]]) -> List[Finding]:
        """Run ML-based anomaly detection on behavioral data"""
        findings = []
        
        try:
            if len(metrics_history) < 10:
                logger.info("🤖 Insufficient data for ML anomaly detection")
                return findings
            
            logger.info("🤖 Running ML-based anomaly detection...")
            
            # Analyze patterns in metrics
            findings.extend(await self._detect_behavioral_anomalies(metrics_history))
            findings.extend(await self._analyze_performance_patterns(metrics_history))
            
            logger.info(f"🤖 ML anomaly detection found {len(findings)} anomalies")
            
        except Exception as e:
            logger.error(f"ML anomaly detection failed: {e}")
        
        return findings
    
    async def _detect_behavioral_anomalies(self, behavior_metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect behavioral anomalies using statistical analysis"""
        findings = []
        
        try:
            # Statistical outlier detection function
            def detect_outliers(values, threshold=2.0):
                if len(values) < 3:
                    return []
                    
                mean = sum(values) / len(values)
                variance = sum((x - mean) ** 2 for x in values) / len(values)
                std_dev = variance ** 0.5
                
                outliers = []
                for i, value in enumerate(values):
                    if abs(value - mean) > threshold * std_dev:
                        outliers.append((i, value, abs(value - mean) / std_dev))
                return outliers
            
            # Analyze different metrics for anomalies
            metrics_to_analyze = [
                ('cpu_percent', 'CPU Usage'),
                ('memory_mb', 'Memory Usage'),
                ('network_connections', 'Network Connections'),
                ('process_count', 'Process Count'),
                ('file_descriptors', 'File Descriptors')
            ]
            
            for metric_name, display_name in metrics_to_analyze:
                values = [m.get(metric_name, 0) for m in behavior_metrics if metric_name in m]
                
                if not values:
                    continue
                
                outliers = detect_outliers(values)
                
                for idx, value, z_score in outliers:
                    severity = SeverityLevel.HIGH if z_score > 3.0 else SeverityLevel.MEDIUM
                    
                    finding = Finding(
                        title=f"Behavioral Anomaly: {display_name}",
                        description=f"Unusual {display_name.lower()}: {value} (z-score: {z_score:.2f})",
                        severity=severity,
                        vulnerability_type=VulnerabilityType.BEHAVIORAL_ANOMALY,
                        location="runtime:behavior",
                        confidence=min(0.9, z_score / 4.0),  # Higher z-score = higher confidence
                        recommendation=f"Investigate unusual {display_name.lower()} patterns",
                        evidence={
                            'metric': metric_name,
                            'value': value,
                            'z_score': z_score,
                            'timestamp': behavior_metrics[idx].get('timestamp'),
                            'context': f"Statistical anomaly in {display_name.lower()}"
                        }
                    )
                    findings.append(finding)
            
        except Exception as e:
            logger.error(f"Behavioral anomaly detection failed: {e}")
        
        return findings
    
    async def _analyze_performance_patterns(self, metrics_history: List[Dict[str, Any]]) -> List[Finding]:
        """Analyze performance patterns for issues"""
        findings = []
        
        try:
            logger.info("📊 Analyzing performance patterns...")
            
            # Calculate performance metrics
            cpu_values = [m.get('cpu_percent', 0) for m in metrics_history]
            memory_values = [m.get('memory_mb', 0) for m in metrics_history]
            response_times = [m.get('response_time_ms', 0) for m in metrics_history]
            
            # High CPU usage pattern
            avg_cpu = sum(cpu_values) / len(cpu_values) if cpu_values else 0
            if avg_cpu > 80:  # 80% CPU threshold
                finding = Finding(
                    title="Performance Issue: High CPU Usage",
                    description=f"Average CPU usage {avg_cpu:.1f}% indicates potential performance issues",
                    severity=SeverityLevel.MEDIUM,
                    vulnerability_type=VulnerabilityType.PERFORMANCE_ISSUE,
                    location="runtime:cpu",
                    confidence=0.8,
                    recommendation="Investigate CPU-intensive operations and optimize performance",
                    evidence={
                        'average_cpu': avg_cpu,
                        'max_cpu': max(cpu_values) if cpu_values else 0,
                        'samples': len(cpu_values)
                    }
                )
                findings.append(finding)
            
            # Memory leak detection
            if len(memory_values) >= 5:
                # Check for consistent memory growth
                memory_trend = []
                for i in range(1, len(memory_values)):
                    memory_trend.append(memory_values[i] - memory_values[i-1])
                
                avg_growth = sum(memory_trend) / len(memory_trend) if memory_trend else 0
                
                # Flag consistent memory growth
                if avg_growth > 5 and all(growth >= 0 for growth in memory_trend[-3:]):  # 5MB per interval
                    finding = Finding(
                        title="Performance Issue: Potential Memory Leak",
                        description=f"Consistent memory growth detected: {avg_growth:.1f} MB per interval",
                        severity=SeverityLevel.HIGH,
                        vulnerability_type=VulnerabilityType.MEMORY_LEAK,
                        location="runtime:memory",
                        confidence=0.7,
                        recommendation="Investigate memory usage patterns and fix potential memory leaks",
                        evidence={
                            'memory_growth_rate': avg_growth,
                            'initial_memory': memory_values[0] if memory_values else 0,
                            'final_memory': memory_values[-1] if memory_values else 0,
                            'total_growth': memory_values[-1] - memory_values[0] if len(memory_values) >= 2 else 0
                        }
                    )
                    findings.append(finding)
            
            # Response time degradation
            if len(response_times) >= 5:
                early_responses = response_times[:len(response_times)//2]
                late_responses = response_times[len(response_times)//2:]
                
                avg_early = sum(early_responses) / len(early_responses) if early_responses else 0
                avg_late = sum(late_responses) / len(late_responses) if late_responses else 0
                
                # Flag response time degradation
                if avg_late > avg_early * 2 and avg_late > 1000:  # 2x slower and > 1s
                    finding = Finding(
                        title="Performance Issue: Response Time Degradation",
                        description=f"Response times degraded from {avg_early:.0f}ms to {avg_late:.0f}ms",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.PERFORMANCE_ISSUE,
                        location="runtime:response_time",
                        confidence=0.6,
                        recommendation="Investigate causes of response time degradation",
                        evidence={
                            'early_avg_response_time': avg_early,
                            'late_avg_response_time': avg_late,
                            'degradation_ratio': avg_late / avg_early if avg_early > 0 else 0
                        }
                    )
                    findings.append(finding)
            
            logger.info(f"📊 Performance analysis found {len(findings)} issues")
            
        except Exception as e:
            logger.error(f"Performance pattern analysis failed: {e}")
        
        return findings