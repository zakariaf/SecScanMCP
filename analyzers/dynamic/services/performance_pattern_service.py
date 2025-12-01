"""Performance pattern analysis service."""

import logging
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

# Map descriptive types to available VulnerabilityTypes
PERFORMANCE_TYPE = VulnerabilityType.RESOURCE_ABUSE
MEMORY_TYPE = VulnerabilityType.RESOURCE_ABUSE

logger = logging.getLogger(__name__)


class PerformancePatternService:
    """Analyzes performance patterns for issues."""

    async def analyze_patterns(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Analyze all performance patterns."""
        findings = []
        findings.extend(self._analyze_cpu_usage(metrics))
        findings.extend(self._analyze_memory_leaks(metrics))
        findings.extend(self._analyze_response_degradation(metrics))
        return findings

    def _analyze_cpu_usage(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Analyze CPU usage patterns."""
        findings = []
        cpu_values = [m.get('cpu_percent', 0) for m in metrics]
        if not cpu_values:
            return findings
        avg_cpu = sum(cpu_values) / len(cpu_values)
        if avg_cpu > 80:
            findings.append(Finding(
                title="Performance Issue: High CPU Usage",
                description=f"Average CPU usage {avg_cpu:.1f}% indicates potential issues",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=PERFORMANCE_TYPE,
                location="runtime:cpu",
                confidence=0.8,
                recommendation="Investigate CPU-intensive operations",
                evidence={'average_cpu': avg_cpu, 'max_cpu': max(cpu_values), 'samples': len(cpu_values)}
            ))
        return findings

    def _analyze_memory_leaks(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect potential memory leaks."""
        findings = []
        memory_values = [m.get('memory_mb', 0) for m in metrics]
        if len(memory_values) < 5:
            return findings
        memory_trend = [memory_values[i] - memory_values[i-1] for i in range(1, len(memory_values))]
        avg_growth = sum(memory_trend) / len(memory_trend) if memory_trend else 0
        if avg_growth > 5 and all(g >= 0 for g in memory_trend[-3:]):
            findings.append(Finding(
                title="Performance Issue: Potential Memory Leak",
                description=f"Consistent memory growth: {avg_growth:.1f} MB per interval",
                severity=SeverityLevel.HIGH,
                vulnerability_type=MEMORY_TYPE,
                location="runtime:memory",
                confidence=0.7,
                recommendation="Investigate memory usage patterns",
                evidence={
                    'memory_growth_rate': avg_growth,
                    'initial_memory': memory_values[0] if memory_values else 0,
                    'final_memory': memory_values[-1] if memory_values else 0
                }
            ))
        return findings

    def _analyze_response_degradation(self, metrics: List[Dict[str, Any]]) -> List[Finding]:
        """Detect response time degradation."""
        findings = []
        response_times = [m.get('response_time_ms', 0) for m in metrics]
        if len(response_times) < 5:
            return findings
        mid = len(response_times) // 2
        early = response_times[:mid]
        late = response_times[mid:]
        avg_early = sum(early) / len(early) if early else 0
        avg_late = sum(late) / len(late) if late else 0
        if avg_late > avg_early * 2 and avg_late > 1000:
            findings.append(Finding(
                title="Performance Issue: Response Time Degradation",
                description=f"Response times degraded from {avg_early:.0f}ms to {avg_late:.0f}ms",
                severity=SeverityLevel.MEDIUM,
                vulnerability_type=PERFORMANCE_TYPE,
                location="runtime:response_time",
                confidence=0.6,
                recommendation="Investigate response time degradation causes",
                evidence={
                    'early_avg_response_time': avg_early,
                    'late_avg_response_time': avg_late,
                    'degradation_ratio': avg_late / avg_early if avg_early > 0 else 0
                }
            ))
        return findings
