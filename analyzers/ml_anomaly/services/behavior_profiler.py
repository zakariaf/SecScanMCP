"""
Behavior Profiler Service

Creates and manages behavioral profiles of MCP servers
Following clean architecture with single responsibility
"""

import time
import logging
import statistics
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class BehaviorProfiler:
    """Creates behavioral profiles of MCP servers for comparison"""
    
    def __init__(self):
        self.profiles = {}
        self.current_session = []
        
    def create_profile(self, session_data: List[Dict[str, Any]], profile_name: str = "default"):
        """Create a behavioral profile from session data"""
        if not session_data:
            return
        
        profile = self._build_profile(session_data, profile_name)
        self.profiles[profile_name] = profile
        logger.info(f"Created profile '{profile_name}' with {len(session_data)} points")
    
    def compare_to_profile(self, current_data: List[Dict[str, Any]], profile_name: str = "default") -> Dict[str, Any]:
        """Compare current behavior to a stored profile"""
        if profile_name not in self.profiles or not current_data:
            return {}
        
        profile = self.profiles[profile_name]
        current_stats = self._calculate_stats(current_data)
        deviations = self._calculate_deviations(current_stats, profile)
        
        return {
            'profile_name': profile_name,
            'current_stats': current_stats,
            'profile_stats': {k: profile.get(k, 0) for k in current_stats.keys()},
            'deviations': deviations,
            'similarity_score': self._calculate_similarity_score(deviations)
        }
    
    def _build_profile(self, session_data: List[Dict[str, Any]], profile_name: str) -> Dict[str, Any]:
        """Build profile from session data"""
        stats = self._calculate_stats(session_data)
        patterns = self._extract_behavior_patterns(session_data)
        
        return {
            'name': profile_name,
            'session_count': len(session_data),
            **stats,
            'patterns': patterns,
            'created_at': time.time()
        }
    
    def _calculate_stats(self, session_data: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate aggregate statistics from session data"""
        return {
            'avg_cpu': statistics.mean(d.get('cpu_percent', 0) for d in session_data),
            'avg_memory': statistics.mean(d.get('memory_mb', 0) for d in session_data),
            'avg_network': statistics.mean(d.get('network_connections', 0) for d in session_data),
            'total_tool_calls': sum(d.get('tool_calls', 0) for d in session_data),
            'total_errors': sum(d.get('error_count', 0) for d in session_data),
        }
    
    def _extract_behavior_patterns(self, session_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract behavioral patterns from session data"""
        patterns = {}
        
        # Tool usage patterns
        tool_calls = [d.get('tool_calls', 0) for d in session_data]
        patterns['tool_usage'] = self._analyze_tool_patterns(tool_calls)
        
        # Resource usage patterns  
        cpu_usage = [d.get('cpu_percent', 0) for d in session_data]
        patterns['resource_usage'] = self._analyze_resource_patterns(cpu_usage)
        
        return patterns
    
    def _analyze_tool_patterns(self, tool_calls: List[int]) -> Dict[str, float]:
        """Analyze tool usage patterns"""
        if not tool_calls:
            return {'burst_detection': 0, 'consistency': 0}
        
        mean_calls = statistics.mean(tool_calls)
        return {
            'burst_detection': len([x for x in tool_calls if x > mean_calls * 2]),
            'consistency': statistics.stdev(tool_calls) if len(tool_calls) > 1 else 0
        }
    
    def _analyze_resource_patterns(self, cpu_usage: List[float]) -> Dict[str, float]:
        """Analyze resource usage patterns"""
        if not cpu_usage:
            return {'peak_cpu': 0, 'cpu_variance': 0}
        
        return {
            'peak_cpu': max(cpu_usage),
            'cpu_variance': statistics.variance(cpu_usage) if len(cpu_usage) > 1 else 0
        }
    
    def _calculate_deviations(self, current_stats: Dict[str, float], profile: Dict[str, Any]) -> Dict[str, float]:
        """Calculate deviations between current stats and profile"""
        deviations = {}
        
        for key in current_stats:
            profile_val = profile.get(key, 0)
            current_val = current_stats[key]
            
            if profile_val > 0:
                deviation = (current_val - profile_val) / profile_val
                deviations[key] = deviation
        
        return deviations
    
    def _calculate_similarity_score(self, deviations: Dict[str, float]) -> float:
        """Calculate similarity score between current behavior and profile"""
        if not deviations:
            return 1.0
        
        weights = {
            'avg_cpu': 0.2,
            'avg_memory': 0.2,
            'avg_network': 0.3,
            'total_tool_calls': 0.2,
            'total_errors': 0.1
        }
        
        weighted_deviation = sum(
            abs(deviations.get(key, 0)) * weight
            for key, weight in weights.items()
        )
        
        return max(0, 1 - weighted_deviation)