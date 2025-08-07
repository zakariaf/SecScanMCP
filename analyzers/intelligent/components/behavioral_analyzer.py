"""Behavioral pattern analysis component."""

import numpy as np
from typing import Tuple, Dict, Any, List
from collections import defaultdict

from .base_analyzer import BaseAnalyzer
from ..models.analysis_models import CodeContext
from ..utils.ml_utils import is_ml_available
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class BehavioralFingerprinter:
    """Creates behavioral fingerprints from code context."""
    
    def create_fingerprint(self, context: CodeContext) -> Dict[str, Any]:
        """Create comprehensive behavioral fingerprint."""
        return {
            'operation_counts': self._get_operation_counts(context),
            'operation_types': self._get_operation_types(context),
            'complexity_metrics': self._get_complexity_metrics(context),
            'risk_indicators': self._get_risk_indicators(context),
            'project_metadata': self._get_project_metadata(context)
        }
    
    def _get_operation_counts(self, context: CodeContext) -> Dict[str, int]:
        """Get counts of different operation types."""
        return {
            'file_ops': len(context.file_operations),
            'network_ops': len(context.network_operations),
            'system_ops': len(context.system_operations),
            'functions': len(context.functions)
        }
    
    def _get_operation_types(self, context: CodeContext) -> Dict[str, List[str]]:
        """Get specific operation type patterns."""
        return {
            'file_ops': list(set(op.get('operation', 'unknown') 
                               for op in context.file_operations)),
            'network_methods': list(set(op.get('method', 'unknown') 
                                      for op in context.network_operations)),
            'system_commands': list(set(op.get('command_type', 'unknown') 
                                      for op in context.system_operations))
        }
    
    def _get_complexity_metrics(self, context: CodeContext) -> Dict[str, float]:
        """Calculate complexity-related metrics."""
        complexities = [func.get('complexity', 1) for func in context.functions]
        
        return {
            'avg_function_complexity': np.mean(complexities) if complexities else 0,
            'max_function_complexity': max(complexities) if complexities else 0,
            'dependency_count': len(context.dependencies)
        }
    
    def _get_risk_indicators(self, context: CodeContext) -> Dict[str, bool]:
        """Identify potential risk indicators."""
        all_ops = (context.file_operations + 
                  context.network_operations + 
                  context.system_operations)
        
        return {
            'has_user_input': self._has_user_input_ops(all_ops),
            'has_external_network': self._has_external_network_ops(
                context.network_operations),
            'has_system_commands': len(context.system_operations) > 0,
            'mixed_operation_types': self._has_mixed_ops(context)
        }
    
    def _has_user_input_ops(self, operations: List[Dict]) -> bool:
        """Check if operations involve user input."""
        user_keywords = ['user', 'input', 'request', 'param']
        return any(any(kw in str(op).lower() for kw in user_keywords) 
                  for op in operations)
    
    def _has_external_network_ops(self, network_ops: List[Dict]) -> bool:
        """Check for external network operations."""
        return any('external' in str(op).lower() for op in network_ops)
    
    def _has_mixed_ops(self, context: CodeContext) -> bool:
        """Check if project has mixed operation types."""
        op_types = sum([
            len(context.file_operations) > 0,
            len(context.network_operations) > 0,
            len(context.system_operations) > 0
        ])
        return op_types >= 2
    
    def _get_project_metadata(self, context: CodeContext) -> Dict[str, str]:
        """Extract project metadata."""
        return {
            'project_type': context.project_type,
            'language': context.language
        }


class PatternMatcher:
    """Matches behavioral patterns against known patterns."""
    
    def __init__(self):
        self.known_patterns = self._load_known_patterns()
    
    def find_similar_patterns(self, fingerprint: Dict) -> List[Dict]:
        """Find patterns similar to given fingerprint."""
        similarities = []
        
        for pattern_name, pattern_data in self.known_patterns.items():
            similarity = self._calculate_pattern_similarity(fingerprint, pattern_data)
            if similarity > 0.3:  # Threshold for meaningful similarity
                similarities.append({
                    'pattern_name': pattern_name,
                    'similarity': similarity,
                    'legitimacy_score': pattern_data.get('legitimacy', 0.5),
                    'confidence': pattern_data.get('confidence', 0.5)
                })
        
        return sorted(similarities, key=lambda x: x['similarity'], reverse=True)
    
    def _load_known_patterns(self) -> Dict[str, Dict]:
        """Load known behavioral patterns."""
        # In production, this would load from database
        return {
            'mcp_storage_server': {
                'file_ops': [2, 5],  # Range of expected file operations
                'network_ops': [0, 2],
                'system_ops': [0, 0],
                'has_mcp_deps': True,
                'legitimacy': 0.8,
                'confidence': 0.7
            },
            'web_scraper': {
                'file_ops': [1, 10],
                'network_ops': [5, 50],
                'system_ops': [0, 1],
                'has_external_network': True,
                'legitimacy': 0.6,
                'confidence': 0.5
            }
        }
    
    def _calculate_pattern_similarity(self, fingerprint: Dict, pattern: Dict) -> float:
        """Calculate similarity between fingerprint and known pattern."""
        score = 0.0
        checks = 0
        
        # Check operation counts
        op_counts = fingerprint.get('operation_counts', {})
        for op_type, count in op_counts.items():
            if op_type in pattern:
                expected_range = pattern[op_type]
                if isinstance(expected_range, list) and len(expected_range) == 2:
                    if expected_range[0] <= count <= expected_range[1]:
                        score += 1
                    checks += 1
        
        # Check boolean indicators
        risk_indicators = fingerprint.get('risk_indicators', {})
        for indicator, value in risk_indicators.items():
            if indicator in pattern:
                if pattern[indicator] == value:
                    score += 1
                checks += 1
        
        return score / checks if checks > 0 else 0.0


class BehavioralPatternAnalyzer(BaseAnalyzer):
    """Analyzes behavioral patterns using clustering and pattern matching."""
    
    def __init__(self):
        self.fingerprinter = BehavioralFingerprinter()
        self.pattern_matcher = PatternMatcher()
    
    async def analyze(self, context: CodeContext) -> Tuple[float, Dict[str, Any]]:
        """Analyze behavioral patterns for legitimacy."""
        evidence = {
            'behavioral_fingerprint': {},
            'similar_patterns': [],
            'pattern_confidence': 0.0,
            'anomaly_indicators': []
        }
        
        # Create behavioral fingerprint
        fingerprint = self.fingerprinter.create_fingerprint(context)
        evidence['behavioral_fingerprint'] = fingerprint
        
        # Find similar patterns
        similar_patterns = self.pattern_matcher.find_similar_patterns(fingerprint)
        evidence['similar_patterns'] = similar_patterns[:5]  # Top 5
        
        # Calculate legitimacy score
        if similar_patterns:
            # Weight by similarity
            weighted_scores = []
            total_weight = 0
            
            for pattern in similar_patterns:
                weight = pattern['similarity'] * pattern['confidence']
                weighted_scores.append(pattern['legitimacy_score'] * weight)
                total_weight += weight
            
            legitimacy_score = sum(weighted_scores) / total_weight if total_weight > 0 else 0.5
            evidence['pattern_confidence'] = total_weight / len(similar_patterns)
        else:
            legitimacy_score = self._fallback_pattern_analysis(fingerprint)
            evidence['pattern_confidence'] = 0.3
        
        # Check for anomaly indicators
        anomalies = self._detect_pattern_anomalies(fingerprint)
        evidence['anomaly_indicators'] = anomalies
        
        # Adjust score based on anomalies
        if anomalies:
            anomaly_penalty = min(0.3, len(anomalies) * 0.1)
            legitimacy_score = max(0.1, legitimacy_score - anomaly_penalty)
        
        return float(legitimacy_score), evidence
    
    def _fallback_pattern_analysis(self, fingerprint: Dict) -> float:
        """Fallback analysis when no patterns match."""
        score = 0.5  # Neutral starting point
        
        # Basic heuristics
        op_counts = fingerprint.get('operation_counts', {})
        risk_indicators = fingerprint.get('risk_indicators', {})
        
        # Reasonable operation counts
        if op_counts.get('file_ops', 0) <= 5:
            score += 0.1
        if op_counts.get('system_ops', 0) == 0:
            score += 0.2
        if op_counts.get('network_ops', 0) <= 3:
            score += 0.1
        
        # Low risk indicators
        if not risk_indicators.get('has_user_input', False):
            score += 0.1
        if not risk_indicators.get('has_external_network', False):
            score += 0.1
        
        return min(1.0, score)
    
    def _detect_pattern_anomalies(self, fingerprint: Dict) -> List[str]:
        """Detect anomalous patterns in behavior."""
        anomalies = []
        
        op_counts = fingerprint.get('operation_counts', {})
        risk_indicators = fingerprint.get('risk_indicators', {})
        
        # Excessive operations
        if op_counts.get('file_ops', 0) > 20:
            anomalies.append("Excessive file operations")
        if op_counts.get('network_ops', 0) > 15:
            anomalies.append("Excessive network operations")
        if op_counts.get('system_ops', 0) > 5:
            anomalies.append("Multiple system operations")
        
        # Risky combinations
        if (op_counts.get('system_ops', 0) > 0 and 
            op_counts.get('network_ops', 0) > 0):
            anomalies.append("System and network operations combined")
        
        # User input in sensitive operations
        if risk_indicators.get('has_user_input', False):
            anomalies.append("User input in operations")
        
        return anomalies