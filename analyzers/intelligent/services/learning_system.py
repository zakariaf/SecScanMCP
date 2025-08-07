"""Learning and feedback system with async operations."""

import logging
import hashlib
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from ..models.analysis_models import CodeContext, LegitimacyAnalysis
from .async_database import AsyncDatabaseManager, AsyncFeedbackCollector
from ..utils.config_manager import ConfigManager

logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyzes patterns for learning purposes."""
    
    def create_pattern_signature(self, context: CodeContext) -> str:
        """Create pattern signature for learning."""
        file_ops = len(context.file_operations)
        net_ops = len(context.network_operations)
        sys_ops = len(context.system_operations)
        
        if 'mcp' in context.project_name.lower():
            if file_ops > 0 and net_ops == 0 and sys_ops == 0:
                return 'mcp_file_storage'
            elif file_ops == 0 and net_ops > 0 and sys_ops == 0:
                return 'mcp_network_client'
        
        if net_ops > file_ops and net_ops > 10:
            return 'network_heavy'
        elif sys_ops > 0:
            return 'system_commands'
        else:
            return 'general_utility'
    
    def extract_learning_features(self, context: CodeContext) -> Dict[str, Any]:
        """Extract features for learning algorithms."""
        return {
            'file_ops_count': len(context.file_operations),
            'network_ops_count': len(context.network_operations),
            'system_ops_count': len(context.system_operations),
            'function_count': len(context.functions),
            'dependency_count': len(context.dependencies),
            'project_type': context.project_type,
            'language': context.language,
            'has_readme': bool(context.readme_content),
            'has_docstrings': bool(context.docstrings)
        }
    
    def generate_code_hash(self, context: CodeContext) -> str:
        """Generate unique hash for code context."""
        content = f"{context.project_name}:{context.language}:{len(context.functions)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class ModelUpdater:
    """Updates ML models based on feedback."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
    
    async def analyze_feedback_trends(self, feedback_data: List[Dict]) -> Dict[str, float]:
        """Analyze feedback trends for model improvement."""
        if not feedback_data:
            return {'fp_rate': 0.0, 'fn_rate': 0.0, 'total_samples': 0}
        
        false_positives = sum(1 for f in feedback_data 
                            if f.get('original_classification') == 'malicious' 
                            and f.get('corrected_classification') == 'legitimate')
        
        false_negatives = sum(1 for f in feedback_data 
                            if f.get('original_classification') == 'legitimate' 
                            and f.get('corrected_classification') == 'malicious')
        
        total = len(feedback_data)
        return {
            'fp_rate': false_positives / total if total > 0 else 0.0,
            'fn_rate': false_negatives / total if total > 0 else 0.0,
            'total_samples': total
        }


class LearningSystem:
    """Lightweight learning and feedback system with async operations."""
    
    def __init__(self, storage_path: str = "/tmp/security_learning", 
                 config_manager: ConfigManager = None):
        self.config_manager = config_manager or ConfigManager()
        
        # Initialize components
        self.pattern_analyzer = PatternAnalyzer()
        self.model_updater = ModelUpdater(self.config_manager)
        self.db_manager = AsyncDatabaseManager(self.config_manager)
        self.feedback_collector = AsyncFeedbackCollector(self.db_manager)
        
        # Start async processing
        self._setup_async_processing()
    
    def _setup_async_processing(self):
        """Set up async processing if event loop is available."""
        try:
            loop = asyncio.get_running_loop()
            asyncio.create_task(self.feedback_collector.start_processing())
        except RuntimeError:
            # No event loop running, will start when needed
            pass
    
    async def record_analysis(self, context: CodeContext, 
                            analysis: LegitimacyAnalysis):
        """Record analysis for learning purposes."""
        code_hash = self.pattern_analyzer.generate_code_hash(context)
        pattern_sig = self.pattern_analyzer.create_pattern_signature(context)
        features = self.pattern_analyzer.extract_learning_features(context)
        
        legitimacy_score = 1.0 if analysis.is_legitimate else 0.0
        await self.db_manager.update_pattern_learning(
            pattern_sig, features, legitimacy_score, analysis.confidence_score
        )
        
        logger.debug(f"Recorded analysis for pattern: {pattern_sig}")
    
    async def submit_feedback(self, code_hash: str, original_result: str, 
                            corrected_result: str, reason: str):
        """Submit user feedback for learning."""
        await self.feedback_collector.submit_feedback(
            code_hash, original_result, corrected_result, reason
        )
        logger.info(f"Feedback submitted: {original_result} -> {corrected_result}")
    
    async def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning system statistics."""
        stats = await self.db_manager.get_pattern_stats()
        stats['last_update'] = datetime.now().isoformat()
        return stats
    
    async def analyze_recent_feedback(self, days: int = 7) -> Dict[str, Any]:
        """Analyze recent feedback for insights."""
        feedback_data = await self.db_manager.get_recent_feedback(days=days)
        return await self.model_updater.analyze_feedback_trends(feedback_data)
    
    async def cleanup_old_data(self, retention_days: int = 365):
        """Clean up old data based on retention policy."""
        return await self.db_manager.cleanup_old_data(retention_days)
    
    async def close(self):
        """Clean up resources."""
        await self.feedback_collector.stop_processing()
        await self.db_manager.close()