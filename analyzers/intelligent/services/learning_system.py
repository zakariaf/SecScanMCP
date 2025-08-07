"""Learning and feedback system."""

import logging
import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional

from ..models.analysis_models import CodeContext, LegitimacyAnalysis

logger = logging.getLogger(__name__)


class FeedbackDatabase:
    """Database for storing feedback and learning data."""
    
    def __init__(self, db_path: str):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        self._initialize_db()
    
    def _initialize_db(self):
        """Initialize database tables."""
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analysis_feedback (
                    id INTEGER PRIMARY KEY,
                    code_hash TEXT UNIQUE,
                    original_classification TEXT,
                    corrected_classification TEXT,
                    feedback_reason TEXT,
                    confidence_adjustment REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS pattern_learning (
                    id INTEGER PRIMARY KEY,
                    pattern_signature TEXT,
                    context_features TEXT,
                    legitimacy_score REAL,
                    confidence REAL,
                    verification_count INTEGER DEFAULT 1,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS model_performance (
                    id INTEGER PRIMARY KEY,
                    model_version TEXT,
                    accuracy REAL,
                    precision_score REAL,
                    recall REAL,
                    f1_score REAL,
                    evaluation_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
    
    def store_feedback(self, code_hash: str, original: str, corrected: str, 
                      reason: str, confidence_adj: float = 0.0):
        """Store user feedback."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO analysis_feedback 
                (code_hash, original_classification, corrected_classification, 
                 feedback_reason, confidence_adjustment)
                VALUES (?, ?, ?, ?, ?)
            """, (code_hash, original, corrected, reason, confidence_adj))
    
    def get_feedback_for_pattern(self, pattern_sig: str) -> list:
        """Get feedback for similar patterns."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute("""
                SELECT * FROM analysis_feedback 
                WHERE code_hash IN (
                    SELECT code_hash FROM pattern_learning 
                    WHERE pattern_signature = ?
                )
            """, (pattern_sig,))
            return cursor.fetchall()
    
    def update_pattern_learning(self, pattern_sig: str, features: Dict, 
                               legitimacy: float, confidence: float):
        """Update pattern learning data."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO pattern_learning 
                (pattern_signature, context_features, legitimacy_score, 
                 confidence, verification_count, last_updated)
                VALUES (?, ?, ?, ?, 
                    COALESCE((SELECT verification_count + 1 FROM pattern_learning 
                             WHERE pattern_signature = ?), 1),
                    CURRENT_TIMESTAMP)
            """, (pattern_sig, json.dumps(features), legitimacy, 
                 confidence, pattern_sig))


class ModelUpdater:
    """Updates ML models based on feedback."""
    
    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.model_path.mkdir(exist_ok=True, parents=True)
    
    def update_models(self, feedback_data: list):
        """Update models with new feedback data."""
        if not feedback_data:
            logger.info("No feedback data for model updates")
            return
        
        # In production, this would retrain ML models
        logger.info(f"Processing {len(feedback_data)} feedback samples")
        
        # Update thresholds based on feedback
        self._update_thresholds(feedback_data)
    
    def _update_thresholds(self, feedback_data: list):
        """Update classification thresholds based on feedback."""
        # Simple threshold adjustment based on false positive/negative rates
        false_positives = sum(1 for f in feedback_data 
                            if f[1] == 'malicious' and f[2] == 'legitimate')
        false_negatives = sum(1 for f in feedback_data 
                            if f[1] == 'legitimate' and f[2] == 'malicious')
        
        total_feedback = len(feedback_data)
        if total_feedback > 0:
            fp_rate = false_positives / total_feedback
            fn_rate = false_negatives / total_feedback
            
            logger.info(f"FP rate: {fp_rate:.3f}, FN rate: {fn_rate:.3f}")
            
            # Adjust thresholds (simple heuristic)
            if fp_rate > 0.1:  # Too many false positives
                logger.info("Lowering sensitivity due to high FP rate")
            if fn_rate > 0.05:  # Too many false negatives
                logger.info("Increasing sensitivity due to high FN rate")


class LearningSystem:
    """Main learning and feedback system."""
    
    def __init__(self, storage_path: str = "/tmp/security_learning"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(exist_ok=True, parents=True)
        
        self.feedback_db = FeedbackDatabase(
            self.storage_path / "feedback.db"
        )
        self.model_updater = ModelUpdater(
            self.storage_path / "models"
        )
    
    async def record_analysis(self, context: CodeContext, 
                            analysis: LegitimacyAnalysis):
        """Record analysis for learning purposes."""
        code_hash = self._generate_code_hash(context)
        
        # Store pattern for future reference
        pattern_sig = self._create_pattern_signature(context)
        features = self._extract_learning_features(context)
        
        self.feedback_db.update_pattern_learning(
            pattern_sig, features, 
            1.0 if analysis.is_legitimate else 0.0,
            analysis.confidence_score
        )
        
        logger.debug(f"Recorded analysis for pattern: {pattern_sig}")
    
    def submit_feedback(self, code_hash: str, original_result: str, 
                       corrected_result: str, reason: str):
        """Submit user feedback for learning."""
        try:
            self.feedback_db.store_feedback(
                code_hash, original_result, corrected_result, reason
            )
            
            logger.info(f"Feedback recorded: {original_result} -> {corrected_result}")
            
            # Trigger model update if enough feedback accumulated
            self._trigger_learning_update()
            
        except Exception as e:
            logger.error(f"Failed to submit feedback: {e}")
    
    def _generate_code_hash(self, context: CodeContext) -> str:
        """Generate unique hash for code context."""
        content = f"{context.project_name}:{context.language}:{len(context.functions)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _create_pattern_signature(self, context: CodeContext) -> str:
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
    
    def _extract_learning_features(self, context: CodeContext) -> Dict[str, Any]:
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
    
    def _trigger_learning_update(self):
        """Trigger model update if conditions are met."""
        # In production, this would check conditions like:
        # - Enough new feedback samples
        # - Scheduled update time
        # - Performance degradation detected
        pass
    
    def get_learning_stats(self) -> Dict[str, Any]:
        """Get learning system statistics."""
        with sqlite3.connect(self.feedback_db.db_path) as conn:
            cursor = conn.execute("SELECT COUNT(*) FROM analysis_feedback")
            feedback_count = cursor.fetchone()[0]
            
            cursor = conn.execute("SELECT COUNT(*) FROM pattern_learning")
            pattern_count = cursor.fetchone()[0]
        
        return {
            'feedback_samples': feedback_count,
            'learned_patterns': pattern_count,
            'last_update': datetime.now().isoformat()
        }