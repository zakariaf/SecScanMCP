"""Async database operations for learning system."""

import asyncio
import aiosqlite
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime
from contextlib import asynccontextmanager

from ..utils.config_manager import ConfigManager
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class AsyncDatabaseManager:
    """Async database manager using aiosqlite."""
    
    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        settings = config_manager.load_settings()
        self.db_path = Path(settings.database.path)
        
        # Ensure database directory exists (important for container deployment)
        self.db_path.parent.mkdir(exist_ok=True, parents=True)
        logger.info("Database path configured",
                   db_path=str(self.db_path),
                   async_enabled=settings.database.async_enabled,
                   component="async_database")
        
        self._connection = None
    
    @asynccontextmanager
    async def get_connection(self):
        """Get async database connection."""
        if self._connection is None:
            self._connection = await aiosqlite.connect(self.db_path)
            await self._initialize_tables()
        
        try:
            yield self._connection
        except Exception as e:
            logger.error("Database operation failed",
                           error=str(e),
                           component="async_database")
            await self._connection.rollback()
            raise
    
    async def _initialize_tables(self):
        """Initialize database tables."""
        await self._connection.executescript("""
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
            
            CREATE INDEX IF NOT EXISTS idx_code_hash ON analysis_feedback(code_hash);
            CREATE INDEX IF NOT EXISTS idx_pattern_sig ON pattern_learning(pattern_signature);
            CREATE INDEX IF NOT EXISTS idx_created_at ON analysis_feedback(created_at);
        """)
        await self._connection.commit()
    
    async def store_feedback(self, code_hash: str, original: str, corrected: str, 
                           reason: str, confidence_adj: float = 0.0):
        """Store user feedback asynchronously."""
        async with self.get_connection() as conn:
            await conn.execute("""
                INSERT OR REPLACE INTO analysis_feedback 
                (code_hash, original_classification, corrected_classification, 
                 feedback_reason, confidence_adjustment)
                VALUES (?, ?, ?, ?, ?)
            """, (code_hash, original, corrected, reason, confidence_adj))
            await conn.commit()
            logger.debug("Stored feedback",
                        code_hash=code_hash[:8],
                        original=original,
                        corrected=corrected,
                        component="async_database")
    
    async def get_feedback_for_pattern(self, pattern_sig: str, limit: int = 100) -> List[Dict]:
        """Get feedback for similar patterns asynchronously."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("""
                SELECT af.* FROM analysis_feedback af
                INNER JOIN pattern_learning pl ON af.code_hash = pl.pattern_signature
                WHERE pl.pattern_signature = ?
                ORDER BY af.created_at DESC
                LIMIT ?
            """, (pattern_sig, limit))
            
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            return [dict(zip(columns, row)) for row in rows]
    
    async def update_pattern_learning(self, pattern_sig: str, features: Dict, 
                                    legitimacy: float, confidence: float):
        """Update pattern learning data asynchronously."""
        async with self.get_connection() as conn:
            # Check if pattern exists
            cursor = await conn.execute(
                "SELECT verification_count FROM pattern_learning WHERE pattern_signature = ?",
                (pattern_sig,)
            )
            row = await cursor.fetchone()
            
            if row:
                # Update existing pattern
                new_count = row[0] + 1
                await conn.execute("""
                    UPDATE pattern_learning 
                    SET context_features = ?, legitimacy_score = ?, confidence = ?,
                        verification_count = ?, last_updated = CURRENT_TIMESTAMP
                    WHERE pattern_signature = ?
                """, (json.dumps(features), legitimacy, confidence, new_count, pattern_sig))
            else:
                # Insert new pattern
                await conn.execute("""
                    INSERT INTO pattern_learning 
                    (pattern_signature, context_features, legitimacy_score, 
                     confidence, verification_count)
                    VALUES (?, ?, ?, ?, 1)
                """, (pattern_sig, json.dumps(features), legitimacy, confidence))
            
            await conn.commit()
            logger.debug("Updated pattern learning",
                        pattern_signature=pattern_sig[:16],
                        component="async_database")
    
    async def get_recent_feedback(self, days: int = 30, limit: int = 500) -> List[Dict]:
        """Get recent feedback for model updates."""
        async with self.get_connection() as conn:
            cursor = await conn.execute("""
                SELECT * FROM analysis_feedback 
                WHERE created_at >= datetime('now', '-{} days')
                ORDER BY created_at DESC
                LIMIT ?
            """.format(days), (limit,))
            
            rows = await cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            return [dict(zip(columns, row)) for row in rows]
    
    async def get_pattern_stats(self) -> Dict[str, Any]:
        """Get pattern learning statistics."""
        async with self.get_connection() as conn:
            # Count patterns by legitimacy
            cursor = await conn.execute("""
                SELECT 
                    COUNT(*) as total_patterns,
                    AVG(legitimacy_score) as avg_legitimacy,
                    AVG(confidence) as avg_confidence,
                    SUM(verification_count) as total_verifications
                FROM pattern_learning
            """)
            stats = await cursor.fetchone()
            
            # Count feedback by classification
            cursor = await conn.execute("""
                SELECT 
                    original_classification,
                    corrected_classification,
                    COUNT(*) as count
                FROM analysis_feedback
                GROUP BY original_classification, corrected_classification
            """)
            feedback_stats = await cursor.fetchall()
            
            return {
                'total_patterns': stats[0] or 0,
                'avg_legitimacy': stats[1] or 0.0,
                'avg_confidence': stats[2] or 0.0,
                'total_verifications': stats[3] or 0,
                'feedback_breakdown': [
                    {'original': row[0], 'corrected': row[1], 'count': row[2]}
                    for row in feedback_stats
                ]
            }
    
    async def cleanup_old_data(self, retention_days: int = 365):
        """Clean up old data based on retention policy."""
        async with self.get_connection() as conn:
            # Clean old feedback
            cursor = await conn.execute("""
                DELETE FROM analysis_feedback 
                WHERE created_at < datetime('now', '-{} days')
            """.format(retention_days))
            
            deleted_feedback = cursor.rowcount
            
            # Clean old patterns with low verification
            cursor = await conn.execute("""
                DELETE FROM pattern_learning 
                WHERE verification_count < 3 
                AND last_updated < datetime('now', '-{} days')
            """.format(retention_days // 2))
            
            deleted_patterns = cursor.rowcount
            
            await conn.commit()
            
            logger.info("Cleaned up old data",
                       deleted_feedback=deleted_feedback,
                       deleted_patterns=deleted_patterns,
                       component="async_database")
            
            return {
                'deleted_feedback': deleted_feedback,
                'deleted_patterns': deleted_patterns
            }
    
    async def close(self):
        """Close database connection."""
        if self._connection:
            await self._connection.close()
            self._connection = None


class AsyncFeedbackCollector:
    """Collects and processes feedback asynchronously."""
    
    def __init__(self, db_manager: AsyncDatabaseManager):
        self.db_manager = db_manager
        self._feedback_queue = asyncio.Queue()
        self._processing_task = None
    
    async def start_processing(self):
        """Start background feedback processing."""
        if self._processing_task is None:
            self._processing_task = asyncio.create_task(self._process_feedback_queue())
            logger.info("Started async feedback processing",
                       component="async_feedback_collector")
    
    async def stop_processing(self):
        """Stop background feedback processing."""
        if self._processing_task:
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
            self._processing_task = None
            logger.info("Stopped async feedback processing",
                       component="async_feedback_collector")
    
    async def submit_feedback(self, code_hash: str, original: str, corrected: str, reason: str):
        """Submit feedback for async processing."""
        await self._feedback_queue.put({
            'code_hash': code_hash,
            'original': original,
            'corrected': corrected,
            'reason': reason,
            'timestamp': datetime.now()
        })
        logger.debug("Queued feedback",
                    code_hash=code_hash[:8],
                    component="async_feedback_collector")
    
    async def _process_feedback_queue(self):
        """Process feedback queue in background."""
        while True:
            try:
                # Process feedback in batches for efficiency
                batch = []
                timeout = 5.0  # 5 second batching window
                
                try:
                    # Get first item with timeout
                    item = await asyncio.wait_for(self._feedback_queue.get(), timeout)
                    batch.append(item)
                    
                    # Collect more items without waiting
                    while not self._feedback_queue.empty() and len(batch) < 10:
                        batch.append(self._feedback_queue.get_nowait())
                        
                except asyncio.TimeoutError:
                    continue
                
                if batch:
                    await self._process_feedback_batch(batch)
                    
            except asyncio.CancelledError:
                logger.info("Feedback processing cancelled",
                           component="async_feedback_collector")
                break
            except Exception as e:
                logger.error("Error processing feedback",
                            error=str(e),
                            component="async_feedback_collector")
                await asyncio.sleep(1)  # Brief pause before retrying
    
    async def _process_feedback_batch(self, batch: List[Dict]):
        """Process a batch of feedback items."""
        for item in batch:
            try:
                await self.db_manager.store_feedback(
                    item['code_hash'],
                    item['original'],
                    item['corrected'],
                    item['reason']
                )
            except Exception as e:
                logger.error("Failed to store feedback",
                            code_hash=item['code_hash'][:8],
                            error=str(e),
                            component="async_feedback_collector")
        
        logger.debug("Processed feedback batch",
                    batch_size=len(batch),
                    component="async_feedback_collector")