"""Semantic intent analysis component."""

import numpy as np
from typing import Tuple, Dict, Any, List

from .base_analyzer import BaseAnalyzer
from ..models.analysis_models import CodeContext
from ..utils.ml_utils import is_ml_available
from ..utils.text_utils import extract_keywords, clean_text, calculate_text_overlap
from ..utils.embeddings import EmbeddingsManager
from ..utils.config_manager import ConfigManager
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class IntentExtractor:
    """Extracts declared intents from project context."""
    
    def extract(self, context: CodeContext) -> List[str]:
        """Extract declared intents from multiple sources."""
        intents = []
        
        intents.extend(self._extract_from_name(context.project_name))
        intents.extend(self._extract_from_description(context.project_description))
        intents.extend(self._extract_from_readme(context.readme_content))
        intents.extend(self._extract_from_docstrings(context.docstrings))
        
        return [intent for intent in intents if len(intent.strip()) > 5]
    
    def _extract_from_name(self, project_name: str) -> List[str]:
        """Extract intent from project name."""
        if not project_name:
            return []
            
        clean_name = clean_text(project_name)
        return [f"project provides {clean_name} functionality"]
    
    def _extract_from_description(self, description: str) -> List[str]:
        """Extract intent from project description."""
        return [description.lower()] if description else []
    
    def _extract_from_readme(self, readme: str) -> List[str]:
        """Extract functional descriptions from README."""
        if not readme:
            return []
            
        intents = []
        readme_lower = readme.lower()
        
        # Extract functional sentences
        keywords = ['server', 'tool', 'function', 'provide', 'enable', 
                   'allow', 'memory', 'storage', 'persist', 'save', 
                   'store', 'cache']
        sentences = readme_lower.split('.')
        
        for sentence in sentences:
            if any(kw in sentence for kw in keywords) and len(sentence) > 10:
                intents.append(sentence.strip())
                
        return intents[:8]  # Limit to prevent noise
    
    def _extract_from_docstrings(self, docstrings: List[str]) -> List[str]:
        """Extract intent from docstrings.""" 
        return [doc.lower() for doc in docstrings[:10]] if docstrings else []


class BehaviorExtractor:
    """Extracts behavioral patterns from code analysis."""
    
    def extract(self, context: CodeContext) -> List[str]:
        """Extract actual behavioral patterns."""
        behaviors = []
        
        behaviors.extend(self._extract_file_behaviors(context.file_operations))
        behaviors.extend(self._extract_network_behaviors(context.network_operations))
        behaviors.extend(self._extract_system_behaviors(context.system_operations))
        behaviors.extend(self._extract_function_behaviors(context.functions))
        behaviors.extend(self._extract_dependency_behaviors(context.dependencies))
        
        return behaviors
    
    def _extract_file_behaviors(self, file_ops: List[Dict]) -> List[str]:
        """Extract file operation behaviors."""
        behaviors = []
        
        for op in file_ops:
            operation = op.get('operation', 'file operation').lower()
            target = op.get('target', 'files')
            
            if self._is_storage_operation(operation, target):
                behaviors.append(f"stores data persistently in {target}")
                behaviors.append("provides data persistence functionality")
            elif 'write' in operation:
                behaviors.append(f"writes data to {target}")
            elif 'read' in operation:
                behaviors.append(f"reads data from {target}")
            else:
                behaviors.append(f"performs {operation} on {target}")
                
        return behaviors
    
    def _is_storage_operation(self, operation: str, target: str) -> bool:
        """Check if operation is storage-related."""
        storage_words = ['memory', 'cache', 'data', 'store']
        return 'write' in operation and any(word in target.lower() for word in storage_words)
    
    def _extract_network_behaviors(self, network_ops: List[Dict]) -> List[str]:
        """Extract network operation behaviors."""
        behaviors = []
        
        for op in network_ops:
            method = op.get('method', 'network').lower()
            target = op.get('target', 'external services')
            behaviors.append(f"makes {method} requests to {target}")
            
        return behaviors
    
    def _extract_system_behaviors(self, system_ops: List[Dict]) -> List[str]:
        """Extract system operation behaviors."""
        behaviors = []
        
        for op in system_ops:
            cmd_type = op.get('command_type', 'system commands')
            purpose = op.get('purpose', 'system interaction')
            behaviors.append(f"executes {cmd_type} for {purpose}")
            
        return behaviors
    
    def _extract_function_behaviors(self, functions: List[Dict]) -> List[str]:
        """Extract function-level behaviors."""
        behaviors = []
        
        for func in functions:
            func_name = func.get('name', '').lower()
            description = func.get('description', '')
            
            if description:
                behaviors.append(f"implements {description.lower()}")
            elif func_name:
                behavior = self._infer_from_function_name(func_name)
                if behavior:
                    behaviors.append(behavior)
                    
        return behaviors
    
    def _infer_from_function_name(self, func_name: str) -> str:
        """Infer behavior from function name."""
        store_words = ['add', 'store', 'save', 'write']
        retrieve_words = ['get', 'read', 'query', 'fetch']
        memory_words = ['memory', 'cache', 'persist']
        
        if any(word in func_name for word in store_words):
            return "provides data storage functionality"
        elif any(word in func_name for word in retrieve_words):
            return "provides data retrieval functionality"
        elif any(word in func_name for word in memory_words):
            return "manages persistent data storage"
        
        return ""
    
    def _extract_dependency_behaviors(self, dependencies: List[str]) -> List[str]:
        """Extract behaviors from dependencies."""
        behaviors = []
        
        for dep in dependencies:
            if 'mcp' in dep.lower() or 'modelcontextprotocol' in dep.lower():
                behaviors.extend([
                    "implements MCP server protocol",
                    "provides structured tool interface"
                ])
                
        return behaviors


class SemanticIntentAnalyzer(BaseAnalyzer):
    """Analyzes semantic alignment between declared intent and actual behavior."""
    
    def __init__(self):
        self.intent_extractor = IntentExtractor()
        self.behavior_extractor = BehaviorExtractor()
        self.embeddings_manager = EmbeddingsManager()
        self.config_manager = ConfigManager()
    
    async def analyze(self, context: CodeContext) -> Tuple[float, Dict[str, Any]]:
        """Analyze semantic alignment between intent and behavior."""
        evidence = {
            'declared_intents': [],
            'code_behaviors': [],
            'alignment_score': 0.0,
            'semantic_matches': []
        }
        
        # Extract intents and behaviors
        intents = self.intent_extractor.extract(context)
        behaviors = self.behavior_extractor.extract(context)
        
        evidence['declared_intents'] = intents
        evidence['code_behaviors'] = behaviors
        
        # Calculate alignment score using frozen embeddings
        if intents and behaviors:
            score = await self._embeddings_semantic_analysis(intents, behaviors, evidence)
        else:
            score = self._fallback_semantic_analysis(intents, behaviors)
            
        evidence['alignment_score'] = score
        return score, evidence
    
    async def _embeddings_semantic_analysis(self, intents: List[str], behaviors: List[str], 
                                           evidence: Dict) -> float:
        """Frozen embeddings-based semantic similarity analysis."""
        try:
            # Use frozen embeddings system (no runtime training)
            max_similarity = self.embeddings_manager.calculate_similarity(intents, behaviors)
            
            # Find best semantic matches
            matches = self.embeddings_manager.find_best_matches(intents, behaviors)
            evidence['semantic_matches'] = matches
            
            logger.debug("Embeddings analysis completed",
                        max_similarity=max_similarity,
                        matches_count=len(matches),
                        component="semantic_analyzer")
            return max_similarity
                
        except Exception as e:
            logger.debug("Embeddings semantic analysis failed",
                        error=str(e),
                        component="semantic_analyzer")
            
        return self._fallback_semantic_analysis(intents, behaviors)
    
    def _fallback_semantic_analysis(self, intents: List[str], behaviors: List[str]) -> float:
        """Keyword-based fallback analysis."""
        if not intents or not behaviors:
            return 0.5
        
        # Calculate text overlap
        intent_text = ' '.join(intents)
        behavior_text = ' '.join(behaviors)
        
        return calculate_text_overlap(intent_text, behavior_text)