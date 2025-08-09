"""
Language Detection Service for CodeQL Analysis

Detects programming languages in repository for CodeQL analysis
Following clean architecture with single responsibility
"""

import logging
from pathlib import Path
from typing import List, Dict, Any, Set

logger = logging.getLogger(__name__)


class LanguageService:
    """Detects programming languages for CodeQL analysis"""
    
    # Supported languages by CodeQL
    SUPPORTED_LANGUAGES = {
        "python", "javascript", "java", "csharp", "cpp", "go", "ruby"
    }
    
    # Extension to language mapping
    EXTENSION_MAP = {
        ".py": "python",
        ".js": "javascript", 
        ".jsx": "javascript", 
        ".ts": "javascript", 
        ".tsx": "javascript",
        ".java": "java",
        ".cs": "csharp",
        ".c": "cpp", 
        ".cc": "cpp", 
        ".cpp": "cpp", 
        ".cxx": "cpp", 
        ".h": "cpp", 
        ".hpp": "cpp",
        ".go": "go",  
        ".rb": "ruby",
    }
    
    def __init__(self, base_analyzer):
        self.base_analyzer = base_analyzer
    
    def detect_languages(self, repo_path: Path, project_info: Dict[str, Any]) -> List[str]:
        """Detect programming languages in the repository"""
        languages = set()
        
        # Add language from project info hint
        languages.update(self._get_language_from_project_info(project_info))
        
        # Scan repository files for language patterns
        languages.update(self._scan_repository_files(repo_path))
        
        # Log MCP project indicators
        self._check_mcp_indicators(repo_path)
        
        detected_languages = list(languages & self.SUPPORTED_LANGUAGES)
        logger.info(f"Detected languages for CodeQL: {detected_languages}")
        
        return detected_languages
    
    def _get_language_from_project_info(self, project_info: Dict[str, Any]) -> Set[str]:
        """Extract language from project information"""
        languages = set()
        
        lang = (project_info or {}).get("language", "").lower()
        if lang in self.SUPPORTED_LANGUAGES:
            # Map TypeScript to JavaScript for CodeQL
            if lang in {"javascript", "typescript"}:
                languages.add("javascript")
            else:
                languages.add(lang)
        
        return languages
    
    def _scan_repository_files(self, repo_path: Path) -> Set[str]:
        """Scan repository files to detect languages by extension"""
        languages = set()
        
        try:
            # Get filtered files from base analyzer
            filtered_files = self.base_analyzer.get_filtered_files(str(repo_path))
            
            for file_path in filtered_files:
                file_ext = Path(file_path).suffix.lower()
                if file_ext in self.EXTENSION_MAP:
                    languages.add(self.EXTENSION_MAP[file_ext])
            
        except Exception as e:
            logger.error(f"Error scanning repository files: {e}")
        
        return languages
    
    def _check_mcp_indicators(self, repo_path: Path):
        """Check for MCP project indicators and log if found"""
        try:
            filtered_files = self.base_analyzer.get_filtered_files(str(repo_path))
            
            mcp_indicators = any([
                any(
                    "mcp" in Path(f).name.lower() and f.endswith((".json", ".yaml", ".yml")) 
                    for f in filtered_files
                ),
                any(
                    "tool" in Path(f).name.lower() and "schema" in Path(f).name.lower() and f.endswith(".json") 
                    for f in filtered_files
                )
            ])
            
            if mcp_indicators:
                logger.info("MCP project indicators detected.")
                logger.info("MCP-specific rules are enabled.")
                
        except Exception as e:
            logger.debug(f"Error checking MCP indicators: {e}")
    
    def is_language_supported(self, language: str) -> bool:
        """Check if language is supported by CodeQL"""
        return language.lower() in self.SUPPORTED_LANGUAGES
    
    def get_supported_languages(self) -> List[str]:
        """Get list of all supported languages"""
        return list(self.SUPPORTED_LANGUAGES)