"""
Base analyzer class that all security analyzers inherit from
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging
import os
from pathlib import Path

from models import Finding
from config.ignore_patterns import IgnorePatterns

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for all security analyzers"""

    def __init__(self):
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)
        self.tool_name = self.name.replace('Analyzer', '').lower()

    @abstractmethod
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """
        Analyze the repository for security vulnerabilities

        Args:
            repo_path: Path to the cloned repository
            project_info: Information about the project (type, language, etc.)

        Returns:
            List of security findings
        """
        pass

    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """
        Check if this analyzer is applicable to the project

        Override in subclasses for language-specific analyzers
        """
        return True

    def create_finding(self, **kwargs) -> Finding:
        """Helper to create a finding with the analyzer name"""
        kwargs['tool'] = self.tool_name
        return Finding(**kwargs)
    
    def get_filtered_files(self, repo_path: str, include_extensions: set = None) -> List[str]:
        """
        Get list of files to scan, applying ignore patterns
        
        Args:
            repo_path: Repository path to scan
            include_extensions: Optional set of file extensions to include (e.g., {'.py', '.js'})
            
        Returns:
            List of file paths that should be scanned
        """
        return IgnorePatterns.get_filtered_files(repo_path, self.tool_name, include_extensions)
    
    def should_ignore_file(self, file_path: str) -> bool:
        """Check if a file should be ignored by this analyzer"""
        return IgnorePatterns.should_ignore_file(file_path, self.tool_name)
    
    def should_ignore_directory(self, dir_path: str) -> bool:
        """Check if a directory should be ignored by this analyzer"""
        return IgnorePatterns.should_ignore_directory(dir_path, self.tool_name)
    
    def create_ignore_file(self, temp_path: str) -> str:
        """
        Create a temporary ignore file for tools that support .gitignore-style patterns
        
        Returns:
            Path to the created ignore file
        """
        import tempfile
        
        ignore_patterns = IgnorePatterns.create_gitignore_style_list(self.tool_name)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.ignore', delete=False) as f:
            for pattern in ignore_patterns:
                f.write(f"{pattern}\n")
            return f.name
    
    def log_scan_summary(self, repo_path: str):
        """Log summary of what will be scanned vs ignored"""
        summary = IgnorePatterns.get_scan_summary(repo_path)
        self.logger.info(
            f"Scan efficiency: {summary['scan_efficiency']} "
            f"({summary['scanned_files']}/{summary['total_files']} files)"
        )
        if summary['ignored_directories']:
            self.logger.debug(f"Ignored directories: {', '.join(summary['ignored_directories'][:5])}")
            if len(summary['ignored_directories']) > 5:
                self.logger.debug(f"... and {len(summary['ignored_directories']) - 5} more")