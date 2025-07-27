"""
Base analyzer class that all security analyzers inherit from
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any
import logging

from models import Finding

logger = logging.getLogger(__name__)


class BaseAnalyzer(ABC):
    """Base class for all security analyzers"""

    def __init__(self):
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(self.name)

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
        kwargs['tool'] = self.name.replace('Analyzer', '').lower()
        return Finding(**kwargs)