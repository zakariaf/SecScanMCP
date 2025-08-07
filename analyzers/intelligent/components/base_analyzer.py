"""Base analyzer interface."""

from abc import ABC, abstractmethod
from typing import Tuple, Dict, Any
from ..models.analysis_models import CodeContext


class BaseAnalyzer(ABC):
    """Base interface for analysis components."""
    
    @abstractmethod
    async def analyze(self, context: CodeContext) -> Tuple[float, Dict[str, Any]]:
        """
        Analyze code context and return score and evidence.
        
        Returns:
            Tuple of (legitimacy_score, evidence_dict)
        """
        pass