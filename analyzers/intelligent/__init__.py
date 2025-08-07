"""
Intelligent Context-Aware Security Analysis Engine
==================================================

Modular ML-based security analysis system following Sandi Metz best practices:
- Small classes (≤100 lines)
- Short methods (≤10 lines)  
- Single responsibility principle
- Clear separation of concerns
"""

from .main_analyzer import IntelligentContextAnalyzer
from .models.analysis_models import CodeContext, LegitimacyAnalysis

__all__ = ['IntelligentContextAnalyzer', 'CodeContext', 'LegitimacyAnalysis']