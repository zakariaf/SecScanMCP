"""
CodeQL Semantic Analysis Module

Clean modular architecture for CodeQL-based semantic code analysis
Following Sandi Metz best practices and clean architecture principles
"""

# Public exports - main interface only
from .main_analyzer import CodeQLAnalyzer

__all__ = ['CodeQLAnalyzer']