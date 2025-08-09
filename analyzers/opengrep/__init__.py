"""
OpenGrep Static Analysis Module

Clean modular architecture for OpenGrep pattern-based static analysis
Following Sandi Metz best practices and clean architecture principles
"""

# Public exports - main interface only
from .main_analyzer import OpenGrepAnalyzer

__all__ = ['OpenGrepAnalyzer']