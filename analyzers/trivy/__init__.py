"""
Trivy Vulnerability Scanner Module

Clean modular architecture for Trivy-based comprehensive security scanning
Following Sandi Metz best practices and clean architecture principles
"""

# Public exports - main interface only
from .main_analyzer import TrivyAnalyzer

__all__ = ['TrivyAnalyzer']