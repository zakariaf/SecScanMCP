"""
Grype Analyzer Module

Vulnerability scanner for container images and filesystems by Anchore
"""

from .main_analyzer import GrypeAnalyzer

__all__ = ['GrypeAnalyzer']