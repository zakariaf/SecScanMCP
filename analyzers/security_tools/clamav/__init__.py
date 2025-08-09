"""
ClamAV Malware Detection Module

Clean modular architecture for ClamAV-based malware scanning
Following Sandi Metz best practices and clean architecture principles
"""

# Public exports - main interface only
from .main_analyzer import ClamAVAnalyzer

__all__ = ['ClamAVAnalyzer']