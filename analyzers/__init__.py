"""
Security analyzers for various vulnerability types
"""

from .base import BaseAnalyzer
from .bandit import BanditAnalyzer
from .opengrep import OpenGrepAnalyzer  # Updated to use refactored module
from .trivy import TrivyAnalyzer
from .grype import GrypeAnalyzer
from .syft import SyftAnalyzer
from .trufflehog import TruffleHogAnalyzer
from .mcp import MCPSpecificAnalyzer
from .dynamic import DynamicAnalyzer  # Updated to use refactored module
# TrafficAnalyzer is a container utility, not a BaseAnalyzer - import directly if needed
from .traffic import TrafficAnalyzer

from .security_tools.clamav import ClamAVAnalyzer
from .security_tools.yara import YARAAnalyzer
from .security_tools.codeql import CodeQLAnalyzer

__all__ = [
    'BaseAnalyzer',
    'BanditAnalyzer',
    'OpenGrepAnalyzer',  # Replaces SemgrepAnalyzer
    'TrivyAnalyzer',
    'GrypeAnalyzer',
    'SyftAnalyzer',
    'TruffleHogAnalyzer',
    'MCPSpecificAnalyzer',
    'DynamicAnalyzer',
    'ClamAVAnalyzer',
    'YARAAnalyzer',
    'CodeQLAnalyzer'
]