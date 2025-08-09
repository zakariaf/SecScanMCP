"""MCP analyzer detectors."""

from .injection_detector import InjectionDetector
from .permission_detector import PermissionDetector

__all__ = ['InjectionDetector', 'PermissionDetector']