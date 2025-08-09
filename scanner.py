"""
Core security scanner - backward compatibility wrapper.

This file now imports from the modular scanner package which follows
clean architecture principles similar to analyzers/intelligent/.
"""

from scanner import SecurityScanner

# Re-export for backward compatibility
__all__ = ['SecurityScanner']