"""Payload categories."""

from .prompt_injection import PromptInjectionPayloads
from .command_injection import CommandInjectionPayloads
from .path_traversal import PathTraversalPayloads

__all__ = [
    'PromptInjectionPayloads',
    'CommandInjectionPayloads', 
    'PathTraversalPayloads'
]