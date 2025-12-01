"""Utility functions for capability abuse detection."""

from pathlib import Path


EXCLUDE_PATTERNS = [
    'test_', 'tests/', '__pycache__/',
    'node_modules/', '.git/', 'venv/'
]


def should_analyze_file(file_path: Path) -> bool:
    """Check if file should be analyzed."""
    file_str = str(file_path)
    return not any(pattern in file_str for pattern in EXCLUDE_PATTERNS)


def extract_context(content: str, position: int, context_chars: int = 150) -> str:
    """Extract context around match position."""
    start = max(0, position - context_chars // 2)
    end = min(len(content), position + context_chars // 2)
    return content[start:end].strip()
