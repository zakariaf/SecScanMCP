"""Utility functions for output poisoning analysis."""

import re
from pathlib import Path
from typing import List, Dict, Any

from .patterns import EXCLUDE_PATTERNS, MCP_TOOL_INDICATORS


def should_analyze_file(file_path: Path) -> bool:
    """Check if file should be analyzed."""
    file_str = str(file_path)
    return not any(pattern in file_str for pattern in EXCLUDE_PATTERNS)


def extract_context(content: str, position: int, context_chars: int = 150) -> str:
    """Extract context around match position."""
    start = max(0, position - context_chars // 2)
    end = min(len(content), position + context_chars // 2)
    return content[start:end].strip()


def is_in_output_context(line: str, position: int) -> bool:
    """Check if position is in an output context (string, return, etc.)."""
    before_pos = line[:position]
    single_quotes = before_pos.count("'") - before_pos.count("\\'")
    double_quotes = before_pos.count('"') - before_pos.count('\\"')
    in_string = (single_quotes % 2 == 1) or (double_quotes % 2 == 1)
    has_return = 'return' in line.lower()
    return in_string or has_return


def is_mcp_tool_file(content: str) -> bool:
    """Check if file contains MCP tool definitions."""
    return any(indicator in content for indicator in MCP_TOOL_INDICATORS)


def check_patterns_in_content(
    content: str,
    patterns: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Check content for matching patterns, return matches with info."""
    matches = []
    for pattern_info in patterns:
        for match in re.finditer(pattern_info['pattern'], content, re.MULTILINE):
            matches.append({
                'match': match,
                'pattern_info': pattern_info,
                'context': extract_context(content, match.start())
            })
    return matches
