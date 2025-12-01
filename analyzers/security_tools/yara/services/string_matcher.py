"""
YARA String Matcher Service

Extracts and parses matched strings from YARA matches
Handles both pre-4.3 and post-4.3 YARA formats
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Constants
MAX_MATCHES = 10
MAX_CONTENT_LENGTH = 100


class StringMatcherService:
    """Extracts matched strings from YARA matches"""

    def extract_matched_strings(self, match: Any, file_path: Path) -> List[Dict]:
        """Extract matched strings with line information"""
        matched_strings = []
        file_content = None

        for s in match.strings:
            if file_content is None and self._needs_file_content(s):
                file_content = self._load_file_content(file_path)

            string_info = self._parse_string_match(s, file_path, file_content)
            if string_info:
                matched_strings.append(string_info)

        return matched_strings[:MAX_MATCHES]

    def _needs_file_content(self, s: Any) -> bool:
        """Check if string match needs file content for line numbers"""
        if isinstance(s, tuple):
            return s[0] is not None  # pre-4.3: offset at index 0
        return bool(s.instances and s.instances[0].offset is not None)

    def _parse_string_match(self, s: Any, file_path: Path,
                           file_content: Optional[str]) -> Dict:
        """Parse a single string match"""
        offset, identifier, data = self._extract_match_data(s)
        line_number, line_content = self._get_line_info(offset, file_content)

        return {
            'offset': offset,
            'line': line_number,
            'line_content': line_content,
            'identifier': identifier,
            'content': data[:MAX_CONTENT_LENGTH] if data else ''
        }

    def _extract_match_data(self, s: Any) -> tuple:
        """Extract offset, identifier, and data from match"""
        if isinstance(s, tuple):
            return s  # pre-4.3: (offset, identifier, data)

        # post-4.3: yara.StringMatch
        identifier = s.identifier
        if s.instances:
            inst = s.instances[0]
            return inst.offset, identifier, inst.matched_data
        return None, identifier, None

    def _get_line_info(self, offset: Optional[int],
                      file_content: Optional[str]) -> tuple:
        """Get line number and content for offset"""
        if offset is None or file_content is None:
            return None, None

        try:
            line_number = file_content[:offset].count('\n') + 1
            lines = file_content.split('\n')

            if 0 < line_number <= len(lines):
                return line_number, lines[line_number - 1].strip()
        except Exception as e:
            logger.debug(f"Could not determine line info: {e}")

        return None, None

    def _load_file_content(self, file_path: Path) -> Optional[str]:
        """Load file content for line number calculation"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            return None
