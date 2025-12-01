"""Source code analysis service."""

import logging
from pathlib import Path
from typing import List

from models import Finding

logger = logging.getLogger(__name__)


class SourceCodeService:
    """Handles Python source code analysis."""

    EXCLUDE_PATTERNS = [
        'test_', 'tests/', '__pycache__/',
        'venv/', '.venv/', 'node_modules/'
    ]

    def __init__(self, code_analyzer):
        self.code_analyzer = code_analyzer

    def analyze_source_files(self, repo: Path) -> List[Finding]:
        """Analyze all Python source files in repository."""
        findings = []
        python_files = list(repo.glob('**/*.py'))

        for py_file in python_files:
            if self._should_analyze(py_file):
                findings.extend(self.code_analyzer.analyze_python_file(py_file))

        return findings

    def _should_analyze(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        file_str = str(file_path)
        return not any(p in file_str for p in self.EXCLUDE_PATTERNS)
