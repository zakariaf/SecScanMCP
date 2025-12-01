"""Source code analysis service."""

import logging
from pathlib import Path
from typing import List

from models import Finding

logger = logging.getLogger(__name__)


class SourceCodeService:
    """Handles Python source code analysis."""

    EXCLUDE_DIRS = {'tests', 'test', '__pycache__', 'venv', '.venv', 'node_modules'}
    EXCLUDE_PREFIXES = ('test_',)

    def __init__(self, code_analyzer):
        self.code_analyzer = code_analyzer

    def analyze_source_files(self, repo: Path) -> List[Finding]:
        """Analyze all Python source files in repository."""
        findings = []
        python_files = list(repo.glob('**/*.py'))

        for py_file in python_files:
            if self._should_analyze(py_file, repo):
                findings.extend(self.code_analyzer.analyze_python_file(py_file))

        return findings

    def _should_analyze(self, file_path: Path, repo: Path) -> bool:
        """Check if file should be analyzed based on relative path."""
        try:
            rel_path = file_path.relative_to(repo)
            parts = rel_path.parts
            if any(part in self.EXCLUDE_DIRS for part in parts[:-1]):
                return False
            if any(parts[-1].startswith(p) for p in self.EXCLUDE_PREFIXES):
                return False
            return True
        except ValueError:
            return False
