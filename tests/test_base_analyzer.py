"""Tests for BaseAnalyzer helper methods."""
from pathlib import Path
import os
import tempfile
import pytest

from analyzers.base import BaseAnalyzer
from models import SeverityLevel, VulnerabilityType

class DummyAnalyzer(BaseAnalyzer):
    async def analyze(self, repo_path: str, project_info):  # pragma: no cover - not needed here
        return []


def test_create_finding_sets_tool():
    a = DummyAnalyzer()
    f = a.create_finding(
        vulnerability_type=VulnerabilityType.GENERIC,
        severity=SeverityLevel.LOW,
        title="t",
        description="d",
        location="file.py:1",
        recommendation="r",
    )
    assert f.tool == 'dummy'
    assert f.vulnerability_type == VulnerabilityType.GENERIC


def test_get_filtered_files_and_ignores():
    a = DummyAnalyzer()
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        # Ignored directory
        (repo / 'node_modules').mkdir()
        (repo / 'node_modules' / 'lib.js').write_text('console.log(1)')
        # Scannable file
        (repo / 'main.py').write_text('print(1)')
        # Large file (>10MB) should be ignored
        big = repo / 'big.txt'
        big.write_bytes(b'0' * (10 * 1024 * 1024 + 1))

        files = a.get_filtered_files(str(repo))
        names = {Path(f).name for f in files}
        assert 'main.py' in names
        assert 'lib.js' not in names  # ignored due to node_modules
        assert 'big.txt' not in names


def test_include_extensions_filter():
    a = DummyAnalyzer()
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / 'a.py').write_text('print()')
        (repo / 'b.js').write_text('console.log()')
        only_py = a.get_filtered_files(str(repo), include_extensions={'.py'})
        assert any(p.endswith('a.py') for p in only_py)
        assert not any(p.endswith('b.js') for p in only_py)


def test_create_ignore_file():
    a = DummyAnalyzer()
    with tempfile.TemporaryDirectory() as d:
        path = a.create_ignore_file(d)
        content = Path(path).read_text().splitlines()
        # spot check a couple patterns
        assert any('node_modules/' in line for line in content)
        assert any('*.pyc' in line for line in content)
