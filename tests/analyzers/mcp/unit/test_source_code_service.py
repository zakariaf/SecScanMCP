"""Tests for SourceCodeService."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from analyzers.mcp.services.source_code_service import SourceCodeService


class MockCodeAnalyzer:
    """Mock code analyzer."""
    def __init__(self):
        self.analyze_python_file = MagicMock(return_value=[])


@pytest.fixture
def code_analyzer():
    return MockCodeAnalyzer()


@pytest.fixture
def source_service(code_analyzer):
    return SourceCodeService(code_analyzer)


class TestSourceCodeService:
    """Tests for SourceCodeService."""

    def test_init(self, source_service, code_analyzer):
        """Test service initialization."""
        assert source_service.code_analyzer == code_analyzer

    def test_analyze_source_files_empty_repo(self, source_service, tmp_path):
        """Test analyzing empty repository."""
        findings = source_service.analyze_source_files(tmp_path)
        assert findings == []

    def test_analyze_source_files_finds_python(self, source_service, code_analyzer, tmp_path):
        """Test finding Python files."""
        # Create a subdir to avoid test_ in pytest temp path
        project_dir = tmp_path / "project"
        project_dir.mkdir()
        py_file = project_dir / "main.py"
        py_file.write_text('print("hello")')

        code_analyzer.analyze_python_file.return_value = [MagicMock()]
        findings = source_service.analyze_source_files(project_dir)

        assert len(findings) == 1
        code_analyzer.analyze_python_file.assert_called_once()

    def test_analyze_source_files_excludes_tests(self, source_service, code_analyzer, tmp_path):
        """Test excluding test files."""
        test_file = tmp_path / "test_main.py"
        test_file.write_text('def test_foo(): pass')

        findings = source_service.analyze_source_files(tmp_path)

        assert findings == []
        code_analyzer.analyze_python_file.assert_not_called()

    def test_analyze_source_files_excludes_venv(self, source_service, code_analyzer, tmp_path):
        """Test excluding venv directory."""
        venv_dir = tmp_path / "venv"
        venv_dir.mkdir()
        py_file = venv_dir / "script.py"
        py_file.write_text('print("venv")')

        findings = source_service.analyze_source_files(tmp_path)

        assert findings == []
        code_analyzer.analyze_python_file.assert_not_called()

    def test_should_analyze_regular_file(self, source_service, tmp_path):
        """Test should_analyze returns True for regular files."""
        py_file = tmp_path / "app.py"
        py_file.touch()
        assert source_service._should_analyze(py_file, tmp_path) is True

    def test_should_analyze_excludes_pycache(self, source_service, tmp_path):
        """Test should_analyze excludes __pycache__."""
        pycache_dir = tmp_path / "__pycache__"
        pycache_dir.mkdir()
        pycache_file = pycache_dir / "module.pyc"
        pycache_file.touch()
        assert source_service._should_analyze(pycache_file, tmp_path) is False

    def test_should_analyze_excludes_node_modules(self, source_service, tmp_path):
        """Test should_analyze excludes node_modules."""
        node_dir = tmp_path / "node_modules" / "package"
        node_dir.mkdir(parents=True)
        node_file = node_dir / "index.py"
        node_file.touch()
        assert source_service._should_analyze(node_file, tmp_path) is False

    def test_should_analyze_excludes_test_files(self, source_service, tmp_path):
        """Test should_analyze excludes test_ prefixed files."""
        test_file = tmp_path / "test_something.py"
        test_file.touch()
        assert source_service._should_analyze(test_file, tmp_path) is False
