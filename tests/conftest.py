"""Shared pytest fixtures for analyzer tests."""
import os
import tempfile
from pathlib import Path
import pytest

@pytest.fixture
def temp_repo():
    """Create a temporary repository structure we can populate with test files."""
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        # common subdirs
        (repo / 'src').mkdir()
        (repo / 'node_modules').mkdir()
        (repo / '.git').mkdir()
        yield repo

@pytest.fixture
def mock_project_info():
    return {
        'type': 'python',
        'language': 'python',
        'is_mcp': True,
        'mcp_config': {}
    }
