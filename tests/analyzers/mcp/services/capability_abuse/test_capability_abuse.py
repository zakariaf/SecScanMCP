"""Tests for capability abuse detection services."""

import pytest
import tempfile
from pathlib import Path

from analyzers.mcp.services.capability_abuse import (
    CapabilityPatterns,
    ConfigCapabilityChecker,
    CodeCapabilityChecker,
    AccessPatternChecker,
    ToolChecker,
)
from analyzers.mcp.services.capability_abuse.utils import should_analyze_file, extract_context


class TestCapabilityPatterns:
    """Tests for CapabilityPatterns."""

    def test_capability_patterns_exist(self):
        """Test capability patterns are defined."""
        assert len(CapabilityPatterns.CAPABILITY_PATTERNS) > 0

    def test_abuse_indicators_exist(self):
        """Test abuse indicators are defined."""
        assert len(CapabilityPatterns.ABUSE_INDICATORS) > 0

    def test_dangerous_operations_exist(self):
        """Test dangerous operations are defined."""
        assert 'eval' in CapabilityPatterns.DANGEROUS_OPERATIONS


class TestUtils:
    """Tests for utility functions."""

    def test_should_analyze_regular_file(self):
        """Test regular file should be analyzed."""
        assert should_analyze_file(Path('/project/src/main.py'))

    def test_should_not_analyze_test_file(self):
        """Test test files should not be analyzed."""
        assert not should_analyze_file(Path('/project/tests/test_main.py'))

    def test_should_not_analyze_pycache(self):
        """Test pycache files should not be analyzed."""
        assert not should_analyze_file(Path('/project/__pycache__/main.cpython-39.pyc'))

    def test_extract_context(self):
        """Test context extraction."""
        content = "x" * 100 + "MATCH" + "y" * 100
        context = extract_context(content, 100)
        assert "MATCH" in context


class TestConfigCapabilityChecker:
    """Tests for ConfigCapabilityChecker."""

    @pytest.fixture
    def checker(self):
        return ConfigCapabilityChecker()

    def test_check_empty_repo(self, checker):
        """Test checking empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = checker.check(Path(tmpdir))
            assert findings == []

    def test_check_config_with_admin_capability(self, checker):
        """Test detecting admin capability exposure."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / 'mcp.json'
            config.write_text("capability = 'admin_role'")
            findings = checker.check(Path(tmpdir))
            assert len(findings) > 0
            assert any('Admin Capability' in f.title for f in findings)

    def test_check_config_with_wildcard_permissions(self, checker):
        """Test detecting wildcard permissions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / 'mcp.json'
            config.write_text('{"tools": [{"name": "test", "permissions": ["all"]}]}')
            findings = checker.check(Path(tmpdir))
            assert any('Overly Broad' in f.title for f in findings)


class TestCodeCapabilityChecker:
    """Tests for CodeCapabilityChecker."""

    @pytest.fixture
    def checker(self):
        return CodeCapabilityChecker()

    def test_check_empty_repo(self, checker):
        """Test checking empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = checker.check(Path(tmpdir))
            assert findings == []

    def test_check_code_with_capability_exposure(self, checker):
        """Test detecting capability exposure in code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'src'
            src.mkdir()
            code = src / 'main.py'
            code.write_text('capability = "admin"')
            findings = checker.check(Path(tmpdir))
            assert len(findings) > 0


class TestAccessPatternChecker:
    """Tests for AccessPatternChecker."""

    @pytest.fixture
    def checker(self):
        return AccessPatternChecker()

    def test_check_empty_repo(self, checker):
        """Test checking empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = checker.check(Path(tmpdir))
            assert findings == []

    def test_check_auth_bypass(self, checker):
        """Test detecting authentication bypass."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'src'
            src.mkdir()
            code = src / 'main.py'
            code.write_text('if auth == false: pass')
            findings = checker.check(Path(tmpdir))
            assert len(findings) > 0
            assert any('Authentication Bypass' in f.title for f in findings)


class TestToolChecker:
    """Tests for ToolChecker."""

    @pytest.fixture
    def checker(self):
        return ToolChecker()

    def test_check_implementations_empty_repo(self, checker):
        """Test checking empty repository."""
        with tempfile.TemporaryDirectory() as tmpdir:
            findings = checker.check_implementations(Path(tmpdir))
            assert findings == []

    def test_check_tool_with_file_system_abuse(self, checker):
        """Test detecting file system abuse in tools."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'src'
            src.mkdir()
            tool = src / 'tool.py'
            tool.write_text('@mcp.tool("test")\ndef test(): delete all *')
            findings = checker.check_implementations(Path(tmpdir))
            assert len(findings) > 0

    def test_check_tool_shadowing(self, checker):
        """Test detecting tool name collisions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'src'
            src.mkdir()
            tool1 = src / 'tool1.py'
            tool1.write_text('@mcp.tool("duplicate")\ndef f1(): pass')
            tool2 = src / 'tool2.py'
            tool2.write_text('@mcp.tool("duplicate")\ndef f2(): pass')
            findings = checker.check_shadowing(Path(tmpdir))
            assert len(findings) > 0
            assert any('Collision' in f.title for f in findings)

    def test_check_resource_patterns(self, checker):
        """Test detecting dangerous resource patterns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / 'src'
            src.mkdir()
            code = src / 'main.py'
            code.write_text('file: "../../../etc/passwd"')
            findings = checker.check_resource_patterns(Path(tmpdir))
            assert len(findings) > 0
