"""Tests for ConfigFileService."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from analyzers.mcp.services.config_file_service import ConfigFileService


class MockConfigAnalyzer:
    """Mock config analyzer."""
    def __init__(self):
        self.analyze_mcp_config = MagicMock(return_value=[])


@pytest.fixture
def config_analyzer():
    return MockConfigAnalyzer()


@pytest.fixture
def config_service(config_analyzer):
    return ConfigFileService(config_analyzer)


class TestConfigFileService:
    """Tests for ConfigFileService."""

    def test_init(self, config_service, config_analyzer):
        """Test service initialization."""
        assert config_service.config_analyzer == config_analyzer

    def test_analyze_configs_empty_repo(self, config_service, tmp_path):
        """Test analyzing empty repository."""
        findings = config_service.analyze_configs(tmp_path)
        assert findings == []

    def test_analyze_configs_finds_mcp_json(self, config_service, config_analyzer, tmp_path):
        """Test finding mcp.json config."""
        config_file = tmp_path / "mcp.json"
        config_file.write_text('{"name": "test"}')

        config_analyzer.analyze_mcp_config.return_value = [MagicMock()]
        findings = config_service.analyze_configs(tmp_path)

        config_analyzer.analyze_mcp_config.assert_called_once()
        assert len(findings) == 1

    def test_analyze_configs_finds_mcp_yaml(self, config_service, config_analyzer, tmp_path):
        """Test finding mcp.yaml config."""
        config_file = tmp_path / "mcp.yaml"
        config_file.write_text('name: test')

        config_analyzer.analyze_mcp_config.return_value = [MagicMock()]
        findings = config_service.analyze_configs(tmp_path)

        config_analyzer.analyze_mcp_config.assert_called_once()
        assert len(findings) == 1

    def test_analyze_configs_handles_invalid_json(self, config_service, tmp_path):
        """Test handling invalid JSON gracefully."""
        config_file = tmp_path / "mcp.json"
        config_file.write_text('invalid json{')

        findings = config_service.analyze_configs(tmp_path)
        assert findings == []

    def test_parse_config_json(self, config_service, tmp_path):
        """Test parsing JSON config."""
        config_file = tmp_path / "test.json"
        config_file.write_text('{"key": "value"}')

        result = config_service._parse_config(config_file, '{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_config_yaml(self, config_service, tmp_path):
        """Test parsing YAML config."""
        config_file = tmp_path / "test.yaml"
        config_file.write_text('key: value')

        result = config_service._parse_config(config_file, 'key: value')
        assert result == {"key": "value"}

    def test_parse_config_unknown_extension(self, config_service, tmp_path):
        """Test parsing unknown extension returns None."""
        config_file = tmp_path / "test.txt"
        result = config_service._parse_config(config_file, 'content')
        assert result is None
