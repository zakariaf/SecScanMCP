"""Tests for DatabaseService."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from analyzers.security_tools.codeql.services.database_service import DatabaseService


class MockCLIService:
    """Mock CLI service."""
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.run_command = AsyncMock(return_value=MagicMock(
            returncode=returncode, stderr=stderr, stdout=stdout
        ))


@pytest.fixture
def cli_service():
    return MockCLIService()


@pytest.fixture
def database_service(cli_service):
    return DatabaseService(cli_service)


class TestDatabaseService:
    """Tests for DatabaseService."""

    def test_set_options(self, database_service):
        """Test setting options."""
        options = {'codeql_build_command': 'custom build'}
        database_service.set_options(options)
        assert database_service.scan_options == options

    def test_set_options_none(self, database_service):
        """Test setting options with None."""
        database_service.set_options(None)
        assert database_service.scan_options == {}

    @pytest.mark.asyncio
    async def test_create_database_basic(self, database_service, cli_service, tmp_path):
        """Test basic database creation."""
        repo = tmp_path / "repo"
        repo.mkdir()
        db_path = tmp_path / "db"

        await database_service.create_database(repo, db_path, "python")

        cli_service.run_command.assert_called_once()
        call_args = cli_service.run_command.call_args[0][0]
        assert "database" in call_args
        assert "create" in call_args
        assert "--language=python" in call_args

    @pytest.mark.asyncio
    async def test_create_database_go_includes_build_command(self, database_service, cli_service, tmp_path):
        """Test Go database creation includes build command."""
        repo = tmp_path / "repo"
        repo.mkdir()
        db_path = tmp_path / "db"

        await database_service.create_database(repo, db_path, "go")

        call_args = cli_service.run_command.call_args[0][0]
        assert "--command" in call_args

    @pytest.mark.asyncio
    async def test_create_database_go_custom_build(self, database_service, cli_service, tmp_path):
        """Test Go with custom build command."""
        database_service.set_options({'codeql_build_command': 'make build'})
        repo = tmp_path / "repo"
        repo.mkdir()
        db_path = tmp_path / "db"

        await database_service.create_database(repo, db_path, "go")

        call_args = cli_service.run_command.call_args[0][0]
        assert "--command" in call_args
        cmd_index = call_args.index("--command")
        assert call_args[cmd_index + 1] == 'make build'

    @pytest.mark.asyncio
    async def test_create_database_failure(self, cli_service, tmp_path):
        """Test database creation failure."""
        cli_service.run_command.return_value = MagicMock(
            returncode=1, stderr="Error creating database", stdout=""
        )
        database_service = DatabaseService(cli_service)

        repo = tmp_path / "repo"
        repo.mkdir()
        db_path = tmp_path / "db"

        with pytest.raises(RuntimeError) as exc_info:
            await database_service.create_database(repo, db_path, "python")
        assert "Database creation failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_create_database_includes_overwrite(self, database_service, cli_service, tmp_path):
        """Test that --overwrite flag is included."""
        repo = tmp_path / "repo"
        repo.mkdir()
        db_path = tmp_path / "db"

        await database_service.create_database(repo, db_path, "python")

        call_args = cli_service.run_command.call_args[0][0]
        assert "--overwrite" in call_args

    def test_get_go_build_command_default(self, database_service, tmp_path):
        """Test default Go build command."""
        repo = tmp_path / "repo"
        cmd = database_service._get_go_build_command(repo)
        assert "go mod download" in cmd
        assert "go build" in cmd

    def test_get_go_build_command_custom(self, database_service, tmp_path):
        """Test custom Go build command."""
        database_service.set_options({'codeql_build_command': 'custom'})
        repo = tmp_path / "repo"
        cmd = database_service._get_go_build_command(repo)
        assert cmd == 'custom'
