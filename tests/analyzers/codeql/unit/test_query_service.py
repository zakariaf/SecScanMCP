"""Tests for QueryService."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from analyzers.security_tools.codeql.services.query_service import QueryService


class MockCLIService:
    """Mock CLI service."""
    def __init__(self, returncode=0, stderr="", stdout=""):
        self.run_command = AsyncMock(return_value=MagicMock(
            returncode=returncode, stderr=stderr, stdout=stdout
        ))


class MockPackService:
    """Mock pack service."""
    def __init__(self):
        self.official_suites = {'python': 'codeql/python-queries:codeql-suites/python-security'}
        self.local_suites = {}

    def get_official_suite_for_language(self, lang):
        return self.official_suites.get(lang)

    def get_local_suite_for_language(self, lang):
        path = self.local_suites.get(lang)
        if path:
            return Path(path)
        return None


@pytest.fixture
def cli_service():
    return MockCLIService()


@pytest.fixture
def pack_service():
    return MockPackService()


@pytest.fixture
def query_service(cli_service, pack_service):
    service = QueryService(cli_service, pack_service)
    service.set_search_path("/test/path")
    return service


class TestQueryService:
    """Tests for QueryService."""

    def test_set_search_path(self, cli_service, pack_service):
        """Test setting search path."""
        service = QueryService(cli_service, pack_service)
        service.set_search_path("/custom/path")
        assert service.search_path == "/custom/path"

    def test_get_query_specs_with_official(self, query_service):
        """Test getting query specs with official suite."""
        specs = query_service.get_query_specs('python')
        assert len(specs) >= 1
        assert 'codeql/python-queries' in specs[0]

    def test_get_query_specs_no_suite(self, query_service):
        """Test getting query specs for unknown language."""
        specs = query_service.get_query_specs('unknown')
        assert specs == []

    def test_get_query_specs_with_local(self, query_service, tmp_path):
        """Test getting query specs with local suite."""
        local_suite = tmp_path / "local.qls"
        local_suite.touch()
        query_service.pack_service.local_suites = {'python': str(local_suite)}

        specs = query_service.get_query_specs('python')
        assert len(specs) == 2
        assert str(local_suite) in specs

    @pytest.mark.asyncio
    async def test_preview_queries_success(self, query_service, cli_service):
        """Test preview queries with success."""
        cli_service.run_command.return_value = MagicMock(
            returncode=0,
            stdout="query1.ql\nquery2.ql\nquery3.ql",
            stderr=""
        )

        await query_service.preview_queries(['spec1'], 'python')

        cli_service.run_command.assert_called_once()
        call_args = cli_service.run_command.call_args[0][0]
        assert "resolve" in call_args
        assert "queries" in call_args

    @pytest.mark.asyncio
    async def test_preview_queries_failure(self, query_service, cli_service):
        """Test preview queries handles failure gracefully."""
        cli_service.run_command.return_value = MagicMock(
            returncode=1, stdout="", stderr="Error"
        )

        # Should not raise
        await query_service.preview_queries(['spec1'], 'python')

    @pytest.mark.asyncio
    async def test_preview_queries_exception(self, query_service, cli_service):
        """Test preview queries handles exception gracefully."""
        cli_service.run_command.side_effect = Exception("Network error")

        # Should not raise
        await query_service.preview_queries(['spec1'], 'python')

    @pytest.mark.asyncio
    async def test_run_analysis_success(self, query_service, cli_service, tmp_path):
        """Test run analysis with success."""
        db_path = tmp_path / "db"
        sarif_path = tmp_path / "results.sarif"

        await query_service.run_analysis(db_path, sarif_path, ['spec1', 'spec2'])

        cli_service.run_command.assert_called_once()
        call_args = cli_service.run_command.call_args[0][0]
        assert "database" in call_args
        assert "analyze" in call_args
        assert "--format=sarif-latest" in call_args

    @pytest.mark.asyncio
    async def test_run_analysis_failure(self, query_service, cli_service, tmp_path):
        """Test run analysis failure."""
        cli_service.run_command.return_value = MagicMock(
            returncode=1, stderr="Analysis failed", stdout=""
        )

        db_path = tmp_path / "db"
        sarif_path = tmp_path / "results.sarif"

        with pytest.raises(RuntimeError) as exc_info:
            await query_service.run_analysis(db_path, sarif_path, ['spec1'])
        assert "Analysis failed" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_run_analysis_includes_search_path(self, query_service, cli_service, tmp_path):
        """Test that analysis includes search path."""
        db_path = tmp_path / "db"
        sarif_path = tmp_path / "results.sarif"

        await query_service.run_analysis(db_path, sarif_path, ['spec1'])

        call_args = cli_service.run_command.call_args[0][0]
        search_path_arg = [a for a in call_args if '--search-path=' in a]
        assert len(search_path_arg) == 1
        assert '/test/path' in search_path_arg[0]

    @pytest.mark.asyncio
    async def test_run_analysis_timeout(self, query_service, cli_service, tmp_path):
        """Test that analysis uses correct timeout."""
        db_path = tmp_path / "db"
        sarif_path = tmp_path / "results.sarif"

        await query_service.run_analysis(db_path, sarif_path, ['spec1'])

        kwargs = cli_service.run_command.call_args[1]
        assert kwargs.get('timeout') == 1800
