"""Tests for WorkspaceService."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from analyzers.security_tools.codeql.services.workspace_service import WorkspaceService


class MockCLIService:
    """Mock CLI service."""
    def __init__(self):
        self.run_command = AsyncMock(return_value=MagicMock(returncode=0))


class MockPackService:
    """Mock pack service."""
    def __init__(self):
        self.synthesize_language_packs = AsyncMock()
        self.packs_for_download = {'python': 'codeql/python-queries'}

    def get_official_pack_for_download(self, lang):
        return self.packs_for_download.get(lang)


@pytest.fixture
def cli_service():
    return MockCLIService()


@pytest.fixture
def pack_service():
    return MockPackService()


@pytest.fixture
def workspace_service(cli_service, pack_service):
    return WorkspaceService(cli_service, pack_service)


class TestWorkspaceService:
    """Tests for WorkspaceService."""

    @pytest.mark.asyncio
    async def test_setup_creates_local_packs_dir(self, workspace_service, tmp_path):
        """Test that setup creates local-packs directory."""
        await workspace_service.setup(tmp_path, ['python'])
        assert (tmp_path / 'local-packs').exists()

    @pytest.mark.asyncio
    async def test_setup_calls_synthesize_packs(self, workspace_service, pack_service, tmp_path):
        """Test that setup calls synthesize_language_packs."""
        await workspace_service.setup(tmp_path, ['python'])
        pack_service.synthesize_language_packs.assert_called_once()

    @pytest.mark.asyncio
    async def test_setup_sets_search_path(self, workspace_service, tmp_path):
        """Test that setup sets the search path."""
        await workspace_service.setup(tmp_path, ['python'])
        assert workspace_service.search_path != ""
        assert 'local-packs' in workspace_service.search_path

    @pytest.mark.asyncio
    async def test_setup_downloads_packs(self, workspace_service, cli_service, tmp_path):
        """Test that setup downloads official packs."""
        await workspace_service.setup(tmp_path, ['python'])
        cli_service.run_command.assert_called()
        call_args = cli_service.run_command.call_args[0][0]
        assert 'pack' in call_args
        assert 'download' in call_args

    @pytest.mark.asyncio
    async def test_setup_handles_download_failure(self, workspace_service, cli_service, tmp_path):
        """Test that setup handles download failure gracefully."""
        cli_service.run_command.side_effect = Exception("Download failed")
        # Should not raise
        await workspace_service.setup(tmp_path, ['python'])

    @pytest.mark.asyncio
    async def test_setup_multiple_languages(self, workspace_service, cli_service, tmp_path):
        """Test setup with multiple languages."""
        workspace_service.pack_service.packs_for_download = {
            'python': 'codeql/python-queries',
            'javascript': 'codeql/javascript-queries'
        }
        await workspace_service.setup(tmp_path, ['python', 'javascript'])
        # Should download both packs
        call_args = cli_service.run_command.call_args[0][0]
        assert len([a for a in call_args if 'codeql/' in a]) == 2

    @pytest.mark.asyncio
    async def test_setup_no_packs_to_download(self, workspace_service, cli_service, tmp_path):
        """Test setup when no packs need downloading."""
        workspace_service.pack_service.packs_for_download = {}
        await workspace_service.setup(tmp_path, ['unknown'])
        # run_command should not be called for pack download
        # (only synthesize_language_packs should be called)
