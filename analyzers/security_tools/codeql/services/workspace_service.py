"""CodeQL workspace setup service."""

import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class WorkspaceService:
    """Manages CodeQL workspace setup."""

    def __init__(self, cli_service, pack_service):
        self.cli_service = cli_service
        self.pack_service = pack_service
        self.search_path = ""

    async def setup(self, work: Path, languages: List[str]):
        """Setup CodeQL workspace with packs and search paths."""
        local_packs_root = work / "local-packs"
        local_packs_root.mkdir(parents=True, exist_ok=True)
        await self.pack_service.synthesize_language_packs(local_packs_root)
        codeql_pkg_cache = Path.home() / ".codeql" / "packages"
        self.search_path = f"{local_packs_root}:{codeql_pkg_cache}"
        await self._download_official_packs(languages)

    async def _download_official_packs(self, languages: List[str]):
        """Pre-download official CodeQL packs."""
        to_download = []
        for lang in languages:
            pack_name = self.pack_service.get_official_pack_for_download(lang)
            if pack_name:
                to_download.append(pack_name)

        if to_download:
            unique_packs = sorted(set(to_download))
            logger.info(f"Pre-downloading CodeQL packs: {unique_packs}")
            try:
                await self.cli_service.run_command(
                    ["pack", "download"] + unique_packs, timeout=300
                )
            except Exception as e:
                logger.warning(f"Pack download failed: {e}")
