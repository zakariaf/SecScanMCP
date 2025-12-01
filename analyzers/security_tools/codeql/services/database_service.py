"""CodeQL database creation service."""

import logging
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)


class DatabaseService:
    """Manages CodeQL database creation."""

    def __init__(self, cli_service):
        self.cli_service = cli_service
        self.scan_options: Dict[str, Any] = {}

    def set_options(self, options: Dict[str, Any]):
        """Set scan options."""
        self.scan_options = options or {}

    async def create_database(self, repo: Path, db_path: Path, language: str):
        """Create CodeQL database for language."""
        create_cmd = [
            "database", "create", str(db_path),
            f"--language={language}",
            f"--source-root={repo}",
            "--overwrite",
            "--log-to-stderr",
        ]

        if language == "go":
            build_cmd = self._get_go_build_command(repo)
            create_cmd.extend(["--command", build_cmd])

        result = await self.cli_service.run_command(create_cmd, timeout=600)
        if result.returncode != 0:
            msg = (result.stderr or "").strip() or (result.stdout or "").strip()
            raise RuntimeError(f"Database creation failed: {msg}")

    def _get_go_build_command(self, repo: Path) -> str:
        """Get Go build command for database creation."""
        build_cmd = self.scan_options.get("codeql_build_command")
        if not build_cmd:
            build_cmd = (
                f"sh -c \"cd '{repo}'; "
                "export GOPROXY='https://proxy.golang.org,direct' "
                "GOSUMDB='sum.golang.org' CGO_ENABLED=0; "
                "go mod download || true; go build ./...\""
            )
        return build_cmd
