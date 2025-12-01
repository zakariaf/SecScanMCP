"""CodeQL query execution service."""

import logging
from pathlib import Path
from typing import List

logger = logging.getLogger(__name__)


class QueryService:
    """Manages CodeQL query execution."""

    def __init__(self, cli_service, pack_service):
        self.cli_service = cli_service
        self.pack_service = pack_service
        self.search_path = ""

    def set_search_path(self, path: str):
        """Set the search path for queries."""
        self.search_path = path

    def get_query_specs(self, language: str) -> List[str]:
        """Get query specifications for language."""
        specs: List[str] = []
        official = self.pack_service.get_official_suite_for_language(language)
        if official:
            specs.append(official)
        local = self.pack_service.get_local_suite_for_language(language)
        if local and local.exists():
            specs.append(str(local))
        logger.info(f"Using query specs for {language}: {specs}")
        return specs

    async def preview_queries(self, query_specs: List[str], language: str):
        """Preview queries that will be executed."""
        try:
            result = await self.cli_service.run_command(
                ["resolve", "queries"] + query_specs +
                [f"--search-path={self.search_path}"],
                timeout=120
            )
            if result.returncode == 0:
                lines = [ln for ln in result.stdout.splitlines() if ln.strip()]
                logger.info(f"Resolved {len(lines)} CodeQL queries for {language}")
                for qpath in lines[:10]:
                    logger.info(f"Resolved query: {qpath}")
                if len(lines) > 10:
                    logger.info(f"... and {len(lines) - 10} more")
            else:
                logger.warning(f"Could not resolve queries: {result.stderr}")
        except Exception as e:
            logger.warning(f"Query resolution failed: {e}")

    async def run_analysis(
        self, db_path: Path, sarif_path: Path, query_specs: List[str]
    ):
        """Run CodeQL analysis and generate SARIF results."""
        analyze_cmd = [
            "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--sarif-add-query-help",
            "--threads=0",
            "--ram=2048",
            f"--search-path={self.search_path}",
        ] + query_specs

        logger.info(f"Running CodeQL analysis with {len(query_specs)} query specs")
        result = await self.cli_service.run_command(analyze_cmd, timeout=1800)
        if result.returncode != 0:
            raise RuntimeError(f"Analysis failed: {result.stderr or result.stdout}")
