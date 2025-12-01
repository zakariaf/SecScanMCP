"""Main CodeQL Semantic Analysis Analyzer."""

import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services import (
    CLIService, LanguageService, PackService, SarifService,
    WorkspaceService, DatabaseService, QueryService,
)

logger = logging.getLogger(__name__)


class CodeQLAnalyzer(BaseAnalyzer):
    """Clean orchestrator for CodeQL semantic code analysis."""

    def __init__(self):
        super().__init__()
        self._init_services()
        self.cli_service.discover_cli()
        self.cli_service.validate_cli()

    def _init_services(self):
        """Initialize all services."""
        self.cli_service = CLIService()
        self.language_service = LanguageService(self)
        self.pack_service = PackService(self.cli_service)
        self.sarif_service = SarifService(self)
        self.workspace_service = WorkspaceService(self.cli_service, self.pack_service)
        self.database_service = DatabaseService(self.cli_service)
        self.query_service = QueryService(self.cli_service, self.pack_service)

    def set_options(self, options: Dict[str, Any]):
        """Set analysis options."""
        self.database_service.set_options(options)

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run CodeQL semantic analysis on the repository."""
        if not self.cli_service.discover_cli() or not self.cli_service.validate_cli():
            return []

        repo = Path(repo_path)
        languages = self.language_service.detect_languages(repo, project_info)
        if not languages:
            return []

        try:
            findings = await self._analyze_with_temp_workspace(repo, languages)
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")
            return []

        logger.info(f"CodeQL analysis found {len(findings)} issues")
        return findings

    async def _analyze_with_temp_workspace(
        self, repo: Path, languages: List[str]
    ) -> List[Finding]:
        """Analyze languages in temporary workspace."""
        findings: List[Finding] = []

        with tempfile.TemporaryDirectory(prefix="codeql_") as temp_dir:
            work = Path(temp_dir)
            await self.workspace_service.setup(work, languages)
            self.query_service.set_search_path(self.workspace_service.search_path)

            for lang in languages:
                try:
                    lang_findings = await self._analyze_language(repo, work, lang)
                    findings.extend(lang_findings)
                except Exception as e:
                    logger.error(f"CodeQL analysis failed for {lang}: {e}")

        return findings

    async def _analyze_language(
        self, repo: Path, work: Path, language: str
    ) -> List[Finding]:
        """Analyze single language with CodeQL."""
        logger.info(f"Running CodeQL analysis for {language}")
        db_path = work / f"{language}_db"
        sarif_path = work / f"{language}_results.sarif"

        await self.database_service.create_database(repo, db_path, language)

        query_specs = self.query_service.get_query_specs(language)
        if not query_specs:
            logger.warning(f"No query specs available for {language}")
            return []

        await self.query_service.preview_queries(query_specs, language)
        await self.query_service.run_analysis(db_path, sarif_path, query_specs)

        if sarif_path.exists():
            return self.sarif_service.parse_sarif_results(sarif_path, repo)
        return []
