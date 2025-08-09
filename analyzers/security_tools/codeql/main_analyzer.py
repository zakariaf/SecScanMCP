"""
Main CodeQL Semantic Analysis Analyzer

Orchestrates CodeQL-based semantic code analysis with MCP security rules
Following clean architecture principles with ≤100 lines per file
"""

import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any

from analyzers.base import BaseAnalyzer
from models import Finding
from .services.cli_service import CLIService
from .services.language_service import LanguageService
from .services.pack_service import PackService
from .services.sarif_service import SarifService

logger = logging.getLogger(__name__)


class CodeQLAnalyzer(BaseAnalyzer):
    """Clean orchestrator for CodeQL semantic code analysis"""
    
    def __init__(self):
        super().__init__()
        self.cli_service = CLIService()
        self.language_service = LanguageService(self)
        self.pack_service = PackService(self.cli_service)
        self.sarif_service = SarifService(self)
        
        # Initialize CLI and validate
        self.cli_service.discover_cli()
        self.cli_service.validate_cli()
        
        # Instance variables from original
        self.scan_options: Dict[str, Any] = {}
        self._search_path = ""
    
    def set_options(self, options: Dict[str, Any]):
        """Set analysis options"""
        self.scan_options = options or {}
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run CodeQL semantic analysis on the repository"""
        # Initialize CLI
        if not self.cli_service.discover_cli() or not self.cli_service.validate_cli():
            logger.warning("CodeQL CLI not available, skipping analysis")
            return []
        
        findings: List[Finding] = []
        repo = Path(repo_path)
        
        try:
            self.log_scan_summary(repo_path)
            
            # Detect supported languages
            languages = self.language_service.detect_languages(repo, project_info)
            if not languages:
                logger.info("No supported languages found for CodeQL analysis")
                return findings
            
            # Analyze in temporary working directory
            findings = await self._analyze_with_temp_workspace(repo, languages)
            
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")
        
        logger.info(f"CodeQL analysis found {len(findings)} issues")
        return findings
    
    async def _analyze_with_temp_workspace(self, repo: Path, languages: List[str]) -> List[Finding]:
        """Analyze languages in temporary workspace"""
        findings: List[Finding] = []
        
        with tempfile.TemporaryDirectory(prefix="codeql_") as temp_dir:
            work = Path(temp_dir)
            
            # Setup workspace
            await self._setup_workspace(work, languages)
            
            # Analyze each language
            for lang in languages:
                try:
                    lang_findings = await self._analyze_language(repo, work, lang)
                    findings.extend(lang_findings)
                except Exception as e:
                    logger.error(f"CodeQL analysis failed for {lang}: {e}")
        
        return findings
    
    async def _setup_workspace(self, work: Path, languages: List[str]):
        """Setup CodeQL workspace with packs and search paths"""
        # Setup local packs
        local_packs_root = work / "local-packs"
        local_packs_root.mkdir(parents=True, exist_ok=True)
        await self.pack_service.synthesize_language_packs(local_packs_root)
        
        # Setup search path
        codeql_pkg_cache = Path.home() / ".codeql" / "packages"
        self._search_path = f"{local_packs_root}:{codeql_pkg_cache}"
        
        # Pre-download official packs  
        await self._download_official_packs(languages)
    
    async def _download_official_packs(self, languages: List[str]):
        """Pre-download official CodeQL packs"""
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
                    ["pack", "download"] + unique_packs,
                    timeout=300
                )
            except Exception as e:
                logger.warning(f"Pack download failed: {e}")
    
    async def _analyze_language(self, repo: Path, work: Path, language: str) -> List[Finding]:
        """Analyze single language with CodeQL"""
        findings: List[Finding] = []
        
        logger.info(f"Running CodeQL analysis for {language}")
        db_path = work / f"{language}_db"
        sarif_path = work / f"{language}_results.sarif"
        
        try:
            # Create database
            await self._create_database(repo, db_path, language)
            
            # Get query specifications
            query_specs = self._get_query_specs(language)
            if not query_specs:
                logger.warning(f"No query specs available for {language}")
                return findings
            
            # Preview queries (for logging)
            await self._preview_queries(query_specs, language)
            
            # Run analysis
            await self._run_analysis(db_path, sarif_path, query_specs)
            
            # Parse results
            if sarif_path.exists():
                findings = self.sarif_service.parse_sarif_results(sarif_path, repo)
            
        except Exception as e:
            logger.error(f"Language analysis failed for {language}: {e}")
        
        return findings
    
    async def _create_database(self, repo: Path, db_path: Path, language: str):
        """Create CodeQL database for language"""
        create_cmd = [
            "database", "create", str(db_path),
            f"--language={language}",
            f"--source-root={repo}",
            "--overwrite",
            "--log-to-stderr",
        ]
        
        # Add Go-specific build command if needed
        if language == "go":
            build_cmd = self._get_go_build_command(repo)
            create_cmd.extend(["--command", build_cmd])
        
        result = await self.cli_service.run_command(create_cmd, timeout=600)
        if result.returncode != 0:
            msg = (result.stderr or "").strip() or (result.stdout or "").strip()
            raise RuntimeError(f"Database creation failed: {msg}")
    
    def _get_go_build_command(self, repo: Path) -> str:
        """Get Go build command for database creation"""
        build_cmd = (self.scan_options or {}).get("codeql_build_command")
        if not build_cmd:
            build_cmd = (
                f"sh -c \"cd '{repo}'; "
                "export GOPROXY='https://proxy.golang.org,direct' GOSUMDB='sum.golang.org' CGO_ENABLED=0; "
                "go mod download || true; go build ./...\""
            )
        return build_cmd
    
    def _get_query_specs(self, language: str) -> List[str]:
        """Get query specifications for language"""
        specs: List[str] = []
        
        # Add official suite
        official_suite = self.pack_service.get_official_suite_for_language(language)
        if official_suite:
            specs.append(official_suite)
        
        # Add local MCP suite if available
        local_suite = self.pack_service.get_local_suite_for_language(language)
        if local_suite and local_suite.exists():
            specs.append(str(local_suite))
        
        logger.info(f"Using query specs for {language}: {specs}")
        return specs
    
    async def _preview_queries(self, query_specs: List[str], language: str):
        """Preview queries that will be executed"""
        try:
            result = await self.cli_service.run_command(
                ["resolve", "queries"] + query_specs + [f"--search-path={self._search_path}"],
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
    
    async def _run_analysis(self, db_path: Path, sarif_path: Path, query_specs: List[str]):
        """Run CodeQL analysis and generate SARIF results"""
        analyze_cmd = [
            "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
            "--sarif-add-query-help",
            "--threads=0",
            "--ram=2048",
            f"--search-path={self._search_path}",
        ] + query_specs
        
        logger.info(f"Running CodeQL analysis with {len(query_specs)} query specs")
        result = await self.cli_service.run_command(analyze_cmd, timeout=1800)
        
        if result.returncode != 0:
            raise RuntimeError(f"Analysis failed: {result.stderr or result.stdout}")