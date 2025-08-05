import asyncio
import subprocess
import json
import tempfile
import shutil
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import os

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class CodeQLAnalyzer(BaseAnalyzer):
    """CodeQL semantic code analysis engine (finalized)
    - Splits local MCP rules into per-language ephemeral packs to avoid dbscheme conflicts.
    - Uses official CodeQL code-scanning suites per language + local MCP suites.
    - Runs everything from a writable temp workdir (no more read-only lockfile errors).
    - Provides rich logging for observability.
    """
    CODEQL_CLI: Optional[str] = None

    # Root where your repo mounts language-specific queries (read-only in the container)
    RULES_ROOT = Path("/app/rules/codeql/mcp-security-queries")

    # Official code-scanning suites by language
    OFFICIAL_SUITE = {
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls",
        "python": "codeql/python-queries:codeql-suites/python-code-scanning.qls",
        "java": "codeql/java-queries:codeql-suites/java-code-scanning.qls",
        "go": "codeql/go-queries:codeql-suites/go-code-scanning.qls",
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-code-scanning.qls",
        "csharp": "codeql/csharp-queries:codeql-suites/csharp-code-scanning.qls",
        "ruby": "codeql/ruby-queries:codeql-suites/ruby-code-scanning.qls",
    }

    # Mapping to language libraries (each pack must pick exactly one)
    CORE_DEPS = {
        "javascript": "codeql/javascript-all",
        "python": "codeql/python-all",
        "java": "codeql/java-all",
        "go": "codeql/go-all",
        "cpp": "codeql/cpp-all",
        "csharp": "codeql/csharp-all",
        "ruby": "codeql/ruby-all",
    }


    def __init__(self):
        super().__init__()
        self._find_codeql_cli()
        self._validate_setup()
        self.scan_options: Dict[str, Any] = {}
        # ephemeral per-run pack root and suites
        self._local_packs_root: Optional[Path] = None
        self._local_suite_for_lang: Dict[str, Path] = {}
        self._search_path: Optional[str] = None

    def set_options(self, options: Dict[str, Any]):
        self.scan_options = options or {}

    # --- Setup helpers -----------------------------------------------------

    def _find_codeql_cli(self):
        try:
            r = subprocess.run(["which", "codeql"], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip():
                self.CODEQL_CLI = r.stdout.strip()
                logger.info(f"Found CodeQL CLI at: {self.CODEQL_CLI}")
                return
        except Exception:
            pass

        for location in ["/opt/codeql/codeql", "/usr/local/bin/codeql", "/usr/bin/codeql"]:
            if os.path.exists(location) and os.access(location, os.X_OK):
                self.CODEQL_CLI = location
                logger.info(f"Found CodeQL CLI at: {self.CODEQL_CLI}")
                return

        logger.error("CodeQL CLI not found in PATH or known locations")

    def _validate_setup(self):
        if not self.CODEQL_CLI:
            logger.error("CodeQL CLI not found")
            return
        try:
            r = subprocess.run([self.CODEQL_CLI, "--version"], capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                logger.info(f"CodeQL version: {r.stdout.strip()}")
            else:
                logger.error(f"CodeQL validation failed: {r.stderr}")
        except Exception as e:
            logger.error(f"Failed to validate CodeQL: {e}")

    # --- Orchestration -----------------------------------------------------

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        if not self.CODEQL_CLI:
            logger.warning("CodeQL CLI not available, skipping analysis")
            return []

        findings: List[Finding] = []
        repo = Path(repo_path)

        try:
            # Log scan summary
            self.log_scan_summary(repo_path)
            
            languages = await self._detect_languages(repo, project_info)
            if not languages:
                logger.info("No supported languages found for CodeQL analysis")
                return findings

            logger.info(f"Detected languages for CodeQL: {languages}")

            # Prepare working area (copy local packs per language and install dependencies)
            with tempfile.TemporaryDirectory(prefix="codeql_") as td:
                work = Path(td)
                codeql_pkg_cache = Path.home() / ".codeql" / "packages"
                self._local_packs_root = work / "local-packs"
                self._local_packs_root.mkdir(parents=True, exist_ok=True)
                await self._synthesize_language_packs(self._local_packs_root)

                # global search path includes our local-packs root and the CodeQL cache
                self._search_path = f"{self._local_packs_root}:{codeql_pkg_cache}"

                # Pre-download the official base packs (best-effort)
                to_download = sorted({self._official_pack_for_lang(l) for l in languages if self._official_pack_for_lang(l)})
                if to_download:
                    logger.info(f"Pre-downloading default CodeQL packs: {to_download}")
                    try:
                        await self._run_command([self.CODEQL_CLI, "pack", "download", *to_download], timeout=300)
                    except Exception as e:
                        logger.warning(f"Pack download skipped/failed ({e})")

                # analyze each language
                for lang in languages:
                    try:
                        lang_findings = await self._analyze_language(repo, work, lang)
                        findings.extend(lang_findings)
                    except Exception as e:
                        logger.error(f"CodeQL analysis failed for {lang}: {e}")
        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")

        logger.info(f"CodeQL analysis found {len(findings)} issues")
        return findings

    # --- Language detection ------------------------------------------------

    async def _detect_languages(self, repo_path: Path, project_info: Dict[str, Any]) -> List[str]:
        languages = set()
        # project hint
        lang = (project_info or {}).get("language", "").lower()
        if lang in {"python", "javascript", "java", "csharp", "cpp", "go", "ruby", "typescript"}:
            languages.add("javascript" if lang in {"javascript", "typescript"} else lang)

        # Get filtered files to check language patterns efficiently
        filtered_files = self.get_filtered_files(str(repo_path))
        
        # Map extensions to languages
        ext_to_lang = {
            ".py": "python",
            ".js": "javascript", ".jsx": "javascript", ".ts": "javascript", ".tsx": "javascript",
            ".java": "java",
            ".cs": "csharp",
            ".c": "cpp", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".h": "cpp", ".hpp": "cpp",
            ".go": "go",  
            ".rb": "ruby",
        }
        
        # Check filtered files for language patterns
        for file_path in filtered_files:
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ext_to_lang:
                languages.add(ext_to_lang[file_ext])

        # MCP indicator logging (check only filtered files)
        mcp_indicators = any([
            any("mcp" in Path(f).name.lower() and f.endswith((".json", ".yaml", ".yml")) for f in filtered_files),
            any("tool" in Path(f).name.lower() and "schema" in Path(f).name.lower() and f.endswith(".json") for f in filtered_files),
        ])
        if mcp_indicators:
            logger.info("MCP project indicators detected.")
            logger.info("MCP-specific rules are enabled.")
        return list(languages)

    # --- Pack synthesis ----------------------------------------------------

    async def _synthesize_language_packs(self, packs_root: Path) -> None:
        """Set up language-specific packs from RULES_ROOT.
        
        Since we now have separate pre-configured packs for each language,
        we just need to copy them and set up the search paths correctly.
        """
        if not self.RULES_ROOT.exists():
            logger.info(f"No local CodeQL rules found at {self.RULES_ROOT}")
            return

        # Check for JavaScript pack
        js_pack_path = self.RULES_ROOT
        if (js_pack_path / "qlpack.yml").exists() and (js_pack_path / "javascript").exists():
            logger.info("Found JavaScript MCP security pack")
            # Copy to working directory
            js_work_pack = packs_root / "mcp-security-queries-javascript"
            shutil.copytree(js_pack_path, js_work_pack, dirs_exist_ok=True)
            # Remove Python directory if it exists
            python_dir = js_work_pack / "python"
            if python_dir.exists():
                shutil.rmtree(python_dir)
            self._local_suite_for_lang["javascript"] = js_work_pack / "mcp-javascript-suite.qls"
            
            # Install dependencies
            try:
                logger.info(f"Installing JavaScript MCP CodeQL pack from {js_work_pack}")
                await self._run_command([self.CODEQL_CLI, "pack", "install"], cwd=str(js_work_pack), timeout=300)
            except Exception as e:
                logger.error(f"'codeql pack install' failed for JavaScript pack: {e}")

        # Check for Python pack
        py_pack_path = self.RULES_ROOT / "python"
        if (py_pack_path / "qlpack.yml").exists():
            logger.info("Found Python MCP security pack")
            # Copy to working directory
            py_work_pack = packs_root / "mcp-security-queries-python"
            shutil.copytree(py_pack_path, py_work_pack, dirs_exist_ok=True)
            self._local_suite_for_lang["python"] = py_work_pack / "mcp-python-suite.qls"
            
            # Install dependencies
            try:
                logger.info(f"Installing Python MCP CodeQL pack from {py_work_pack}")
                await self._run_command([self.CODEQL_CLI, "pack", "install"], cwd=str(py_work_pack), timeout=300)
            except Exception as e:
                logger.error(f"'codeql pack install' failed for Python pack: {e}")

    # --- Per-language analysis --------------------------------------------

    async def _analyze_language(self, repo: Path, work: Path, language: str) -> List[Finding]:
        findings: List[Finding] = []

        logger.info(f"Running CodeQL analysis for {language}")
        db = work / f"{language}_db"
        sarif = work / f"{language}_results.sarif"

        # 1) create database
        create_cmd = [
            self.CODEQL_CLI, "database", "create", str(db),
            f"--language={language}",
            f"--source-root={repo}",
            "--overwrite",
            "--log-to-stderr",
        ]
        if language == "go":
            build_cmd = (self.scan_options or {}).get("codeql_build_command")
            if not build_cmd:
                build_cmd = (
                    f"sh -c \"cd '{repo}'; "
                    "export GOPROXY='https://proxy.golang.org,direct' GOSUMDB='sum.golang.org' CGO_ENABLED=0; "
                    "go mod download || true; go build ./...\""
                )
            create_cmd.extend(["--command", build_cmd])

        result = await self._run_command(create_cmd, timeout=600)
        if result.returncode != 0:
            msg = (result.stderr or "").strip() or (result.stdout or "").strip()
            logger.error(f"Database creation failed: {msg}")
            return findings

        # 2) compute query specs (official + local mcp suite if present)
        official_suite = self._resolve_official_suite(language)
        local_suite = self._local_suite_for_lang.get(language)
        specs: List[str] = [official_suite] if official_suite else []
        if local_suite and local_suite.exists():
            specs.append(str(local_suite))
        logger.info(f"Selected official CodeQL suite for {language}: {official_suite}")
        logger.info(f"Using query specs for {language}: {specs}")

        # 3) preview queries (log what will run)
        try:
            preview = await self._run_command(
                [self.CODEQL_CLI, "resolve", "queries", *specs, f"--search-path={self._search_path}"],
                timeout=120
            )
            if preview.returncode == 0:
                lines = [ln for ln in preview.stdout.splitlines() if ln.strip()]
                logger.info(f"Resolved {len(lines)} CodeQL queries for {language}")
                for qpath in lines[:10]:
                    logger.info(f"Resolved query: {qpath}")
                if len(lines) > 10:
                    logger.info(f"... and {len(lines) - 10} more")
            else:
                logger.warning(f"Could not resolve queries: {preview.stderr}")
        except Exception as e:
            logger.warning(f"Resolve queries failed: {e}")

        # 4) analyze
        analyze_cmd = [
            self.CODEQL_CLI, "database", "analyze", str(db),
            "--format=sarif-latest",
            f"--output={sarif}",
            "--sarif-add-query-help",
            "--threads=0",
            "--ram=2048",
            f"--search-path={self._search_path}",
            *specs,
        ]
        logger.info(f"Analyze cmd: {' '.join(analyze_cmd)}")
        result = await self._run_command(analyze_cmd, timeout=1800)
        if result.returncode != 0:
            logger.error(f"Analysis failed for {language}: {result.stderr or result.stdout}")
            return findings

        # 5) parse SARIF
        if sarif.exists():
            findings = self._parse_sarif_results(sarif, repo)
        return findings

    def _official_pack_for_lang(self, lang: str) -> str:
        # For download purpose, use the queries pack not the all pack
        mapping = {
            "javascript": "codeql/javascript-queries",
            "python": "codeql/python-queries",
            "java": "codeql/java-queries",
            "go": "codeql/go-queries",
            "cpp": "codeql/cpp-queries",
            "csharp": "codeql/csharp-queries",
            "ruby": "codeql/ruby-queries",
        }
        return mapping.get(lang, "")

    def _resolve_official_suite(self, lang: str) -> Optional[str]:
        return self.OFFICIAL_SUITE.get(lang)

    # --- Utilities ---------------------------------------------------------

    async def _run_command(self, cmd: List[str], timeout: int = 300, cwd: Optional[str] = None) -> subprocess.CompletedProcess:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            try:
                process.terminate()
            except ProcessLookupError:
                pass
            await process.wait()
            raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

        return subprocess.CompletedProcess(
            args=cmd,
            returncode=process.returncode,
            stdout=stdout.decode("utf-8", errors="replace"),
            stderr=stderr.decode("utf-8", errors="replace")
        )

    # --- SARIF parsing (same logic you already had) ------------------------

    def _parse_sarif_results(self, sarif_file: Path, repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            with open(sarif_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for run in data.get("runs", []):
                rules_by_id = {
                    rule.get("id"): rule
                    for rule in run.get("tool", {}).get("driver", {}).get("rules", []) or []
                }
                for result in run.get("results", []) or []:
                    fnd = self._convert_sarif_result(result, rules_by_id, repo_root)
                    if fnd:
                        findings.append(fnd)
        except Exception as e:
            logger.error(f"Failed to parse SARIF results: {e}")
        return findings

    def _convert_sarif_result(self, result: Dict[str, Any], rules: Dict[str, Any], repo_root: Path) -> Optional[Finding]:
        try:
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # location
            locations = result.get("locations", []) or []
            if locations:
                physical_location = locations[0].get("physicalLocation", {}) or {}
                artifact = physical_location.get("artifactLocation", {}) or {}
                uri = artifact.get("uri", "unknown")
                region = physical_location.get("region", {}) or {}
                line = region.get("startLine", 0)
                location = f"{uri}:{line}"
            else:
                location = "unknown"

            return self.create_finding(
                vulnerability_type=self._determine_vuln_type(rule, result),
                severity=self._determine_severity(rule, result),
                confidence=self._extract_confidence(rule, result),
                title=rule.get("name", result.get("message", {}).get("text", "Unknown issue")),
                description=self._build_description(rule, result),
                location=location,
                recommendation=self._extract_recommendation(rule, result),
                references=self._build_references(rule, rule.get("properties", {}) or {}),
                evidence={
                    "rule_id": rule_id,
                    "level": result.get("level", "warning"),
                    "message": result.get("message", {}).get("text", ""),
                    "fingerprint": result.get("fingerprints", {}) or {},
                },
            )
        except Exception as e:
            logger.error(f"Failed to convert SARIF result: {e}")
            return None

    def _determine_vuln_type(self, rule: Dict[str, Any], result: Dict[str, Any]) -> VulnerabilityType:
        props = rule.get("properties", {}) or {}
        tags = [t.lower() for t in (props.get("tags", []) or [])]
        rid = (rule.get("id", "") or "").lower()

        if any(t in tags for t in ["sql-injection"]):
            return VulnerabilityType.SQL_INJECTION
        if any(t in tags for t in ["command-injection"]):
            return VulnerabilityType.COMMAND_INJECTION
        if any(t in tags for t in ["xss", "cross-site-scripting"]):
            return VulnerabilityType.XSS
        if any(t in tags for t in ["path-traversal"]):
            return VulnerabilityType.PATH_TRAVERSAL
        if any(t in tags for t in ["ssrf"]):
            return VulnerabilityType.SSRF
        if any(t in tags for t in ["crypto", "cryptography"]):
            return VulnerabilityType.WEAK_CRYPTO
        if any(t in tags for t in ["hardcoded-secret", "credential"]):
            return VulnerabilityType.HARDCODED_SECRET

        if "inject" in rid:
            return VulnerabilityType.COMMAND_INJECTION
        if "sql" in rid:
            return VulnerabilityType.SQL_INJECTION
        if "xss" in rid:
            return VulnerabilityType.XSS
        if "xxe" in rid:
            return VulnerabilityType.XXE
        if "path" in rid and "traversal" in rid:
            return VulnerabilityType.PATH_TRAVERSAL

        return VulnerabilityType.GENERIC

    def _determine_severity(self, rule: Dict[str, Any], result: Dict[str, Any]) -> SeverityLevel:
        sev = (rule.get("properties", {}) or {}).get("security-severity")
        if sev:
            try:
                score = float(sev)
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                if score >= 7.0:
                    return SeverityLevel.HIGH
                if score >= 4.0:
                    return SeverityLevel.MEDIUM
                return SeverityLevel.LOW
            except Exception:
                pass
        level = (result.get("level", "warning") or "").lower()
        return {
            "error": SeverityLevel.HIGH,
            "warning": SeverityLevel.MEDIUM,
            "note": SeverityLevel.LOW,
            "none": SeverityLevel.INFO,
        }.get(level, SeverityLevel.MEDIUM)

    def _extract_confidence(self, rule: Dict[str, Any], result: Dict[str, Any]) -> float:
        precision = ((rule.get("properties", {}) or {}).get("precision", "medium") or "").lower()
        return {
            "very-high": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }.get(precision, 0.70)

    def _build_description(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        parts: List[str] = []
        if rule.get("fullDescription"):
            parts.append(rule["fullDescription"].get("text", ""))
        elif rule.get("shortDescription"):
            parts.append(rule["shortDescription"].get("text", ""))
        msg = (result.get("message", {}) or {}).get("text", "")
        if msg and msg not in parts:
            parts.append(f"\n\nDetails: {msg}")
        return "\n".join(filter(None, parts))

    def _extract_recommendation(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        help_text = ((rule.get("help", {}) or {}).get("text", "") or "").strip()
        if help_text:
            return help_text
        rid = (rule.get("id", "") or "").lower()
        if "sql" in rid:
            return "Use parameterized queries or prepared statements."
        if "injection" in rid:
            return "Sanitize and validate all user input before use."
        if "xss" in rid:
            return "Encode output and validate input to prevent XSS."
        if "crypto" in rid:
            return "Use strong, modern cryptographic algorithms."
        return "Review the code and apply security best practices."

    def _build_references(self, rule: Dict[str, Any], properties: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        for tag in properties.get("tags", []) or []:
            if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                try:
                    cwe_num = tag.upper().split("CWE-")[1]
                    refs.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")
                except Exception:
                    pass
        rid = rule.get("id", "") or ""
        if rid:
            refs.append(f"https://codeql.github.com/codeql-query-help/{rid}/")
        return refs
