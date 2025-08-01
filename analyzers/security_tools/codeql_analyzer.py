import asyncio
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path
from shutil import which
from typing import Any, Dict, List, Optional

from ..base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType


class CodeQLAnalyzer(BaseAnalyzer):
    """
    CodeQL semantic analyzer with MCP-aware rules and safe autobuilds.
    - Detects languages
    - Installs standard packs + local MCP pack
    - Builds DBs (with safe JS/TS/go heuristics)
    - Analyzes to SARIF and maps to our Finding model
    """

    CODEQL_CLI: Optional[str] = None
    QUERIES_DIR = Path("/app/rules/codeql")

    LANGUAGE_MAP = {
        "python": "python",
        "javascript": "javascript",
        "typescript": "javascript",
        "java": "java",
        "csharp": "csharp",
        "cpp": "cpp",
        "c": "cpp",
        "go": "go",
        "ruby": "ruby",
    }

    def __init__(self):
        super().__init__()
        self._find_codeql_cli()
        self._validate_setup()
        self.scan_options: Dict[str, Any] = {}

    # ---------- Public API ----------

    def set_options(self, options: Dict[str, Any]):
        self.scan_options = options or {}

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        if not self.CODEQL_CLI:
            self.logger.warning("CodeQL CLI not available, skipping analysis")
            return []

        findings: List[Finding] = []
        repo = Path(repo_path)

        try:
            languages = await self._detect_languages(repo, project_info)
            if not languages:
                self.logger.info("No supported languages found for CodeQL analysis")
                return findings

            # MCP detection → enables MCP rules unless explicitly disabled
            mcp_detected = self._detect_mcp(repo)
            enable_mcp_rules = bool(self.scan_options.get("enable_mcp_rules", mcp_detected))
            if mcp_detected:
                self.logger.info("MCP project indicators detected.")
            if enable_mcp_rules:
                self.logger.info("MCP-specific rules are enabled.")

            # Pre-fetch packs to speed cold start
            await self._ensure_packs(languages, enable_mcp_rules)

            create_timeout = int(self.scan_options.get("create_timeout", 900))
            analyze_timeout = int(self.scan_options.get("analyze_timeout", 2400))
            threads = str(self.scan_options.get("codeql_threads", os.cpu_count() or 4))
            ram_mb = str(self.scan_options.get("codeql_ram_mb", 2048))

            with tempfile.TemporaryDirectory(prefix="codeql_") as temp_dir:
                temp_path = Path(temp_dir)

                for language in languages:
                    self.logger.info(f"Running CodeQL analysis for {language}")
                    try:
                        lang_findings = await self._analyze_language(
                            repo=repo,
                            temp_dir=temp_path,
                            language=language,
                            enable_mcp_rules=enable_mcp_rules,
                            create_timeout=create_timeout,
                            analyze_timeout=analyze_timeout,
                            threads=threads,
                            ram_mb=ram_mb,
                        )
                        findings.extend(lang_findings)
                    except Exception as e:
                        self.logger.error(f"CodeQL analysis failed for {language}: {e}")

            self.logger.info(f"CodeQL analysis found {len(findings)} issues")
        except Exception as e:
            self.logger.error(f"CodeQL analysis failed: {e}")

        return findings

    # ---------- Setup ----------

    def _find_codeql_cli(self):
        path = which("codeql")
        if path:
            self.CODEQL_CLI = path
            self.logger.info(f"Found CodeQL CLI at: {path}")
            return

        for location in ("/opt/codeql/codeql", "/usr/local/bin/codeql", "/usr/bin/codeql"):
            if os.path.exists(location) and os.access(location, os.X_OK):
                self.CODEQL_CLI = location
                self.logger.info(f"Found CodeQL CLI at: {location}")
                return

        self.logger.error("CodeQL CLI not found")

    def _validate_setup(self):
        if not self.CODEQL_CLI:
            return
        try:
            result = subprocess.run(
                [self.CODEQL_CLI, "--version"], capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                self.logger.info(f"CodeQL version: {result.stdout.strip()}")
            else:
                self.logger.error(f"CodeQL validation failed: {result.stderr}")
        except Exception as e:
            self.logger.error(f"Failed to validate CodeQL: {e}")

    # ---------- Language & MCP detection ----------

    async def _detect_languages(self, repo_path: Path, project_info: Dict[str, Any]) -> List[str]:
        langs: set[str] = set()

        hint = (project_info or {}).get("language")
        if hint:
            hint = str(hint).lower()
            if hint in self.LANGUAGE_MAP:
                langs.add(self.LANGUAGE_MAP[hint])

        patterns = {
            "python": ["*.py"],
            "javascript": ["*.js", "*.jsx", "*.ts", "*.tsx"],
            "java": ["*.java"],
            "csharp": ["*.cs"],
            "cpp": ["*.c", "*.cc", "*.cpp", "*.cxx", "*.h", "*.hpp"],
            "go": ["*.go"],
            "ruby": ["*.rb"],
        }
        for language, globs in patterns.items():
            for pat in globs:
                if next(repo_path.rglob(pat), None) is not None:
                    langs.add(language)
                    break

        return sorted(langs)  # stable order

    def _detect_mcp(self, repo: Path) -> bool:
        # Python deps
        for fn in ("requirements.txt", "pyproject.toml"):
            p = repo / fn
            if p.exists():
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore").lower()
                    if any(s in txt for s in ("modelcontextprotocol", "fastmcp", "mcp ")):
                        return True
                except Exception:
                    pass

        # Node deps
        pkg = repo / "package.json"
        if pkg.exists():
            try:
                data = json.loads(pkg.read_text(encoding="utf-8", errors="ignore"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                if any(k.startswith("@modelcontextprotocol/") or k == "@modelcontextprotocol/sdk" for k in deps):
                    return True
            except Exception:
                pass

        # Source hints
        for pat in ("**/*.py", "**/*.ts", "**/*.js"):
            for f in repo.glob(pat):
                try:
                    head = f.read_text(encoding="utf-8", errors="ignore")[:20000]
                except Exception:
                    continue
                if re.search(r"@mcp\.tool|\bserver\.tool\(", head) or re.search(r"\bimport\s+mcp\b", head):
                    return True
        return False

    # ---------- Pack management & query selection ----------

    async def _ensure_packs(self, languages: List[str], enable_mcp_rules: bool):
        if not self.CODEQL_CLI:
            return
        default = [f"codeql/{lang}-queries" for lang in languages if lang in self.LANGUAGE_MAP]
        if default:
            await self._run_command([self.CODEQL_CLI, "pack", "download", *default], timeout=600)

        # Local pack installation (if present)
        if enable_mcp_rules and self.QUERIES_DIR.exists():
            try:
                await self._run_command([self.CODEQL_CLI, "pack", "install", str(self.QUERIES_DIR)], timeout=300)
            except Exception as e:
                self.logger.warning(f"Failed to install local MCP pack: {e}")

    def _suite_args(self, language: str, enable_mcp_rules: bool) -> List[str]:
        args: List[str] = []
        # Always run the standard security-and-quality pack for this language
        args.append(f"codeql/{language}-queries:security-and-quality")
        # If our local MCP pack exists and enabled, run its suite too
        if enable_mcp_rules and (self.QUERIES_DIR / "mcp-security.qls").exists():
            # Allow pack reference or path; pack reference preferred
            args.append(str(self.QUERIES_DIR / "mcp-security.qls"))
        return args

    # ---------- Per-language DB & analyze ----------

    async def _analyze_language(
        self,
        repo: Path,
        temp_dir: Path,
        language: str,
        enable_mcp_rules: bool,
        create_timeout: int,
        analyze_timeout: int,
        threads: str,
        ram_mb: str,
    ) -> List[Finding]:
        findings: List[Finding] = []
        db_path = temp_dir / f"{language}_db"

        # Create DB with safe build heuristics where needed
        create_cmd = [
            self.CODEQL_CLI, "database", "create", str(db_path),
            f"--language={language}",
            f"--source-root={repo}",
            "--overwrite",
            "--log-to-stderr",
            "--quiet",
        ]

        # JS/TS safe install to help extraction, without running scripts
        if language == "javascript":
            build_cmd = None
            if (repo / "pnpm-lock.yaml").exists():
                build_cmd = "sh -c \"pnpm i --ignore-scripts --frozen-lockfile || pnpm i --ignore-scripts; pnpm -v >/dev/null\""
            elif (repo / "yarn.lock").exists():
                build_cmd = "sh -c \"yarn install --ignore-scripts --frozen-lockfile || yarn install --ignore-scripts\""
            elif (repo / "package-lock.json").exists():
                build_cmd = "sh -c \"npm ci --ignore-scripts --no-audit --no-fund || npm i --ignore-scripts\""
            if build_cmd:
                create_cmd.extend(["--command", build_cmd])

        # Go: warm caches & build without CGO
        if language == "go":
            env = (
                f"export GOPROXY='https://proxy.golang.org,direct' GOSUMDB='sum.golang.org' CGO_ENABLED=0;"
                "go env -w GOMODCACHE=${GOMODCACHE:-$HOME/go/pkg/mod} >/dev/null 2>&1 || true;"
                "go list ./... >/dev/null 2>&1 || true; "
                "go build ./... || true"
            )
            create_cmd.extend(["--command", f"sh -c \"cd '{repo}'; {env}\""])

        # Java/C#/C/C++: let CodeQL autobuild try first
        if language in {"java", "csharp", "cpp"}:
            create_cmd.append("--command=autobuild")

        # Create database
        result = await self._run_command(create_cmd, timeout=create_timeout)
        if result.returncode != 0:
            msg = (result.stderr or "").strip() or (result.stdout or "").strip()
            self.logger.error(f"Database creation failed for {language}: {msg}")
            return findings

        # Analyze
        results_file = temp_dir / f"{language}_results.sarif"
        analyze_cmd = [
            self.CODEQL_CLI, "database", "analyze", str(db_path),
            "--format=sarif-latest",
            f"--output={results_file}",
            "--sarif-add-query-help",
            "--no-progress",
            "--quiet",
            f"--threads={threads}",
            f"--ram={ram_mb}",
        ]
        analyze_cmd.extend(self._suite_args(language, enable_mcp_rules))

        result = await self._run_command(analyze_cmd, timeout=analyze_timeout)
        if result.returncode != 0:
            self.logger.error(f"Analysis failed for {language}: {result.stderr}")
            return findings

        if results_file.exists():
            findings = self._parse_sarif_results(results_file, repo)

        return findings

    # ---------- Subprocess helper ----------

    async def _run_command(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout.decode("utf-8", errors="replace"),
                stderr=stderr.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            if process:
                process.terminate()
                try:
                    await process.wait()
                except Exception:
                    pass
            raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

    # ---------- SARIF parsing ----------

    def _relativize(self, uri: str, repo_root: Path) -> str:
        # try to map artifactLocation.uri to a path within repo
        try:
            p = Path(uri)
            if p.is_absolute():
                try:
                    return str(p.relative_to(repo_root))
                except Exception:
                    return str(p)
            return str(p)
        except Exception:
            return uri

    def _parse_sarif_results(self, sarif_file: Path, repo_root: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            sarif = json.loads(sarif_file.read_text(encoding="utf-8", errors="ignore"))
            for run in sarif.get("runs", []) or []:
                rules_by_id = {}
                driver = run.get("tool", {}).get("driver", {}) or {}
                for rule in driver.get("rules", []) or []:
                    if "id" in rule:
                        rules_by_id[rule["id"]] = rule

                for result in run.get("results", []) or []:
                    f = self._convert_sarif_result(result, rules_by_id, repo_root)
                    if f:
                        findings.append(f)
        except Exception as e:
            self.logger.error(f"Failed to parse SARIF results: {e}")
        return findings

    def _convert_sarif_result(
        self, result: Dict[str, Any], rules: Dict[str, Any], repo_root: Path
    ) -> Optional[Finding]:
        try:
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})
            level = (result.get("level") or "warning").lower()

            # Location (normalize to repo-relative if we can)
            location = "unknown"
            locs = result.get("locations") or []
            if locs:
                phys = (locs[0] or {}).get("physicalLocation", {}) or {}
                artifact = phys.get("artifactLocation", {}) or {}
                uri = artifact.get("uri", "unknown")
                region = phys.get("region", {}) or {}
                line = region.get("startLine", 0)
                location = f"{self._relativize(uri, repo_root)}:{line}"

            return self.create_finding(
                vulnerability_type=self._determine_vuln_type(rule, result),
                severity=self._determine_severity(rule, result),
                confidence=self._extract_confidence(rule, result),
                title=self._extract_title(rule, result),
                description=self._build_description(rule, result),
                location=location,
                recommendation=self._extract_recommendation(rule, result),
                references=self._build_references(rule),
                evidence={
                    "rule_id": rule_id,
                    "level": level,
                    "message": (result.get("message", {}) or {}).get("text", ""),
                    "fingerprint": result.get("fingerprints", {}),
                },
            )
        except Exception as e:
            self.logger.error(f"Failed to convert SARIF result: {e}")
            return None

    # ---------- Helpers for fields ----------

    def _extract_title(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        if rule.get("name"):
            return str(rule["name"])
        msg = (result.get("message", {}) or {}).get("text")
        return msg or "CodeQL issue"

    def _build_description(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        parts: List[str] = []
        fd = (rule.get("fullDescription") or {}).get("text")
        if fd:
            parts.append(fd)
        sd = (rule.get("shortDescription") or {}).get("text")
        if sd and sd not in parts:
            parts.append(sd)
        msg = (result.get("message", {}) or {}).get("text")
        if msg:
            parts.append(f"\nDetails: {msg}")
        return "\n".join([p for p in parts if p])

    def _extract_recommendation(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        help_obj = rule.get("help") or {}
        if isinstance(help_obj, dict):
            rec = help_obj.get("text") or help_obj.get("markdown")
            if rec:
                return rec
        rid = (rule.get("id") or "").lower()
        if "sql" in rid:
            return "Use parameterized queries or prepared statements."
        if "injection" in rid:
            return "Validate/sanitize all untrusted input before use."
        if "xss" in rid:
            return "Encode output and validate input to prevent XSS."
        if "crypto" in rid:
            return "Use modern, strong cryptographic primitives and safe modes."
        return "Review and apply relevant secure-coding best practices."

    def _build_references(self, rule: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        help_uri = rule.get("helpUri")
        if help_uri:
            refs.append(help_uri)
        tags = (rule.get("properties", {}) or {}).get("tags", []) or []
        for tag in tags:
            m = re.search(r"cwe[-/](\d+)", str(tag).lower())
            if m:
                refs.append(f"https://cwe.mitre.org/data/definitions/{m.group(1)}.html")
        return refs

    def _determine_vuln_type(self, rule: Dict[str, Any], result: Dict[str, Any]) -> VulnerabilityType:
        tags = (rule.get("properties", {}) or {}).get("tags", []) or []
        tagset = {str(t).lower() for t in tags}
        rid = (rule.get("id") or "").lower()

        if any("cwe-79" in t or "cwe/79" in t for t in tagset):
            return VulnerabilityType.XSS
        if any("cwe-89" in t or "cwe/89" in t for t in tagset):
            return VulnerabilityType.SQL_INJECTION
        if any("cwe-78" in t or "cwe/78" in t for t in tagset):
            return VulnerabilityType.COMMAND_INJECTION
        if any("cwe-22" in t or "cwe/22" in t for t in tagset):
            return VulnerabilityType.PATH_TRAVERSAL
        if any("cwe-352" in t or "cwe/352" in t for t in tagset):
            return VulnerabilityType.CSRF
        if any("ssrf" in t for t in tagset):
            return VulnerabilityType.SSRF
        if any("hardcoded-secret" in t or "credential" in t for t in tagset):
            return VulnerabilityType.HARDCODED_SECRET
        if any("crypto" in t or "cryptography" in t for t in tagset):
            return VulnerabilityType.WEAK_CRYPTO

        if "xss" in rid:
            return VulnerabilityType.XSS
        if "sql" in rid:
            return VulnerabilityType.SQL_INJECTION
        if "inject" in rid:
            return VulnerabilityType.COMMAND_INJECTION
        if "xxe" in rid:
            return VulnerabilityType.XXE
        if "path" in rid and "traversal" in rid:
            return VulnerabilityType.PATH_TRAVERSAL

        return VulnerabilityType.GENERIC

    def _determine_severity(self, rule: Dict[str, Any], result: Dict[str, Any]) -> SeverityLevel:
        props = (rule.get("properties", {}) or {})
        sec_sev = props.get("security-severity")
        if sec_sev is not None:
            try:
                score = float(sec_sev)
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                if score >= 7.0:
                    return SeverityLevel.HIGH
                if score >= 4.0:
                    return SeverityLevel.MEDIUM
                return SeverityLevel.LOW
            except Exception:
                pass
        level = (result.get("level") or "warning").lower()
        return {
            "error": SeverityLevel.HIGH,
            "warning": SeverityLevel.MEDIUM,
            "note": SeverityLevel.LOW,
            "none": SeverityLevel.INFO,
        }.get(level, SeverityLevel.MEDIUM)

    def _extract_confidence(self, rule: Dict[str, Any], result: Dict[str, Any]) -> float:
        precision = (rule.get("properties", {}) or {}).get("precision", "medium").lower()
        return {
            "very-high": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.50,
        }.get(precision, 0.70)
