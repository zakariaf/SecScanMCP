import asyncio
import subprocess
import json
import tempfile
import shutil
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import re
import os

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class CodeQLAnalyzer(BaseAnalyzer):
    """CodeQL semantic code analysis engine"""

    # CodeQL CLI location - use which to find it
    CODEQL_CLI = None

    # Custom queries directory
    QUERIES_DIR = Path("/app/rules/codeql")

    # Supported languages and their identifiers
    LANGUAGE_MAP = {
        'python': 'python',
        'javascript': 'javascript',
        'typescript': 'javascript',
        'java': 'java',
        'csharp': 'csharp',
        'cpp': 'cpp',
        'c': 'cpp',
        'go': 'go',
        'ruby': 'ruby'
    }

    def __init__(self):
        super().__init__()
        self._find_codeql_cli()
        self._validate_setup()

    def _find_codeql_cli(self):
        """Find CodeQL CLI in PATH or known locations"""
        # First try PATH
        try:
            result = subprocess.run(['which', 'codeql'], capture_output=True, text=True)
            if result.returncode == 0 and result.stdout.strip():
                self.CODEQL_CLI = result.stdout.strip()
                self.logger.info(f"Found CodeQL CLI at: {self.CODEQL_CLI}")
                return
        except:
            pass

        # Try known locations
        known_locations = [
            '/opt/codeql/codeql',
            '/usr/local/bin/codeql',
            '/usr/bin/codeql'
        ]

        for location in known_locations:
            if os.path.exists(location) and os.access(location, os.X_OK):
                self.CODEQL_CLI = location
                self.logger.info(f"Found CodeQL CLI at: {self.CODEQL_CLI}")
                return

        self.logger.error("CodeQL CLI not found in PATH or known locations")

    def _validate_setup(self):
        """Validate CodeQL installation"""
        if not self.CODEQL_CLI:
            self.logger.error("CodeQL CLI not found")
            return

        try:
            # Test CodeQL CLI
            result = subprocess.run(
                [self.CODEQL_CLI, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                self.logger.info(f"CodeQL version: {result.stdout.strip()}")
            else:
                self.logger.error(f"CodeQL validation failed: {result.stderr}")

        except Exception as e:
            self.logger.error(f"Failed to validate CodeQL: {e}")

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze repository with CodeQL"""
        if not self.CODEQL_CLI:
            self.logger.warning("CodeQL CLI not available, skipping analysis")
            return []

        findings = []
        repo_path = Path(repo_path)

        try:
            # Determine languages in the project
            languages = await self._detect_languages(repo_path, project_info)

            if not languages:
                self.logger.info("No supported languages found for CodeQL analysis")
                return findings

            # Create temporary directory for CodeQL databases
            with tempfile.TemporaryDirectory(prefix="codeql_") as temp_dir:
                temp_path = Path(temp_dir)

                # Analyze each language
                for language in languages:
                    self.logger.info(f"Running CodeQL analysis for {language}")

                    try:
                        lang_findings = await self._analyze_language(
                            repo_path,
                            temp_path,
                            language
                        )
                        findings.extend(lang_findings)
                    except Exception as e:
                        self.logger.error(f"CodeQL analysis failed for {language}: {e}")

            self.logger.info(f"CodeQL analysis found {len(findings)} issues")

        except Exception as e:
            self.logger.error(f"CodeQL analysis failed: {e}")

        return findings

    async def _detect_languages(self, repo_path: Path, project_info: Dict[str, Any]) -> List[str]:
        """Detect languages in the repository"""
        languages = set()

        # Use project info if available
        if project_info.get('language'):
            lang = project_info['language'].lower()
            if lang in self.LANGUAGE_MAP:
                languages.add(self.LANGUAGE_MAP[lang])

        # Scan for language indicators
        language_patterns = {
            'python': ['*.py'],
            'javascript': ['*.js', '*.jsx', '*.ts', '*.tsx'],
            'java': ['*.java'],
            'csharp': ['*.cs'],
            'cpp': ['*.cpp', '*.cc', '*.cxx', '*.c', '*.h', '*.hpp'],
            'go': ['*.go'],
            'ruby': ['*.rb']
        }

        for language, patterns in language_patterns.items():
            for pattern in patterns:
                if list(repo_path.rglob(pattern)):
                    languages.add(language)
                    break

        return list(languages)

    async def _analyze_language(self, repo_path: Path, temp_dir: Path, language: str) -> List[Finding]:
        """Analyze a specific language with CodeQL"""
        findings = []

        # Create database
        db_path = temp_dir / f"{language}_db"

        try:
            # Step 1: Create CodeQL database
            self.logger.info(f"Creating CodeQL database for {language}")

            create_cmd = [
                self.CODEQL_CLI,
                'database', 'create',
                str(db_path),
                f'--language={language}',
                f'--source-root={repo_path}',
                '--overwrite'
            ]

            # Add quiet flag to reduce output
            create_cmd.append('--quiet')

            result = await self._run_command(create_cmd, timeout=300)

            if result.returncode != 0:
                self.logger.error(f"Database creation failed: {result.stderr}")
                return findings

            # Step 2: Run analysis with queries
            self.logger.info(f"Running CodeQL queries for {language}")

            # Get queries to run
            queries = self._get_queries_for_language(language)

            if not queries:
                self.logger.warning(f"No queries found for {language}")
                return findings

            # Run analysis
            results_file = temp_dir / f"{language}_results.sarif"

            analyze_cmd = [
                self.CODEQL_CLI,
                'database', 'analyze',
                str(db_path),
                '--format=sarif-latest',
                f'--output={results_file}',
                '--sarif-add-query-help'
            ]

            # Add queries
            analyze_cmd.extend(queries)

            result = await self._run_command(analyze_cmd, timeout=600)

            if result.returncode != 0:
                self.logger.error(f"Analysis failed: {result.stderr}")
                return findings

            # Step 3: Parse results
            if results_file.exists():
                findings = self._parse_sarif_results(results_file, repo_path)

        except Exception as e:
            self.logger.error(f"CodeQL analysis error for {language}: {e}")

        return findings

    def _get_queries_for_language(self, language: str) -> List[str]:
        """Get CodeQL queries for a specific language"""
        queries = []

        # Use built-in security queries
        security_queries = {
            'python': 'python-security-and-quality.qls',
            'javascript': 'javascript-security-and-quality.qls',
            'java': 'java-security-and-quality.qls',
            'csharp': 'csharp-security-and-quality.qls',
            'cpp': 'cpp-security-and-quality.qls',
            'go': 'go-security-and-quality.qls',
            'ruby': 'ruby-security-and-quality.qls'
        }

        if language in security_queries:
            queries.append(security_queries[language])

        # Add custom queries if they exist
        if self.QUERIES_DIR.exists():
            custom_queries = list(self.QUERIES_DIR.glob("*.ql"))
            for query in custom_queries:
                # Check if query is for this language (simple heuristic)
                try:
                    with open(query, 'r') as f:
                        content = f.read(500)  # Read first 500 chars
                        if f'language[": ]*{language}' in content.lower():
                            queries.append(str(query))
                except:
                    pass

        return queries

    async def _run_command(self, cmd: List[str], timeout: int = 300) -> subprocess.CompletedProcess:
        """Run a command with timeout"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )

            return subprocess.CompletedProcess(
                args=cmd,
                returncode=process.returncode,
                stdout=stdout.decode('utf-8', errors='replace'),
                stderr=stderr.decode('utf-8', errors='replace')
            )

        except asyncio.TimeoutError:
            if process:
                process.terminate()
                await process.wait()
            raise TimeoutError(f"Command timed out after {timeout}s: {' '.join(cmd)}")

    def _parse_sarif_results(self, sarif_file: Path, repo_root: Path) -> List[Finding]:
        """Parse SARIF results file"""
        findings = []

        try:
            with open(sarif_file, 'r') as f:
                sarif_data = json.load(f)

            # Parse each run in the SARIF file
            for run in sarif_data.get('runs', []):
                # Get rules mapping
                rules_by_id = {
                    rule['id']: rule
                    for rule in run.get('tool', {}).get('driver', {}).get('rules', [])
                }

                # Process results
                for result in run.get('results', []):
                    finding = self._convert_sarif_result(result, rules_by_id, repo_root)
                    if finding:
                        findings.append(finding)

        except Exception as e:
            self.logger.error(f"Failed to parse SARIF results: {e}")

        return findings

    def _convert_sarif_result(self, result: Dict[str, Any], rules: Dict[str, Any], repo_root: Path) -> Optional[Finding]:
        """Convert SARIF result to Finding"""
        try:
            rule_id = result.get('ruleId', '')
            rule = rules.get(rule_id, {})

            # Extract location
            locations = result.get('locations', [])
            if locations:
                physical_location = locations[0].get('physicalLocation', {})
                artifact = physical_location.get('artifactLocation', {})
                uri = artifact.get('uri', 'unknown')
                region = physical_location.get('region', {})
                line = region.get('startLine', 0)
                location = f"{uri}:{line}"
            else:
                location = 'unknown'

            # Extract properties
            properties = rule.get('properties', {})

            # Build finding
            return self.create_finding(
                vulnerability_type=self._determine_vuln_type(rule, result),
                severity=self._determine_severity(rule, result),
                confidence=self._extract_confidence(rule, result),
                title=rule.get('name', result.get('message', {}).get('text', 'Unknown issue')),
                description=self._build_description(rule, result),
                location=location,
                recommendation=self._extract_recommendation(rule, result),
                references=self._build_references(rule, properties),
                evidence={
                    'rule_id': rule_id,
                    'level': result.get('level', 'warning'),
                    'message': result.get('message', {}).get('text', ''),
                    'fingerprint': result.get('fingerprints', {})
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to convert SARIF result: {e}")
            return None

    def _determine_vuln_type(self, rule: Dict[str, Any], result: Dict[str, Any]) -> VulnerabilityType:
        """Determine vulnerability type from CodeQL rule"""
        tags = rule.get('properties', {}).get('tags', [])
        rule_id = rule.get('id', '').lower()

        # Check tags first
        if 'injection' in tags or 'sql-injection' in tags:
            return VulnerabilityType.SQL_INJECTION
        elif 'command-injection' in tags:
            return VulnerabilityType.COMMAND_INJECTION
        elif 'xss' in tags or 'cross-site-scripting' in tags:
            return VulnerabilityType.XSS
        elif 'path-traversal' in tags:
            return VulnerabilityType.PATH_TRAVERSAL
        elif 'ssrf' in tags:
            return VulnerabilityType.SSRF
        elif 'crypto' in tags or 'cryptography' in tags:
            return VulnerabilityType.WEAK_CRYPTO
        elif 'hardcoded-secret' in tags or 'credential' in tags:
            return VulnerabilityType.HARDCODED_SECRET

        # Check rule ID patterns
        if 'inject' in rule_id:
            return VulnerabilityType.COMMAND_INJECTION
        elif 'sql' in rule_id:
            return VulnerabilityType.SQL_INJECTION
        elif 'xss' in rule_id:
            return VulnerabilityType.XSS
        elif 'xxe' in rule_id:
            return VulnerabilityType.XXE
        elif 'path' in rule_id and 'traversal' in rule_id:
            return VulnerabilityType.PATH_TRAVERSAL

        return VulnerabilityType.GENERIC

    def _determine_severity(self, rule: Dict[str, Any], result: Dict[str, Any]) -> SeverityLevel:
        """Determine severity from CodeQL rule"""
        # Check rule severity
        severity = rule.get('properties', {}).get('security-severity', None)
        if severity:
            try:
                score = float(severity)
                if score >= 9.0:
                    return SeverityLevel.CRITICAL
                elif score >= 7.0:
                    return SeverityLevel.HIGH
                elif score >= 4.0:
                    return SeverityLevel.MEDIUM
                else:
                    return SeverityLevel.LOW
            except:
                pass

        # Check result level
        level = result.get('level', 'warning').lower()
        level_map = {
            'error': SeverityLevel.HIGH,
            'warning': SeverityLevel.MEDIUM,
            'note': SeverityLevel.LOW,
            'none': SeverityLevel.INFO
        }

        return level_map.get(level, SeverityLevel.MEDIUM)

    def _extract_confidence(self, rule: Dict[str, Any], result: Dict[str, Any]) -> float:
        """Extract confidence from CodeQL rule"""
        precision = rule.get('properties', {}).get('precision', 'medium').lower()

        precision_map = {
            'very-high': 0.95,
            'high': 0.85,
            'medium': 0.70,
            'low': 0.50
        }

        return precision_map.get(precision, 0.70)

    def _build_description(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        """Build comprehensive description"""
        parts = []

        # Add rule description
        if rule.get('fullDescription'):
            parts.append(rule['fullDescription'].get('text', ''))
        elif rule.get('shortDescription'):
            parts.append(rule['shortDescription'].get('text', ''))

        # Add result message
        message = result.get('message', {}).get('text', '')
        if message and message not in parts:
            parts.append(f"\n\nDetails: {message}")

        return '\n'.join(parts)

    def _extract_recommendation(self, rule: Dict[str, Any], result: Dict[str, Any]) -> str:
        """Extract recommendation from rule"""
        # Check for explicit recommendation
        help_text = rule.get('help', {}).get('text', '')
        if help_text:
            return help_text

        # Generate based on vulnerability type
        rule_id = rule.get('id', '')
        if 'sql' in rule_id.lower():
            return "Use parameterized queries or prepared statements."
        elif 'injection' in rule_id.lower():
            return "Sanitize and validate all user input before use."
        elif 'xss' in rule_id.lower():
            return "Encode output and validate input to prevent XSS."
        elif 'crypto' in rule_id.lower():
            return "Use strong, modern cryptographic algorithms."

        return "Review the code and apply security best practices."

    def _build_references(self, rule: Dict[str, Any], properties: Dict[str, Any]) -> List[str]:
        """Build references list"""
        references = []

        # Add CWE references
        for tag in properties.get('tags', []):
            if tag.startswith('CWE-'):
                cwe_num = tag.replace('CWE-', '')
                references.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        # Add rule documentation
        rule_id = rule.get('id', '')
        if rule_id:
            references.append(f"https://codeql.github.com/codeql-query-help/{rule_id}/")

        return references