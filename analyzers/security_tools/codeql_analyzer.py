"""
analyzers/security_tools/codeql_analyzer.py
CodeQL analyzer - Semantic code analysis for complex vulnerabilities
"""

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
    """
    Integrates CodeQL - GitHub's semantic code analysis engine

    Features:
    - Deep semantic analysis treating code as data
    - Finds complex vulnerabilities that patterns miss
    - Data flow and taint tracking
    - Control flow analysis
    - Industry gold standard for code security
    - Custom query support

    Used by GitHub for security scanning
    """

    # CodeQL CLI location in container
    CODEQL_CLI = "/opt/codeql/codeql"

    # Supported languages and their identifiers
    LANGUAGE_MAP = {
        'python': 'python',
        'javascript': 'javascript',
        'typescript': 'javascript',  # Uses same extractor
        'java': 'java',
        'kotlin': 'java',  # Uses same extractor
        'go': 'go',
        'cpp': 'cpp',
        'c': 'cpp',  # Uses same extractor
        'csharp': 'csharp',
        'ruby': 'ruby'
    }

    # Query suites to run
    QUERY_SUITES = {
        'security-extended': 'Security vulnerabilities with extended coverage',
        'security-and-quality': 'Security and code quality issues'
    }

    # Severity mapping from CodeQL to our model
    SEVERITY_MAP = {
        'error': SeverityLevel.CRITICAL,
        'warning': SeverityLevel.HIGH,
        'recommendation': SeverityLevel.MEDIUM,
        'note': SeverityLevel.LOW
    }

    # Vulnerability type mapping
    VULN_TYPE_MAP = {
        'Command injection': VulnerabilityType.COMMAND_INJECTION,
        'SQL injection': VulnerabilityType.SQL_INJECTION,
        'Path injection': VulnerabilityType.PATH_TRAVERSAL,
        'XSS': VulnerabilityType.GENERIC,
        'XXE': VulnerabilityType.XXE,
        'SSRF': VulnerabilityType.SSRF,
        'Injection': VulnerabilityType.GENERIC,
        'Security': VulnerabilityType.GENERIC
    }

    def __init__(self):
        super().__init__()
        self._codeql_available = self._check_codeql_availability()

    def _check_codeql_availability(self) -> bool:
        """Check if CodeQL CLI is available"""
        try:
            result = subprocess.run(
                [self.CODEQL_CLI, "version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                logger.info(f"CodeQL available: {result.stdout.strip()}")
                return True
        except Exception as e:
            logger.warning(f"CodeQL not available: {e}")
        return False

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run CodeQL semantic analysis"""
        findings = []

        if not self._codeql_available:
            logger.warning("CodeQL not available, skipping analysis")
            return findings

        # Determine language
        language = self._detect_language(repo_path, project_info)
        if not language:
            logger.info("No supported language detected for CodeQL")
            return findings

        codeql_language = self.LANGUAGE_MAP.get(language)
        if not codeql_language:
            logger.info(f"Language {language} not supported by CodeQL")
            return findings

        try:
            # Create temporary directory for CodeQL database
            with tempfile.TemporaryDirectory() as temp_dir:
                db_path = Path(temp_dir) / "codeql-db"
                sarif_path = Path(temp_dir) / "results.sarif"

                # Create CodeQL database
                logger.info(f"Creating CodeQL database for {codeql_language}")
                if not await self._create_database(repo_path, db_path, codeql_language):
                    return findings

                # Run security analysis
                logger.info("Running CodeQL security analysis")
                if not await self._analyze_database(db_path, sarif_path, codeql_language):
                    return findings

                # Parse SARIF results
                findings = self._parse_sarif_results(sarif_path, repo_path)

                logger.info(f"CodeQL found {len(findings)} vulnerabilities")

        except Exception as e:
            logger.error(f"CodeQL analysis failed: {e}")

        return findings

    def _detect_language(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[str]:
        """Detect primary language of the repository"""
        # First check project info
        if 'language' in project_info:
            return project_info['language'].lower()

        # Count files by extension
        language_counts = {}
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.kt': 'kotlin',
            '.go': 'go',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.c': 'c',
            '.h': 'c',
            '.cs': 'csharp',
            '.rb': 'ruby'
        }

        for file_path in Path(repo_path).rglob('*'):
            if file_path.is_file():
                ext = file_path.suffix.lower()
                if ext in extension_map:
                    lang = extension_map[ext]
                    language_counts[lang] = language_counts.get(lang, 0) + 1

        # Return most common language
        if language_counts:
            return max(language_counts, key=language_counts.get)

        return None

    async def _create_database(self, source_path: str, db_path: Path, language: str) -> bool:
        """Create CodeQL database"""
        try:
            # Prepare command based on language
            cmd = [
                self.CODEQL_CLI,
                "database", "create",
                str(db_path),
                f"--language={language}",
                f"--source-root={source_path}",
                "--threads=2"
            ]

            # Add build command for compiled languages
            if language in ['java', 'cpp', 'csharp', 'go']:
                # Try to detect build system
                build_cmd = self._detect_build_command(source_path, language)
                if build_cmd:
                    cmd.extend(["--command", build_cmd])

            # Run database creation
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                logger.error(f"Database creation failed: {stderr.decode()}")
                return False

            return True

        except Exception as e:
            logger.error(f"Failed to create CodeQL database: {e}")
            return False

    def _detect_build_command(self, source_path: str, language: str) -> Optional[str]:
        """Detect build command for compiled languages"""
        path = Path(source_path)

        # Java/Kotlin
        if language == 'java':
            if (path / 'pom.xml').exists():
                return 'mvn compile'
            elif (path / 'build.gradle').exists() or (path / 'build.gradle.kts').exists():
                return 'gradle build'
            elif (path / 'build.xml').exists():
                return 'ant compile'

        # Go
        elif language == 'go':
            if (path / 'go.mod').exists():
                return 'go build ./...'

        # C/C++
        elif language == 'cpp':
            if (path / 'Makefile').exists():
                return 'make'
            elif (path / 'CMakeLists.txt').exists():
                return 'cmake . && make'

        # C#
        elif language == 'csharp':
            if list(path.glob('*.csproj')):
                return 'dotnet build'
            elif list(path.glob('*.sln')):
                return 'msbuild'

        return None

    async def _analyze_database(self, db_path: Path, output_path: Path, language: str) -> bool:
        """Analyze CodeQL database with security queries"""
        try:
            # Use security-extended suite for comprehensive coverage
            query_suite = f"{language}-security-extended.qls"

            cmd = [
                self.CODEQL_CLI,
                "database", "analyze",
                str(db_path),
                query_suite,
                f"--format=sarif-latest",
                f"--output={output_path}",
                "--threads=2"
            ]

            # Run analysis
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                # Try with basic security queries if extended fails
                if "security-extended" in stderr.decode():
                    logger.warning("Extended queries failed, trying basic security suite")
                    query_suite = f"{language}-security-and-quality.qls"
                    cmd[3] = query_suite

                    process = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )

                    stdout, stderr = await process.communicate()

                    if process.returncode != 0:
                        logger.error(f"Analysis failed: {stderr.decode()}")
                        return False
                else:
                    logger.error(f"Analysis failed: {stderr.decode()}")
                    return False

            return True

        except Exception as e:
            logger.error(f"Failed to analyze database: {e}")
            return False

    def _parse_sarif_results(self, sarif_path: Path, repo_path: str) -> List[Finding]:
        """Parse SARIF results into findings"""
        findings = []

        try:
            with open(sarif_path, 'r') as f:
                sarif_data = json.load(f)

            # Extract runs
            for run in sarif_data.get('runs', []):
                # Get rules mapping
                rules_map = {}
                for rule in run.get('tool', {}).get('driver', {}).get('rules', []):
                    rules_map[rule['id']] = rule

                # Process results
                for result in run.get('results', []):
                    finding = self._create_finding_from_result(
                        result, rules_map, repo_path
                    )
                    if finding:
                        findings.append(finding)

        except Exception as e:
            logger.error(f"Failed to parse SARIF results: {e}")

        return findings

    def _create_finding_from_result(
        self,
        result: Dict[str, Any],
        rules_map: Dict[str, Any],
        repo_path: str
    ) -> Optional[Finding]:
        """Create finding from SARIF result"""
        try:
            # Get rule details
            rule_id = result.get('ruleId', '')
            rule = rules_map.get(rule_id, {})

            # Extract basic information
            message = result.get('message', {}).get('text', 'Unknown vulnerability')
            level = result.get('level', 'warning')

            # Get location
            locations = result.get('locations', [])
            if not locations:
                return None

            physical_location = locations[0].get('physicalLocation', {})
            artifact_location = physical_location.get('artifactLocation', {})
            region = physical_location.get('region', {})

            # Build file path
            uri = artifact_location.get('uri', '')
            if uri.startswith('file://'):
                uri = uri[7:]

            # Make path relative to repo
            try:
                file_path = Path(uri).relative_to(Path(repo_path))
            except:
                file_path = Path(uri)

            # Get line information
            start_line = region.get('startLine', 0)
            end_line = region.get('endLine', start_line)

            # Determine severity
            severity = self.SEVERITY_MAP.get(level, SeverityLevel.MEDIUM)

            # Determine vulnerability type
            vuln_type = self._determine_vuln_type(rule, message)

            # Build location string
            location = str(file_path)
            if start_line:
                location += f":{start_line}"
                if end_line != start_line:
                    location += f"-{end_line}"

            # Get additional metadata
            properties = rule.get('properties', {})
            tags = properties.get('tags', [])
            precision = properties.get('precision', 'medium')

            # Calculate confidence based on precision
            confidence_map = {
                'very-high': 0.95,
                'high': 0.90,
                'medium': 0.80,
                'low': 0.70
            }
            confidence = confidence_map.get(precision, 0.80)

            # Build evidence
            evidence = {
                'rule_id': rule_id,
                'query_name': rule.get('name', rule_id),
                'query_description': rule.get('shortDescription', {}).get('text', ''),
                'precision': precision,
                'tags': tags,
                'cwe': self._extract_cwe(properties),
                'data_flow': self._extract_data_flow(result)
            }

            # Get recommendations
            help_text = rule.get('help', {}).get('text', '')
            recommendation = self._extract_recommendation(help_text)

            # Get references
            references = self._build_references(rule, properties)

            return self.create_finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=confidence,
                title=f"CodeQL: {rule.get('name', rule_id)}",
                description=message,
                location=location,
                recommendation=recommendation,
                references=references,
                evidence=evidence
            )

        except Exception as e:
            logger.error(f"Failed to create finding: {e}")
            return None

    def _determine_vuln_type(self, rule: Dict[str, Any], message: str) -> VulnerabilityType:
        """Determine vulnerability type from rule and message"""
        # Check rule name and tags
        rule_name = rule.get('name', '').lower()
        tags = rule.get('properties', {}).get('tags', [])

        # Check for specific vulnerability types
        for pattern, vuln_type in self.VULN_TYPE_MAP.items():
            if pattern.lower() in rule_name or pattern.lower() in message.lower():
                return vuln_type

        # Check tags
        if 'injection' in tags:
            return VulnerabilityType.GENERIC
        elif 'security' in tags:
            return VulnerabilityType.GENERIC

        return VulnerabilityType.GENERIC

    def _extract_cwe(self, properties: Dict[str, Any]) -> List[str]:
        """Extract CWE identifiers"""
        cwe_list = []

        # Check for CWE in tags
        for tag in properties.get('tags', []):
            if tag.startswith('cwe-'):
                cwe_list.append(tag.upper())

        return cwe_list

    def _extract_data_flow(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data flow information"""
        data_flow = {}

        # Check for code flows
        code_flows = result.get('codeFlows', [])
        if code_flows:
            flow = code_flows[0]  # Take first flow
            thread_flows = flow.get('threadFlows', [])
            if thread_flows:
                locations = thread_flows[0].get('locations', [])
                data_flow['steps'] = len(locations)
                data_flow['source'] = self._get_flow_location(locations[0]) if locations else None
                data_flow['sink'] = self._get_flow_location(locations[-1]) if locations else None

        return data_flow

    def _get_flow_location(self, location: Dict[str, Any]) -> str:
        """Get readable location from flow step"""
        physical = location.get('location', {}).get('physicalLocation', {})
        uri = physical.get('artifactLocation', {}).get('uri', 'unknown')
        line = physical.get('region', {}).get('startLine', 0)
        return f"{Path(uri).name}:{line}"

    def _extract_recommendation(self, help_text: str) -> str:
        """Extract recommendation from help text"""
        # Try to find recommendation section
        if 'Recommendation' in help_text:
            parts = help_text.split('Recommendation')
            if len(parts) > 1:
                return parts[1].strip().split('\n')[0]

        # Default recommendations based on common patterns
        if 'injection' in help_text.lower():
            return "Validate and sanitize all user input. Use parameterized queries or prepared statements."
        elif 'encryption' in help_text.lower():
            return "Use strong encryption algorithms and secure key management practices."
        elif 'authentication' in help_text.lower():
            return "Implement proper authentication and authorization checks."

        return "Review the code and apply security best practices for this vulnerability type."

    def _build_references(self, rule: Dict[str, Any], properties: Dict[str, Any]) -> List[str]:
        """Build references list"""
        references = []

        # Add CWE references
        for cwe in self._extract_cwe(properties):
            cwe_num = cwe.replace('CWE-', '')
            references.append(f"https://cwe.mitre.org/data/definitions/{cwe_num}.html")

        # Add rule documentation
        rule_id = rule.get('id', '')
        if rule_id:
            references.append(f"https://codeql.github.com/codeql-query-help/{rule_id}/")

        # Add OWASP reference if applicable
        tags = properties.get('tags', [])
        if 'injection' in tags:
            references.append("https://owasp.org/www-community/Injection_Theory")

        return references