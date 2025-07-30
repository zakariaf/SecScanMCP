import os
import asyncio
import yara
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import hashlib
import base64
import re

from analyzers.base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class YARAAnalyzer(BaseAnalyzer):
    """
    Integrates YARA - Advanced pattern matching engine

    Features:
    - Complex pattern matching with wildcards and regex
    - APT (Advanced Persistent Threat) detection
    - Polymorphic malware detection
    - MCP-specific threat patterns
    - Custom rule compilation
    - High-performance scanning

    Used by threat intelligence teams and malware researchers globally
    """


    # Fix: Use absolute path for rules directory
    RULES_DIR = Path("/app/rules/yara")
    MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB limit
    SCAN_TIMEOUT = 30  # seconds per file

    def __init__(self):
        super().__init__()
        self.rules = None
        self._load_rules()

    def _load_rules(self):
        """Load all YARA rules from rules directory"""
        try:
            rules_path = self.RULES_DIR

            # Check if rules directory exists
            if not rules_path.exists():
                self.logger.warning(f"YARA rules directory not found at {rules_path}")
                # Try alternative paths
                alt_paths = [
                    Path("/app/rules/yara"),
                    Path("./rules/yara"),
                    Path(os.path.join(os.path.dirname(__file__), "../../rules/yara"))
                ]
                for alt_path in alt_paths:
                    if alt_path.exists():
                        rules_path = alt_path
                        self.logger.info(f"Found YARA rules at {rules_path}")
                        break
                else:
                    self.logger.error("No YARA rules directory found")
                    return

            # Compile all .yar files
            rule_files = list(rules_path.glob("*.yar"))
            if not rule_files:
                self.logger.warning(f"No .yar files found in {rules_path}")
                return

            # Compile rules
            rules_dict = {}
            for rule_file in rule_files:
                try:
                    # Use absolute path for rule file
                    rule_path = str(rule_file.absolute())
                    self.logger.info(f"Loading YARA rule: {rule_path}")
                    rules_dict[rule_file.stem] = rule_path
                except Exception as e:
                    self.logger.error(f"Failed to load rule {rule_file}: {e}")

            if rules_dict:
                self.rules = yara.compile(filepaths=rules_dict)
                self.logger.info(f"Successfully loaded {len(rules_dict)} YARA rules")
            else:
                self.logger.warning("No YARA rules compiled successfully")

        except Exception as e:
            self.logger.error(f"Failed to load YARA rules: {e}")
            self.rules = None

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Analyze repository with YARA rules"""
        if not self.rules:
            self.logger.warning("No YARA rules loaded, skipping analysis")
            return []

        findings = []
        repo_path = Path(repo_path)

        try:
            # Scan all files in repository
            with ThreadPoolExecutor(max_workers=4) as executor:
                tasks = []
                for file_path in repo_path.rglob("*"):
                    if file_path.is_file() and not self._should_skip_file(file_path):
                        tasks.append(
                            executor.submit(self._scan_file, file_path, repo_path)
                        )

                # Wait for all scans to complete with timeout
                for future in asyncio.as_completed(
                    [asyncio.wrap_future(f) for f in tasks],
                    timeout=300  # 5 minutes total timeout
                ):
                    try:
                        result = await future
                        if result:
                            findings.extend(result)
                    except asyncio.TimeoutError:
                        self.logger.warning("YARA scan timeout reached")
                        break
                    except Exception as e:
                        self.logger.error(f"Error in YARA scan: {e}")

            self.logger.info(f"YARA analysis found {len(findings)} issues")

        except Exception as e:
            self.logger.error(f"YARA analysis failed: {e}")

        return findings

    def _scan_file(self, file_path: Path, repo_root: Path) -> List[Finding]:
        """Scan a single file with YARA rules"""
        findings = []

        try:
            # Check file size
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                return findings

            # Scan file
            matches = self.rules.match(
                str(file_path),
                timeout=self.SCAN_TIMEOUT
            )

            # Convert matches to findings
            for match in matches:
                finding = self._convert_match_to_finding(match, file_path, repo_root)
                if finding:
                    findings.append(finding)

        except yara.TimeoutError:
            self.logger.warning(f"YARA scan timeout for {file_path}")
        except Exception as e:
            self.logger.debug(f"Error scanning {file_path}: {e}")

        return findings

    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if file should be skipped"""
        skip_extensions = {
            '.pyc', '.pyo', '.so', '.dll', '.dylib',
            '.jpg', '.jpeg', '.png', '.gif', '.ico',
            '.mp3', '.mp4', '.avi', '.mov',
            '.zip', '.tar', '.gz', '.rar'
        }

        skip_dirs = {
            '.git', '__pycache__', 'node_modules',
            '.venv', 'venv', 'env', '.env'
        }

        # Skip by extension
        if file_path.suffix.lower() in skip_extensions:
            return True

        # Skip if in excluded directory
        for parent in file_path.parents:
            if parent.name in skip_dirs:
                return True

        return False

    def _convert_match_to_finding(self, match: Any, file_path: Path, repo_root: Path) -> Optional[Finding]:
        """Convert YARA match to Finding"""
        try:
            # Get relative path
            try:
                relative_path = file_path.relative_to(repo_root)
            except ValueError:
                relative_path = file_path

            # Extract metadata from rule
            meta = match.meta
            severity = self._determine_severity(meta)

            # Build description
            description = meta.get('description', f'YARA rule {match.rule} matched')
            if 'details' in meta:
                description += f"\n\nDetails: {meta['details']}"

            # Extract matched strings
            matched_strings = []
            for s in match.strings:
                if isinstance(s, tuple):
                    # pre-4.3: (<offset>, <identifier>, <data>)
                    offset, identifier, data = s
                else:
                    # post-4.3: yara.StringMatch
                    identifier = s.identifier

                    # pull the first instance, if any
                    if s.instances:
                        inst   = s.instances[0]
                        offset = inst.offset
                        data   = inst.matched_data
                    else:
                        offset = None
                        data   = None

                # truncate to 100 bytes/characters
                content = data[:100] if data else ''
                matched_strings.append({
                    'offset':     offset,
                    'identifier': identifier,
                    'content':    content,
                })

            return self.create_finding(
                vulnerability_type=self._determine_vuln_type(meta),
                severity=severity,
                confidence=float(meta.get('confidence', 0.8)),
                title=f"YARA Detection: {match.rule}",
                description=description,
                location=str(relative_path),
                recommendation=meta.get('recommendation', 'Review the detected pattern and take appropriate action'),
                references=self._extract_references(meta),
                evidence={
                    'rule': match.rule,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': dict(meta),
                    'matched_strings': matched_strings[:10]  # Limit to 10 matches
                }
            )

        except Exception as e:
            self.logger.error(f"Failed to convert YARA match: {e}")
            return None

    def _determine_severity(self, meta: Dict[str, Any]) -> SeverityLevel:
        """Determine severity from rule metadata"""
        severity_str = meta.get('severity', 'medium').lower()

        severity_map = {
            'critical': SeverityLevel.CRITICAL,
            'high': SeverityLevel.HIGH,
            'medium': SeverityLevel.MEDIUM,
            'low': SeverityLevel.LOW,
            'info': SeverityLevel.INFO
        }

        return severity_map.get(severity_str, SeverityLevel.MEDIUM)

    def _determine_vuln_type(self, meta: Dict[str, Any]) -> VulnerabilityType:
        """Determine vulnerability type from rule metadata"""
        category = meta.get('category', '').lower()

        type_map = {
            'malware': VulnerabilityType.MALWARE,
            'backdoor': VulnerabilityType.BACKDOOR,
            'trojan': VulnerabilityType.BACKDOOR,
            'injection': VulnerabilityType.COMMAND_INJECTION,
            'sql_injection': VulnerabilityType.SQL_INJECTION,
            'xss': VulnerabilityType.XSS,
            'credential': VulnerabilityType.HARDCODED_SECRET,
            'secret': VulnerabilityType.HARDCODED_SECRET,
            'crypto': VulnerabilityType.WEAK_CRYPTO,
            'permission': VulnerabilityType.PRIVILEGE_ESCALATION,
            'path_traversal': VulnerabilityType.PATH_TRAVERSAL,
            'mcp_threats': VulnerabilityType.MCP_SPECIFIC,
            'prompt_injection': VulnerabilityType.PROMPT_INJECTION,
            'tool_manipulation': VulnerabilityType.TOOL_MANIPULATION
        }

        return type_map.get(category, VulnerabilityType.GENERIC)

    def _extract_references(self, meta: Dict[str, Any]) -> List[str]:
        """Extract references from rule metadata"""
        references = []

        # Add author info if available
        if 'author' in meta:
            references.append(f"Rule author: {meta['author']}")

        # Add any URLs in metadata
        for key, value in meta.items():
            if isinstance(value, str) and value.startswith(('http://', 'https://')):
                references.append(value)

        return references