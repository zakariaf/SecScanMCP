"""
analyzers/security_tools/yara_analyzer.py
YARA analyzer - Advanced pattern matching for APTs and polymorphic malware
"""

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

    # YARA rule directories
    RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "yara"

    # Rule categories with severity mapping
    RULE_CATEGORIES = {
        'mcp_threats': {
            'severity': SeverityLevel.CRITICAL,
            'type': VulnerabilityType.TOOL_POISONING
        },
        'apt': {
            'severity': SeverityLevel.CRITICAL,
            'type': VulnerabilityType.MALWARE
        },
        'backdoor': {
            'severity': SeverityLevel.CRITICAL,
            'type': VulnerabilityType.MALWARE
        },
        'cryptominer': {
            'severity': SeverityLevel.HIGH,
            'type': VulnerabilityType.MALWARE
        },
        'ransomware': {
            'severity': SeverityLevel.CRITICAL,
            'type': VulnerabilityType.MALWARE
        },
        'webshell': {
            'severity': SeverityLevel.CRITICAL,
            'type': VulnerabilityType.MALWARE
        },
        'exploit': {
            'severity': SeverityLevel.HIGH,
            'type': VulnerabilityType.GENERIC
        },
        'suspicious': {
            'severity': SeverityLevel.MEDIUM,
            'type': VulnerabilityType.GENERIC
        }
    }

    def __init__(self):
        super().__init__()
        self._compiled_rules = {}
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._initialize_rules()

    def _initialize_rules(self):
        """Load and compile all YARA rules"""
        try:
            # Create rules directory if it doesn't exist
            self.RULES_DIR.mkdir(parents=True, exist_ok=True)

            # Load built-in rules
            self._load_builtin_rules()

            # Compile rules from files
            for rule_file in self.RULES_DIR.glob("*.yar*"):
                try:
                    namespace = rule_file.stem
                    self._compiled_rules[namespace] = yara.compile(filepath=str(rule_file))
                    logger.info(f"Loaded YARA rules: {namespace}")
                except Exception as e:
                    logger.error(f"Failed to compile YARA rule {rule_file}: {e}")

        except Exception as e:
            logger.error(f"Failed to initialize YARA rules: {e}")

    def _load_builtin_rules(self):
        """Load built-in YARA rules for MCP threats"""
        # MCP-specific threat rules
        mcp_rules = """
rule MCP_Tool_Poisoning_Attack
{
    meta:
        description = "Detects MCP tool poisoning attempts"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "mcp_threats"

    strings:
        $a1 = "ignore all previous instructions" nocase
        $a2 = "disregard all prior instructions" nocase
        $a3 = "forget everything above" nocase
        $a4 = "IMPORTANT: you must" nocase
        $a5 = "ALWAYS: execute" nocase
        $a6 = "{INSTRUCTION:" nocase
        $a7 = "{{SYSTEM:" nocase
        $a8 = "<IMPORTANT>" nocase

        $b1 = /\{[A-Z]+:.*execute.*tool.*\}/
        $b2 = /SYSTEM\s*:\s*you\s+are\s+now/

    condition:
        any of ($a*) or any of ($b*)
}

rule MCP_Hidden_Backdoor
{
    meta:
        description = "Detects hidden backdoors in MCP servers"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "backdoor"

    strings:
        $exec1 = "exec(base64.b64decode" nocase
        $exec2 = "__import__('os').system" nocase
        $exec3 = "subprocess.Popen" nocase
        $exec4 = "eval(compile(" nocase

        $trigger1 = "TRIGGER_BACKDOOR"
        $trigger2 = "SECRET_COMMAND"
        $trigger3 = /if\s+\w+\s*==\s*["'][A-Z_]{10,}["']/

        $shell1 = "shell=True"
        $shell2 = "/bin/sh"
        $shell3 = "cmd.exe"

    condition:
        (any of ($exec*) and any of ($trigger*)) or
        (any of ($exec*) and any of ($shell*))
}

rule MCP_Data_Exfiltration
{
    meta:
        description = "Detects data exfiltration patterns"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $url1 = /https?:\/\/[a-z0-9]+\.(evil|attacker|malicious)\.com/
        $url2 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/

        $exfil1 = "requests.post" nocase
        $exfil2 = "urllib.request.urlopen" nocase
        $exfil3 = "send_data_to_server" nocase

        $data1 = "stolen_data"
        $data2 = "exfiltrate"
        $data3 = "upload_results"

    condition:
        (any of ($url*) and any of ($exfil*)) or
        (any of ($exfil*) and any of ($data*))
}

rule MCP_Cryptominer
{
    meta:
        description = "Detects cryptocurrency mining code"
        author = "MCP Security Scanner"
        severity = "high"
        category = "cryptominer"

    strings:
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "pool.minexmr.com"
        $pool3 = "xmrpool.eu"

        $miner1 = "xmrig" nocase
        $miner2 = "monero" nocase
        $miner3 = "coinhive" nocase
        $miner4 = "cryptonight"

        $wallet = /[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}/

    condition:
        (any of ($pool*) and any of ($miner*)) or
        ($wallet and any of ($miner*))
}
"""

        # APT detection rules
        apt_rules = """
rule APT_Persistence_Mechanism
{
    meta:
        description = "Detects APT persistence mechanisms"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $reg1 = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"
        $reg2 = "CurrentControlSet\\\\Services"
        $reg3 = "SOFTWARE\\\\Classes\\\\CLSID"

        $sched1 = "schtasks /create"
        $sched2 = "New-ScheduledTask"

        $service1 = "sc create"
        $service2 = "New-Service"

        $wmi1 = "Win32_Process"
        $wmi2 = "EventFilter"

    condition:
        2 of them
}

rule APT_Lateral_Movement
{
    meta:
        description = "Detects lateral movement techniques"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $psexec = "psexec" nocase
        $wmic = "wmic /node:"
        $rdp = "mstsc /v:"
        $ssh = "ssh -o StrictHostKeyChecking=no"

        $mimikatz1 = "sekurlsa::logonpasswords"
        $mimikatz2 = "privilege::debug"

        $cred1 = "hashdump"
        $cred2 = "lsadump"

    condition:
        2 of them
}
"""

        # Polymorphic malware detection
        polymorphic_rules = """
rule Polymorphic_Code_Obfuscation
{
    meta:
        description = "Detects polymorphic code obfuscation"
        author = "MCP Security Scanner"
        severity = "high"
        category = "apt"

    strings:
        $enc1 = /[a-zA-Z0-9+\/]{50,}={0,2}/  // Base64 encoded block
        $enc2 = /\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/  // Hex encoded

        $obf1 = /[a-zA-Z_][a-zA-Z0-9_]{0,2}\s*=\s*[a-zA-Z_][a-zA-Z0-9_]{0,2}/
        $obf2 = /chr\(\d+\)\s*\.\s*chr\(\d+\)/

        $pack1 = "pack(" nocase
        $pack2 = "unpack(" nocase

    condition:
        (#enc1 > 3 or #enc2 > 3) and
        (#obf1 > 10 or #obf2 > 5) and
        any of ($pack*)
}

rule Polymorphic_Self_Modifying
{
    meta:
        description = "Detects self-modifying code patterns"
        author = "MCP Security Scanner"
        severity = "critical"
        category = "apt"

    strings:
        $mod1 = "mprotect" nocase
        $mod2 = "VirtualProtect" nocase
        $mod3 = "NtProtectVirtualMemory"

        $write1 = "WriteProcessMemory"
        $write2 = "ptrace" nocase

        $exec1 = "CreateRemoteThread"
        $exec2 = "RtlCreateUserThread"

    condition:
        (any of ($mod*) and any of ($write*)) or
        (any of ($mod*) and any of ($exec*))
}
"""

        # Compile built-in rules
        try:
            self._compiled_rules['mcp_builtin'] = yara.compile(source=mcp_rules)
            self._compiled_rules['apt_builtin'] = yara.compile(source=apt_rules)
            self._compiled_rules['polymorphic_builtin'] = yara.compile(source=polymorphic_rules)
            logger.info("Loaded built-in YARA rules")
        except Exception as e:
            logger.error(f"Failed to compile built-in rules: {e}")

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run YARA pattern matching analysis"""
        findings = []

        if not self._compiled_rules:
            logger.warning("No YARA rules loaded, skipping analysis")
            return findings

        try:
            # Get all files to scan
            files_to_scan = []
            for file_path in Path(repo_path).rglob('*'):
                if file_path.is_file() and not self._should_skip(file_path):
                    files_to_scan.append(file_path)

            # Scan files in parallel using thread pool
            scan_tasks = []
            for file_path in files_to_scan:
                future = self._executor.submit(self._scan_file, file_path, repo_path)
                scan_tasks.append(asyncio.wrap_future(future))

            # Gather results
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)

            for result in scan_results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"YARA scan error: {result}")

            # Deduplicate findings
            findings = self._deduplicate_findings(findings)

            logger.info(f"YARA analysis found {len(findings)} pattern matches")

        except Exception as e:
            logger.error(f"YARA analysis failed: {e}")

        return findings

    def _scan_file(self, file_path: Path, repo_path: str) -> List[Finding]:
        """Scan a single file with all YARA rules"""
        findings = []

        try:
            # Read file content
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Skip very large files
            if len(file_data) > 10 * 1024 * 1024:  # 10MB
                return findings

            # Calculate file hash for evidence
            file_hash = hashlib.sha256(file_data).hexdigest()

            # Scan with each rule set
            for namespace, rules in self._compiled_rules.items():
                try:
                    matches = rules.match(data=file_data)

                    for match in matches:
                        finding = self._create_finding_from_match(
                            match, file_path, repo_path, file_hash, namespace
                        )
                        if finding:
                            findings.append(finding)

                except Exception as e:
                    logger.debug(f"YARA match error in {file_path}: {e}")

        except Exception as e:
            logger.debug(f"Failed to scan {file_path}: {e}")

        return findings

    def _create_finding_from_match(
        self,
        match: yara.Match,
        file_path: Path,
        repo_path: str,
        file_hash: str,
        namespace: str
    ) -> Optional[Finding]:
        """Create a finding from a YARA match"""

        # Get rule metadata
        rule_name = match.rule
        meta = match.meta

        # Determine category, severity and type
        category = meta.get('category', 'suspicious')
        category_info = self.RULE_CATEGORIES.get(category, {
            'severity': SeverityLevel.MEDIUM,
            'type': VulnerabilityType.GENERIC
        })

        # Override with rule-specific severity if available
        if 'severity' in meta:
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW
            }
            severity = severity_map.get(meta['severity'], category_info['severity'])
        else:
            severity = category_info['severity']

        vuln_type = category_info['type']

        # Build description
        description = meta.get('description', f'YARA rule {rule_name} matched')

        # Collect matched strings
        matched_strings = []
        for string in match.strings:
            if hasattr(string, 'instances'):
                for instance in string.instances:
                    matched_strings.append({
                        'identifier': string.identifier,
                        'offset': instance.offset,
                        'matched': instance.matched.decode('utf-8', errors='ignore')[:100]
                    })
            else:
                # Older YARA versions
                matched_strings.append({
                    'identifier': string[1],
                    'offset': string[0],
                    'matched': string[2].decode('utf-8', errors='ignore')[:100]
                })

        # Build evidence
        evidence = {
            'rule_name': rule_name,
            'namespace': namespace,
            'file_hash': file_hash,
            'matched_strings': matched_strings[:10],  # Limit to 10 matches
            'total_matches': len(matched_strings),
            'tags': list(match.tags) if hasattr(match, 'tags') else [],
            'metadata': meta
        }

        # Determine confidence based on match quality
        confidence = 0.9  # Base confidence
        if len(matched_strings) > 5:
            confidence = 0.95
        if 'author' in meta and meta['author'] == 'MCP Security Scanner':
            confidence = 0.99

        return self.create_finding(
            vulnerability_type=vuln_type,
            severity=severity,
            confidence=confidence,
            title=f"YARA Pattern Match: {rule_name}",
            description=description,
            location=str(file_path.relative_to(repo_path)),
            recommendation=self._get_recommendation(category, rule_name),
            references=self._get_references(category, meta),
            evidence=evidence
        )

    def _get_recommendation(self, category: str, rule_name: str) -> str:
        """Get recommendation based on category"""
        recommendations = {
            'mcp_threats': "Remove or quarantine the file immediately. This appears to be an MCP-specific attack.",
            'apt': "Investigate for signs of advanced persistent threat activity. Check for additional indicators of compromise.",
            'backdoor': "Remove the backdoor code immediately and audit for unauthorized access.",
            'cryptominer': "Remove cryptocurrency mining code and check system resource usage.",
            'ransomware': "Isolate the system immediately. Do not pay ransom. Restore from clean backups.",
            'webshell': "Remove the web shell and audit web server logs for unauthorized access.",
            'exploit': "Patch the vulnerability being exploited and review security controls.",
            'suspicious': "Review the code for potential malicious behavior."
        }

        return recommendations.get(category, f"Investigate why this file matched YARA rule: {rule_name}")

    def _get_references(self, category: str, meta: Dict[str, Any]) -> List[str]:
        """Get references for the finding"""
        references = []

        # Add rule-specific references
        if 'reference' in meta:
            references.append(meta['reference'])

        # Add category-specific references
        category_refs = {
            'apt': [
                "https://attack.mitre.org/tactics/TA0003/",  # Persistence
                "https://attack.mitre.org/tactics/TA0008/"   # Lateral Movement
            ],
            'backdoor': [
                "https://attack.mitre.org/techniques/T1505/003/"  # Web Shell
            ],
            'cryptominer': [
                "https://attack.mitre.org/techniques/T1496/"  # Resource Hijacking
            ]
        }

        if category in category_refs:
            references.extend(category_refs[category])

        return references

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        # Skip git files
        if '.git' in file_path.parts:
            return True

        # Skip binary files
        skip_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico',
            '.mp3', '.mp4', '.avi', '.mov',
            '.zip', '.tar', '.gz', '.rar',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx',
            '.pyc', '.pyo', '.so', '.dll', '.dylib'
        }

        return file_path.suffix.lower() in skip_extensions

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings"""
        seen = set()
        unique_findings = []

        for finding in findings:
            # Create unique key
            key = (
                finding.vulnerability_type,
                finding.location,
                finding.evidence.get('rule_name', ''),
                finding.evidence.get('namespace', '')
            )

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        return unique_findings

    def __del__(self):
        """Clean up thread pool"""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)