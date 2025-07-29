"""
ClamAV analyzer - Enterprise malware detection engine
"""

import asyncio
import socket
import struct
import tempfile
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from io import BytesIO
import hashlib
import re

from .base import BaseAnalyzer
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class ClamAVAnalyzer(BaseAnalyzer):
    """
    Integrates ClamAV - Industry-standard malware detection engine

    Features:
    - 8+ million malware signatures
    - Detects viruses, trojans, backdoors, rootkits
    - Daily signature updates
    - TCP/Unix socket support
    - Stream scanning capability
    - Container isolation

    This analyzer provides military-grade malware detection capabilities
    """

    # ClamAV connection settings
    CLAMD_HOST = "clamav"  # Docker service name
    CLAMD_PORT = 3310
    CLAMD_TIMEOUT = 300  # 5 minutes for large files

    # Chunk size for stream scanning
    CHUNK_SIZE = 65536  # 64KB chunks
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit

    # Known malware patterns that ClamAV might miss
    ADDITIONAL_PATTERNS = [
        # MCP-specific backdoors
        {
            'pattern': rb'exec\s*\(\s*base64\.b64decode',
            'name': 'MCP.Backdoor.ExecBase64',
            'severity': SeverityLevel.CRITICAL
        },
        {
            'pattern': rb'__import__\s*\(\s*["\']os["\']\s*\)\.system',
            'name': 'MCP.Backdoor.ImportSystem',
            'severity': SeverityLevel.CRITICAL
        },
        {
            'pattern': rb'subprocess\.Popen\s*\([^)]*shell\s*=\s*True',
            'name': 'MCP.Suspicious.ShellExec',
            'severity': SeverityLevel.HIGH
        },
        # Cryptominer signatures
        {
            'pattern': rb'stratum\+tcp://|monero|xmrig|coinhive',
            'name': 'MCP.Miner.Generic',
            'severity': SeverityLevel.HIGH
        },
        # Obfuscated code patterns
        {
            'pattern': rb'eval\s*\(\s*compile\s*\(',
            'name': 'MCP.Obfuscation.EvalCompile',
            'severity': SeverityLevel.HIGH
        }
    ]

    def __init__(self):
        super().__init__()
        self._socket = None
        self._connected = False

    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """Run ClamAV malware scan on repository"""
        findings = []

        try:
            # Connect to ClamAV daemon
            await self._connect()

            # Verify ClamAV is running
            if not await self._ping():
                logger.error("ClamAV daemon is not responding")
                return findings

            # Log ClamAV version
            version = await self._get_version()
            logger.info(f"Connected to ClamAV: {version}")

            # Scan all files in repository
            scan_tasks = []
            for file_path in Path(repo_path).rglob('*'):
                if file_path.is_file() and not self._should_skip(file_path):
                    scan_tasks.append(self._scan_file(file_path, repo_path))

            # Run scans in batches to avoid overwhelming ClamAV
            batch_size = 10
            for i in range(0, len(scan_tasks), batch_size):
                batch = scan_tasks[i:i + batch_size]
                batch_results = await asyncio.gather(*batch, return_exceptions=True)

                for result in batch_results:
                    if isinstance(result, Finding):
                        findings.append(result)
                    elif isinstance(result, list):
                        findings.extend(result)
                    elif isinstance(result, Exception):
                        logger.error(f"Scan error: {result}")

            # Additional pattern matching for MCP-specific threats
            pattern_findings = await self._scan_for_patterns(repo_path)
            findings.extend(pattern_findings)

            logger.info(f"ClamAV found {len(findings)} malware/suspicious files")

        except Exception as e:
            logger.error(f"ClamAV analysis failed: {e}")

        finally:
            await self._disconnect()

        return findings

    async def _connect(self):
        """Connect to ClamAV daemon via TCP"""
        try:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.CLAMD_TIMEOUT)

            # Try to connect with retries
            max_retries = 5
            for retry in range(max_retries):
                try:
                    self._socket.connect((self.CLAMD_HOST, self.CLAMD_PORT))
                    self._connected = True
                    break
                except ConnectionRefusedError:
                    if retry < max_retries - 1:
                        logger.warning(f"ClamAV not ready, retrying in {2 ** retry} seconds...")
                        await asyncio.sleep(2 ** retry)
                    else:
                        raise

        except Exception as e:
            logger.error(f"Failed to connect to ClamAV: {e}")
            raise

    async def _disconnect(self):
        """Disconnect from ClamAV daemon"""
        if self._socket:
            try:
                self._socket.close()
            except:
                pass
            self._socket = None
            self._connected = False

    async def _send_command(self, command: str) -> str:
        """Send command to ClamAV and get response"""
        if not self._connected:
            await self._connect()

        try:
            # Commands must end with NULL byte
            self._socket.sendall(f"z{command}\0".encode())

            # Read response
            response = b""
            while True:
                chunk = self._socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\0' in response:
                    break

            return response.rstrip(b'\0').decode('utf-8', errors='ignore')

        except Exception as e:
            logger.error(f"Command failed: {e}")
            self._connected = False
            raise

    async def _ping(self) -> bool:
        """Check if ClamAV is alive"""
        try:
            response = await self._send_command("PING")
            return response == "PONG"
        except:
            return False

    async def _get_version(self) -> str:
        """Get ClamAV version"""
        try:
            return await self._send_command("VERSION")
        except:
            return "Unknown"

    async def _scan_file(self, file_path: Path, repo_path: str) -> Optional[Finding]:
        """Scan a single file for malware"""
        try:
            # Skip files over size limit
            if file_path.stat().st_size > self.MAX_FILE_SIZE:
                logger.debug(f"Skipping large file: {file_path}")
                return None

            # Calculate file hash for evidence
            file_hash = self._calculate_file_hash(file_path)

            # Use INSTREAM scanning for better performance
            with open(file_path, 'rb') as f:
                result = await self._scan_stream(f, str(file_path))

            if result and result[0] == 'FOUND':
                malware_name = result[1]

                # Determine severity based on malware type
                severity = self._determine_severity(malware_name)

                return self.create_finding(
                    vulnerability_type=VulnerabilityType.MALWARE,
                    severity=severity,
                    confidence=0.99,  # ClamAV has very low false positive rate
                    title=f"Malware Detected: {malware_name}",
                    description=f"ClamAV detected malware signature '{malware_name}' in file",
                    location=str(file_path.relative_to(repo_path)),
                    recommendation="Remove or quarantine the infected file immediately. Scan entire system for additional infections.",
                    references=[
                        "https://www.clamav.net/documents/clamav-virus-database-faq",
                        f"https://www.virustotal.com/gui/file/{file_hash}"
                    ],
                    evidence={
                        'malware_name': malware_name,
                        'file_hash': file_hash,
                        'file_size': file_path.stat().st_size,
                        'detection_engine': 'ClamAV',
                        'signature_version': await self._get_version()
                    }
                )

        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")

        return None

    async def _scan_stream(self, stream, filename: str) -> Optional[Tuple[str, str]]:
        """Scan a file stream using INSTREAM protocol"""
        try:
            # Send INSTREAM command
            self._socket.sendall(b"zINSTREAM\0")

            # Send file data in chunks
            while True:
                chunk = stream.read(self.CHUNK_SIZE)
                if not chunk:
                    break

                # Send chunk size (network byte order) + chunk data
                size = struct.pack('!L', len(chunk))
                self._socket.sendall(size + chunk)

            # Send termination sequence (zero-length chunk)
            self._socket.sendall(struct.pack('!L', 0))

            # Read response
            response = b""
            while True:
                chunk = self._socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b'\0' in response:
                    break

            result = response.rstrip(b'\0').decode('utf-8', errors='ignore')

            # Parse result
            if "FOUND" in result:
                # Format: "stream: Malware.Name FOUND"
                parts = result.split(':', 1)
                if len(parts) > 1:
                    malware_info = parts[1].strip()
                    if ' FOUND' in malware_info:
                        malware_name = malware_info.replace(' FOUND', '')
                        return ('FOUND', malware_name)

            return None

        except Exception as e:
            logger.error(f"Stream scan failed for {filename}: {e}")
            return None

    async def _scan_for_patterns(self, repo_path: str) -> List[Finding]:
        """Scan for additional malware patterns that ClamAV might miss"""
        findings = []

        for file_path in Path(repo_path).rglob('*'):
            if file_path.is_file() and file_path.suffix in ['.py', '.js', '.sh', '.bat', '.ps1']:
                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()

                    for pattern_info in self.ADDITIONAL_PATTERNS:
                        if re.search(pattern_info['pattern'], content):
                            findings.append(self.create_finding(
                                vulnerability_type=VulnerabilityType.MALWARE,
                                severity=pattern_info['severity'],
                                confidence=0.8,
                                title=f"Suspicious Pattern: {pattern_info['name']}",
                                description=f"Detected suspicious pattern that matches {pattern_info['name']} signature",
                                location=str(file_path.relative_to(repo_path)),
                                recommendation="Review the code for potential malicious behavior",
                                evidence={
                                    'pattern_name': pattern_info['name'],
                                    'file_type': file_path.suffix,
                                    'detection_method': 'pattern_matching'
                                }
                            ))
                            break

                except Exception as e:
                    logger.debug(f"Failed to scan patterns in {file_path}: {e}")

        return findings

    def _should_skip(self, file_path: Path) -> bool:
        """Check if file should be skipped"""
        # Skip git files
        if '.git' in file_path.parts:
            return True

        # Skip known safe file types
        skip_extensions = {
            '.md', '.txt', '.rst', '.yml', '.yaml', '.json',
            '.gitignore', '.dockerignore', '.editorconfig'
        }

        return file_path.suffix.lower() in skip_extensions

    def _calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except:
            return "unknown"

    def _determine_severity(self, malware_name: str) -> SeverityLevel:
        """Determine severity based on malware type"""
        malware_lower = malware_name.lower()

        # Critical threats
        critical_indicators = [
            'ransomware', 'rootkit', 'backdoor', 'trojan',
            'keylogger', 'rat', 'botnet', 'worm'
        ]

        for indicator in critical_indicators:
            if indicator in malware_lower:
                return SeverityLevel.CRITICAL

        # High severity
        high_indicators = [
            'virus', 'malware', 'exploit', 'dropper',
            'downloader', 'stealer', 'spyware'
        ]

        for indicator in high_indicators:
            if indicator in malware_lower:
                return SeverityLevel.HIGH

        # Medium severity
        medium_indicators = [
            'adware', 'pua', 'pup', 'riskware',
            'hacktools', 'greyware'
        ]

        for indicator in medium_indicators:
            if indicator in malware_lower:
                return SeverityLevel.MEDIUM

        # Default to high for unknown malware
        return SeverityLevel.HIGH