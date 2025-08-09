"""
ClamAV Scanning Service

Handles file scanning operations with batch processing
Following clean architecture with single responsibility
"""

import asyncio
import struct
import socket
import logging
import hashlib
from pathlib import Path
from typing import List, Optional, Tuple
from io import BytesIO

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class ScanningService:
    """Handles ClamAV file scanning operations"""
    
    # Chunk size for stream scanning
    CHUNK_SIZE = 65536  # 64KB chunks
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
    
    def __init__(self, connection_service):
        self.connection_service = connection_service
    
    async def scan_repository(self, repo_path: str) -> List[Finding]:
        """Scan all files in repository for malware"""
        findings: List[Finding] = []
        
        # Collect all files to scan
        scan_tasks = []
        for file_path in Path(repo_path).rglob('*'):
            if file_path.is_file() and not self._should_skip(file_path):
                scan_tasks.append(self._scan_file(file_path, repo_path))
        
        # Run scans in batches to avoid overwhelming ClamAV
        batch_size = 10
        for i in range(0, len(scan_tasks), batch_size):
            batch = scan_tasks[i:i + batch_size]
            batch_results = await asyncio.gather(*batch, return_exceptions=True)
            
            findings.extend(self._process_batch_results(batch_results))
        
        return findings
    
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
                return self._create_malware_finding(
                    file_path, repo_path, result[1], file_hash
                )
                
        except Exception as e:
            logger.error(f"Failed to scan {file_path}: {e}")
        
        return None
    
    async def _scan_stream(self, stream, filename: str) -> Optional[Tuple[str, str]]:
        """Scan a file stream using INSTREAM protocol"""
        try:
            # Open fresh connection per file
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.connection_service.CLAMD_TIMEOUT)
            sock.connect((
                self.connection_service.CLAMD_HOST,
                self.connection_service.CLAMD_PORT
            ))
            
            try:
                return await self._perform_stream_scan(sock, stream)
            finally:
                sock.close()
                
        except Exception as e:
            logger.error(f"Stream scan failed for {filename}: {e}")
            return None
    
    async def _perform_stream_scan(self, sock, stream) -> Optional[Tuple[str, str]]:
        """Perform the actual stream scanning protocol"""
        sock.sendall(b"zINSTREAM\0")
        
        # Send file data in chunks
        while True:
            chunk = stream.read(self.CHUNK_SIZE)
            if not chunk:
                break
            size = struct.pack('!L', len(chunk))
            sock.sendall(size + chunk)
        
        # Send end-of-stream marker
        sock.sendall(struct.pack('!L', 0))
        
        # Receive response
        response = self._receive_response(sock)
        return self._parse_scan_result(response)
    
    def _receive_response(self, sock) -> str:
        """Receive complete response from ClamAV"""
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            if b'\0' in response:
                break
        
        return response.rstrip(b'\0').decode('utf-8', errors='ignore')
    
    def _parse_scan_result(self, result: str) -> Optional[Tuple[str, str]]:
        """Parse ClamAV scan result"""
        if "FOUND" in result:
            # Format: "stream: Malware.Name FOUND"
            parts = result.split(':', 1)
            if len(parts) > 1:
                malware_info = parts[1].strip()
                if ' FOUND' in malware_info:
                    malware_name = malware_info.replace(' FOUND', '')
                    return ('FOUND', malware_name)
        
        return None
    
    def _create_malware_finding(self, file_path: Path, repo_path: str, 
                               malware_name: str, file_hash: str) -> Finding:
        """Create Finding object for detected malware"""
        severity = self._determine_severity(malware_name)
        
        # Import here to avoid circular import
        from analyzers.base import BaseAnalyzer
        base = BaseAnalyzer()
        
        return base.create_finding(
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
                'detection_engine': 'ClamAV'
            }
        )
    
    def _process_batch_results(self, batch_results: List) -> List[Finding]:
        """Process batch scanning results"""
        findings = []
        
        for result in batch_results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, list):
                findings.extend(result)
            elif isinstance(result, Exception):
                logger.error(f"Scan error: {result}")
        
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
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return "unknown"
    
    def _determine_severity(self, malware_name: str) -> SeverityLevel:
        """Determine severity based on malware type"""
        name_lower = malware_name.lower()
        
        # Critical threats
        critical_indicators = ['trojan', 'backdoor', 'rootkit', 'ransomware', 'keylogger']
        if any(indicator in name_lower for indicator in critical_indicators):
            return SeverityLevel.CRITICAL
        
        # High severity threats  
        high_indicators = ['virus', 'worm', 'exploit', 'malware']
        if any(indicator in name_lower for indicator in high_indicators):
            return SeverityLevel.HIGH
        
        # Medium severity
        medium_indicators = ['adware', 'spyware', 'pup', 'suspicious']
        if any(indicator in name_lower for indicator in medium_indicators):
            return SeverityLevel.MEDIUM
        
        # Default to high for unknown malware
        return SeverityLevel.HIGH