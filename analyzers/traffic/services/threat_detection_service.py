"""Threat detection service for network traffic analysis."""

import re
import logging
from typing import Dict, List, Any, Set

logger = logging.getLogger(__name__)


class ThreatDetectionService:
    """Detects threats in network traffic patterns."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.suspicious_domains = set()
        self._initialize_patterns()
    
    def _initialize_patterns(self):
        """Initialize threat detection patterns."""
        # Suspicious domain patterns
        self.suspicious_domain_patterns = [
            r'.*\.tk$',  # Free TLD often used by attackers
            r'.*\.ml$',  # Free TLD
            r'.*\.ga$',  # Free TLD
            r'.*\.cf$',  # Free TLD
            r'.*pastebin\.com.*',  # Data sharing sites
            r'.*paste\.ee.*',
            r'.*hastebin\.com.*',
            r'.*discord\.com/api/webhooks.*',  # Discord webhooks
            r'.*telegram\.org/bot.*',  # Telegram bots
            r'.*ngrok\.io.*',  # Tunneling services
            r'.*serveo\.net.*',
            r'.*localhost\.run.*',
            r'.*tunnel\.to.*',
            r'.*attacker\..*',  # Obvious attack domains
            r'.*evil\..*',
            r'.*malicious\..*',
            r'.*exfil\..*',
            r'.*c2\..*',  # Command and control
        ]
        
        # Network command patterns
        self.exfiltration_commands = [
            r'curl.*-d.*',  # POST with data
            r'wget.*--post.*',  # POST with wget
            r'nc.*-e.*',  # Netcat with command execution
            r'socat.*exec.*',  # Socat with execution
            r'ssh.*-R.*',  # SSH reverse tunnel
            r'python.*-c.*urllib.*',  # Python HTTP requests
            r'python.*-c.*requests.*',  # Python requests library
            r'python.*-c.*socket.*',  # Python socket connections
        ]
    
    def analyze_connection(self, connection: Dict[str, Any]) -> bool:
        """Analyze network connection for threats."""
        try:
            foreign_addr = connection.get('foreign_address', '')
            
            if self._is_suspicious_destination(foreign_addr):
                self.logger.warning(f"Suspicious connection: {foreign_addr}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Connection analysis error: {e}")
            return False
    
    def analyze_dns_query(self, query: Dict[str, Any]) -> bool:
        """Analyze DNS query for threats."""
        try:
            query_line = query.get('query', '')
            
            if self._is_suspicious_dns(query_line):
                self.logger.warning(f"Suspicious DNS: {query_line}")
                return True
            
            if self._detect_dns_tunneling(query_line):
                self.logger.warning(f"DNS tunneling detected: {query_line}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"DNS analysis error: {e}")
            return False
    
    def analyze_network_process(self, process: Dict[str, Any]) -> bool:
        """Analyze network process for threats."""
        try:
            command = process.get('command', '')
            
            if self._is_suspicious_network_process(command):
                self.logger.warning(f"Suspicious process: {command}")
                return True
            
            exfil_data = self._detect_exfiltration_commands(command)
            if exfil_data:
                self.logger.warning(f"Exfiltration command: {exfil_data}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Process analysis error: {e}")
            return False
    
    def analyze_file_operation(self, operation: Dict[str, Any]) -> bool:
        """Analyze file operation for threats."""
        try:
            name = operation.get('name', '')
            command = operation.get('command', '')
            
            if self._is_suspicious_file_operation(name):
                self.logger.warning(f"Suspicious file op: {name}")
                return True
            
            if self._is_data_staging_operation(name):
                self.logger.warning(f"Data staging: {name}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"File operation analysis error: {e}")
            return False
    
    def _is_suspicious_destination(self, destination: str) -> bool:
        """Check if destination is suspicious."""
        for pattern in self.suspicious_domain_patterns:
            if re.match(pattern, destination, re.IGNORECASE):
                return True
        return False
    
    def _is_suspicious_dns(self, query: str) -> bool:
        """Check if DNS query is suspicious."""
        # Look for suspicious domains in DNS traffic
        for pattern in self.suspicious_domain_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
        
        # Check for DNS tunneling indicators
        if len(query) > 200:  # Unusually long DNS queries
            return True
        
        return False
    
    def _is_suspicious_network_process(self, command: str) -> bool:
        """Check if network process command is suspicious."""
        suspicious_indicators = [
            'nc -e',  # Netcat with execution
            'socat',  # Socat connections
            '/dev/tcp/',  # Bash TCP connections
            'python -c',  # Python one-liners
            'perl -e',  # Perl one-liners
            'ruby -e',  # Ruby one-liners
            'curl -d',  # POST requests
            'wget --post',  # POST with wget
        ]
        
        return any(indicator in command.lower() for indicator in suspicious_indicators)
    
    def _is_suspicious_file_operation(self, operation: str) -> bool:
        """Check if file operation is suspicious."""
        suspicious_patterns = [
            r'/tmp/.*\.sh',  # Temporary scripts
            r'/tmp/.*\.py',  # Temporary Python scripts
            r'/dev/tcp/',  # TCP file descriptors
            r'/proc/.*/fd/',  # Process file descriptors
            r'\.ssh/',  # SSH-related files
        ]
        
        return any(re.search(pattern, operation) for pattern in suspicious_patterns)
    
    def _detect_dns_tunneling(self, query: str) -> bool:
        """Detect DNS tunneling attempts."""
        # Long subdomain names indicate data in DNS
        parts = query.split('.')
        for part in parts:
            if len(part) > 50:  # Unusually long subdomain
                return True
        
        # High entropy in domain names
        if self._calculate_entropy(query) > 4.5:
            return True
        
        return False
    
    def _detect_exfiltration_commands(self, command: str) -> Dict[str, Any]:
        """Detect data exfiltration commands."""
        for pattern in self.exfiltration_commands:
            match = re.search(pattern, command, re.IGNORECASE)
            if match:
                return {
                    'pattern': pattern,
                    'match': match.group(),
                    'command': command,
                    'method': self._classify_exfiltration_method(pattern)
                }
        
        return None
    
    def _is_data_staging_operation(self, operation: str) -> bool:
        """Check if operation is data staging."""
        staging_indicators = [
            '/tmp/',  # Temporary directory
            '.tar',   # Archive files
            '.gz',    # Compressed files
            '.zip',   # Zip files
            '.b64',   # Base64 encoded
            '.enc',   # Encrypted files
        ]
        
        return any(indicator in operation.lower() for indicator in staging_indicators)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        import math
        from collections import Counter
        
        if not text:
            return 0.0
        
        counts = Counter(text)
        entropy = 0.0
        length = len(text)
        
        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _classify_exfiltration_method(self, pattern: str) -> str:
        """Classify exfiltration method from pattern."""
        if 'curl' in pattern or 'wget' in pattern:
            return 'HTTP'
        elif 'nc' in pattern or 'socat' in pattern:
            return 'TCP'
        elif 'ssh' in pattern:
            return 'SSH'
        elif 'python' in pattern:
            return 'SCRIPT'
        else:
            return 'UNKNOWN'