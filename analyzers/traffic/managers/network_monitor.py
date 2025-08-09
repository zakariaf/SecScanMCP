"""Network monitoring manager for traffic analysis."""

import asyncio
import time
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class NetworkMonitor:
    """Manages network monitoring for traffic analysis."""
    
    def __init__(self, container_id: str):
        self.container_id = container_id
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
    
    async def start_monitoring(self) -> bool:
        """Start monitoring network traffic."""
        try:
            self.monitoring = True
            
            # Start monitoring tasks
            tasks = [
                asyncio.create_task(self._monitor_connections()),
                asyncio.create_task(self._monitor_dns_queries()),
                asyncio.create_task(self._monitor_processes()),
                asyncio.create_task(self._monitor_file_transfers()),
            ]
            
            # Run monitoring tasks concurrently
            await asyncio.gather(*tasks, return_exceptions=True)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start monitoring: {e}")
            return False
    
    def stop_monitoring(self):
        """Stop all monitoring activities."""
        self.monitoring = False
    
    async def _monitor_connections(self):
        """Monitor network connections."""
        while self.monitoring:
            try:
                result = await self._exec_in_container("netstat -tuln")
                if result:
                    connections = self._parse_netstat_output(result)
                    yield from connections
                
                await asyncio.sleep(2)
                
            except Exception as e:
                self.logger.debug(f"Connection monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_dns_queries(self):
        """Monitor DNS queries."""
        while self.monitoring:
            try:
                result = await self._exec_in_container("ss -u")
                if result:
                    queries = self._parse_dns_activity(result)
                    yield from queries
                
                await asyncio.sleep(3)
                
            except Exception as e:
                self.logger.debug(f"DNS monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_processes(self):
        """Monitor network processes."""
        while self.monitoring:
            try:
                cmd = "ps aux | grep -E 'curl|wget|nc|ncat|socat'"
                result = await self._exec_in_container(cmd)
                if result:
                    processes = self._parse_network_processes(result)
                    yield from processes
                
                await asyncio.sleep(3)
                
            except Exception as e:
                self.logger.debug(f"Process monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _monitor_file_transfers(self):
        """Monitor file transfer operations."""
        while self.monitoring:
            try:
                cmd = "lsof -i 2>/dev/null | head -50"
                result = await self._exec_in_container(cmd)
                if result:
                    operations = self._parse_file_operations(result)
                    yield from operations
                
                await asyncio.sleep(4)
                
            except Exception as e:
                self.logger.debug(f"File transfer monitoring error: {e}")
                await asyncio.sleep(5)
    
    async def _exec_in_container(self, command: str) -> Optional[str]:
        """Execute command in container."""
        try:
            import docker
            client = docker.from_env()
            container = client.containers.get(self.container_id)
            
            result = container.exec_run(command)
            if result.exit_code == 0:
                return result.output.decode('utf-8')
            
        except Exception as e:
            self.logger.debug(f"Container exec error: {e}")
        
        return None
    
    def _parse_netstat_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse netstat output into connection objects."""
        connections = []
        
        for line in output.split('\n'):
            if 'ESTABLISHED' in line or 'LISTEN' in line:
                parts = line.split()
                if len(parts) >= 4:
                    connection = {
                        'protocol': parts[0],
                        'local_address': parts[3],
                        'remote_address': parts[4] if len(parts) > 4 else 'N/A',
                        'state': parts[5] if len(parts) > 5 else 'UNKNOWN',
                        'timestamp': time.time()
                    }
                    connections.append(connection)
        
        return connections
    
    def _parse_dns_activity(self, output: str) -> List[Dict[str, Any]]:
        """Parse DNS-related network activity."""
        dns_queries = []
        
        # Look for DNS-related connections (port 53)
        for line in output.split('\n'):
            if ':53' in line or 'domain' in line:
                query = {
                    'query': line.strip(),
                    'timestamp': time.time(),
                    'suspicious': self._is_suspicious_dns(line)
                }
                dns_queries.append(query)
        
        return dns_queries
    
    def _parse_network_processes(self, output: str) -> List[Dict[str, Any]]:
        """Parse network-related processes."""
        processes = []
        
        for line in output.split('\n'):
            if line.strip() and not line.startswith('grep'):
                parts = line.split()
                if len(parts) >= 10:
                    process = {
                        'pid': parts[1],
                        'user': parts[0],
                        'command': ' '.join(parts[10:]),
                        'timestamp': time.time(),
                        'suspicious': self._is_suspicious_network_process(' '.join(parts[10:]))
                    }
                    processes.append(process)
        
        return processes
    
    def _parse_file_operations(self, output: str) -> List[Dict[str, Any]]:
        """Parse file operations that might indicate data staging."""
        operations = []
        
        for line in output.split('\n'):
            if line.strip():
                operation = {
                    'operation': line.strip(),
                    'timestamp': time.time(),
                    'suspicious': self._is_suspicious_file_operation(line)
                }
                operations.append(operation)
        
        return operations
    
    def _is_suspicious_dns(self, query: str) -> bool:
        """Check if DNS query is suspicious."""
        # Look for DNS tunneling indicators
        indicators = [
            len(query) > 100,  # Unusually long queries
            query.count('.') > 5,  # Many subdomains
            'base64' in query.lower(),
            'data' in query.lower(),
            'exfil' in query.lower()
        ]
        return any(indicators)
    
    def _is_suspicious_network_process(self, command: str) -> bool:
        """Check if network process is suspicious."""
        import re
        suspicious_indicators = [
            'curl.*attacker',
            'wget.*evil',
            'nc.*-e',  # Netcat with command execution
            'telnet.*4444',  # Common backdoor port
            'ssh.*-R',  # SSH reverse tunnel
            'python.*-c.*socket',  # Python socket programming
            'node.*-e.*net',  # Node.js networking
        ]
        
        for indicator in suspicious_indicators:
            if re.search(indicator, command, re.IGNORECASE):
                return True
        
        return False
    
    def _is_suspicious_file_operation(self, operation: str) -> bool:
        """Check if file operation indicates data staging."""
        staging_indicators = [
            '/tmp/',  # Temporary directory usage
            '.tar', '.zip', '.gz',  # Archive creation
            'passwd', 'shadow', 'hosts',  # System files
            '.env', 'config',  # Configuration files
        ]
        
        return any(indicator in operation.lower() for indicator in staging_indicators)