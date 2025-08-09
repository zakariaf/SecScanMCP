"""Network monitoring manager for traffic analysis."""

import asyncio
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
        
        for line in output.strip().split('\n'):
            if line.startswith(('tcp', 'udp')):
                parts = line.split()
                if len(parts) >= 4:
                    connections.append({
                        'protocol': parts[0],
                        'local_address': parts[3],
                        'foreign_address': parts[4] if len(parts) > 4 else '',
                        'state': parts[5] if len(parts) > 5 else '',
                        'raw_line': line
                    })
        
        return connections
    
    def _parse_dns_activity(self, output: str) -> List[Dict[str, Any]]:
        """Parse DNS activity from ss output."""
        queries = []
        
        for line in output.strip().split('\n'):
            if ':53' in line or ':domain' in line:
                parts = line.split()
                if len(parts) >= 2:
                    queries.append({
                        'query': line,
                        'timestamp': asyncio.get_event_loop().time(),
                        'raw_line': line
                    })
        
        return queries
    
    def _parse_network_processes(self, output: str) -> List[Dict[str, Any]]:
        """Parse network processes from ps output."""
        processes = []
        
        for line in output.strip().split('\n'):
            if any(cmd in line for cmd in ['curl', 'wget', 'nc', 'socat']):
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        'pid': parts[1],
                        'command': parts[10],
                        'user': parts[0],
                        'timestamp': asyncio.get_event_loop().time(),
                        'raw_line': line
                    })
        
        return processes
    
    def _parse_file_operations(self, output: str) -> List[Dict[str, Any]]:
        """Parse file operations from lsof output."""
        operations = []
        
        for line in output.strip().split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 8:
                operations.append({
                    'command': parts[0],
                    'pid': parts[1],
                    'user': parts[2],
                    'fd': parts[3],
                    'type': parts[4],
                    'device': parts[5],
                    'node': parts[7],
                    'name': ' '.join(parts[8:]) if len(parts) > 8 else '',
                    'timestamp': asyncio.get_event_loop().time(),
                    'raw_line': line
                })
        
        return operations