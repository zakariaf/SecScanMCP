"""MCP connection management for dynamic analysis."""

import asyncio
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class MCPConnectionManager:
    """Manages MCP client connections for dynamic analysis."""
    
    def __init__(self):
        self.active_connections = {}
    
    async def establish_connection(self, container, 
                                 runtime_info: Dict[str, Any]) -> Optional:
        """
        Establish MCP connection to server in container.
        
        Args:
            container: Docker container running MCP server
            runtime_info: Runtime configuration
            
        Returns:
            MCP client instance or None if connection failed
        """
        try:
            # Start MCP server in container
            server_process = await self._start_mcp_server(container, runtime_info)
            if not server_process:
                return None
            
            # Create MCP client
            mcp_client = await self._create_mcp_client(container, runtime_info)
            if not mcp_client:
                return None
            
            # Test connection
            if not await self._test_connection(mcp_client):
                return None
            
            # Store connection
            self.active_connections[container.id] = {
                'client': mcp_client,
                'server_process': server_process,
                'runtime_info': runtime_info
            }
            
            logger.info(f"MCP connection established for {container.short_id}")
            return mcp_client
            
        except Exception as e:
            logger.error(f"Failed to establish MCP connection: {e}")
            return None
    
    async def _start_mcp_server(self, container, 
                               runtime_info: Dict[str, Any]) -> bool:
        """Start MCP server in container."""
        try:
            entry_point = runtime_info.get('entry_point', 'main.py')
            language = runtime_info.get('language', 'python')
            
            if language == 'python':
                cmd = f'python {entry_point}'
            elif language in ['node', 'typescript']:
                cmd = f'node {entry_point}'
            else:
                logger.error(f"Unsupported language: {language}")
                return False
            
            # Execute server in background
            exec_result = container.exec_run(
                cmd,
                detach=True,
                workdir='/workspace'
            )
            
            if exec_result.exit_code is not None and exec_result.exit_code != 0:
                logger.error(f"Server start failed: {exec_result.output}")
                return False
            
            # Wait for server to start
            await asyncio.sleep(2)
            
            logger.info("MCP server started in container")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start MCP server: {e}")
            return False
    
    async def _create_mcp_client(self, container, 
                                runtime_info: Dict[str, Any]):
        """Create MCP client for communication."""
        try:
            # For now, return a mock client
            # In real implementation, this would create appropriate transport
            transport_type = runtime_info.get('transport', 'stdio')
            
            client = MockMCPClient(
                container=container,
                transport=transport_type
            )
            
            await client.initialize()
            return client
            
        except Exception as e:
            logger.error(f"Failed to create MCP client: {e}")
            return None
    
    async def _test_connection(self, mcp_client) -> bool:
        """Test MCP connection with basic call."""
        try:
            # Test basic connectivity
            response = await mcp_client.ping()
            return response is not None
            
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False
    
    async def cleanup_connection(self, mcp_client) -> None:
        """Clean up MCP connection resources."""
        try:
            if hasattr(mcp_client, 'disconnect'):
                await mcp_client.disconnect()
            
            # Remove from active connections
            container_id = getattr(mcp_client, 'container_id', None)
            if container_id in self.active_connections:
                del self.active_connections[container_id]
            
            logger.info("MCP connection cleaned up")
            
        except Exception as e:
            logger.error(f"Connection cleanup failed: {e}")


class MockMCPClient:
    """Mock MCP client for testing purposes."""
    
    def __init__(self, container, transport: str):
        self.container = container
        self.transport = transport
        self.container_id = container.id
        self.connected = False
    
    async def initialize(self) -> None:
        """Initialize the mock client."""
        self.connected = True
    
    async def ping(self) -> bool:
        """Test connection with ping."""
        return self.connected
    
    async def list_tools(self) -> list:
        """Get list of available tools."""
        # Mock implementation
        return [
            {'name': 'test_tool', 'description': 'Test tool'},
            {'name': 'another_tool', 'description': 'Another test tool'}
        ]
    
    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict:
        """Call a tool with arguments."""
        # Mock implementation
        return {
            'tool': tool_name,
            'arguments': arguments,
            'result': f'Mock result for {tool_name}',
            'success': True
        }
    
    async def list_resources(self) -> list:
        """Get list of available resources."""
        # Mock implementation
        return [
            {'name': 'test_resource', 'type': 'file'},
            {'name': 'another_resource', 'type': 'url'}
        ]
    
    async def get_resource(self, resource_uri: str) -> Dict:
        """Get resource content."""
        # Mock implementation
        return {
            'uri': resource_uri,
            'content': f'Mock content for {resource_uri}',
            'mime_type': 'text/plain'
        }
    
    async def disconnect(self) -> None:
        """Disconnect from server."""
        self.connected = False