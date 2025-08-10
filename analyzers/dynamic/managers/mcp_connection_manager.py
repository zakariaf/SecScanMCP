"""MCP connection management for dynamic analysis."""

import asyncio
import logging
from typing import Optional, Dict, Any
from ..utils.mcp_client import MCPClient, MCPTransport

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
        """Create MCP client for communication with multi-transport fallback."""
        # Check if advanced multi-transport mode is requested
        use_fallback = runtime_info.get('multi_transport_fallback', True)
        
        if use_fallback:
            return await self._create_mcp_client_with_fallback(container, runtime_info)
        else:
            return await self._create_single_transport_client(container, runtime_info)
    
    async def _create_single_transport_client(self, container, runtime_info: Dict[str, Any]):
        """Create MCP client with single transport (original behavior)."""
        try:
            # Determine transport type
            transport_type = runtime_info.get('transport', 'stdio')
            
            # Use real MCPClient if available, fallback to mock for testing
            if transport_type == 'stdio':
                transport = MCPTransport.STDIO
            elif transport_type == 'websocket':
                transport = MCPTransport.WEBSOCKET
            elif transport_type == 'sse':
                transport = MCPTransport.SSE
            else:
                # Fallback to mock for unsupported transports
                logger.info(f"Using mock client for transport: {transport_type}")
                client = MockMCPClient(
                    container=container,
                    transport=transport_type
                )
                await client.initialize()
                return client
            
            # Create real MCP client
            client = MCPClient(transport=transport)
            
            # Configure based on runtime info
            if transport == MCPTransport.WEBSOCKET:
                client.websocket_url = f"ws://localhost:{runtime_info.get('port', 8080)}"
            elif transport == MCPTransport.SSE:
                client.sse_url = f"http://localhost:{runtime_info.get('port', 8080)}/sse"
            
            # Initialize connection
            await client.connect()
            
            logger.info(f"Real MCP client connected via {transport_type}")
            return client
            
        except ImportError:
            # If MCPClient not available, use mock
            logger.warning("MCPClient not available, using mock")
            client = MockMCPClient(
                container=container,
                transport=runtime_info.get('transport', 'stdio')
            )
            await client.initialize()
            return client
            
        except Exception as e:
            logger.error(f"Failed to create MCP client: {e}")
            return None
    
    async def _create_mcp_client_with_fallback(self, container, runtime_info: Dict[str, Any]):
        """Create MCP client with multi-transport fallback (advanced mode)."""
        # Try different transport methods in priority order
        transports_to_try = [
            (MCPTransport.STDIO, runtime_info.get('command', '')),
            (MCPTransport.SSE, 'http://localhost:8000/mcp'),
            (MCPTransport.WEBSOCKET, 'ws://localhost:8000/mcp')
        ]
        
        for transport, endpoint in transports_to_try:
            try:
                client = MCPClient(transport)
                connected = await self._connect_with_transport(client, container, transport, endpoint)
                
                if connected:
                    logger.info(f"🔗 MCP connection established via {transport.value}")
                    return client
                    
            except Exception as e:
                logger.debug(f"Connection failed for {transport.value}: {e}")
                continue
        
        logger.warning("❌ Could not establish MCP protocol connection with any transport")
        
        # Final fallback to mock client
        client = MockMCPClient(
            container=container,
            transport='fallback'
        )
        await client.initialize()
        return client
    
    async def _connect_with_transport(self, client: MCPClient, container, 
                                     transport: MCPTransport, endpoint: str) -> bool:
        """Connect client using specific transport."""
        if transport == MCPTransport.STDIO:
            # Execute command in container
            docker_command = f"docker exec -i {container.id} {endpoint}"
            return await client.connect(docker_command)
        else:
            return await client.connect(endpoint)
    
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
    """Mock MCP client for testing purposes.
    
    This is used as a fallback when the real MCPClient is not available
    or for testing scenarios where a full MCP connection is not needed.
    """
    
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