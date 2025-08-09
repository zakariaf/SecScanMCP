"""Main dynamic analyzer orchestrator with clean architecture."""

import time
import logging
from typing import List, Dict, Any

from models import Finding
from analyzers.base import BaseAnalyzer

from .managers.docker_manager import DockerManager
from .managers.mcp_connection_manager import MCPConnectionManager
from .services.security_testing_service import SecurityTestingService
from .services.traffic_analysis_service import TrafficAnalysisService
from .services.behavioral_analysis_service import BehavioralAnalysisService
from .services.performance_monitoring_service import PerformanceMonitoringService

logger = logging.getLogger(__name__)


class DynamicAnalyzer(BaseAnalyzer):
    """
    Advanced Dynamic Analysis Engine for MCP Servers.
    
    Features:
    - Full MCP protocol support (JSON-RPC 2.0, STDIO, SSE, WebSocket)
    - Advanced security testing with comprehensive payloads
    - Network traffic analysis and data exfiltration detection
    - ML-based behavioral anomaly detection
    - Real-time performance monitoring
    """
    
    def __init__(self):
        super().__init__()
        
        # Initialize managers
        self.docker_manager = DockerManager()
        self.connection_manager = MCPConnectionManager()
        
        # Initialize services
        self.security_testing = SecurityTestingService()
        self.traffic_analysis = TrafficAnalysisService()
        self.behavioral_analysis = BehavioralAnalysisService()
        self.performance_monitoring = PerformanceMonitoringService()
        
        # Analysis session state
        self.session = {
            'start_time': None,
            'container_id': None,
            'mcp_client': None,
            'findings': []
        }
    
    def is_applicable(self, project_info: Dict[str, Any]) -> bool:
        """Check if dynamic analysis should be performed."""
        dynamic_enabled = project_info.get('enable_dynamic_analysis', False)
        is_mcp = project_info.get('is_mcp', False)
        return dynamic_enabled and is_mcp
    
    async def analyze(self, repo_path: str, project_info: Dict[str, Any]) -> List[Finding]:
        """
        Comprehensive dynamic security analysis.
        
        Args:
            repo_path: Path to repository
            project_info: Project information
            
        Returns:
            List of security findings
        """
        if not self.is_applicable(project_info):
            return []
        
        findings = []
        self.session['start_time'] = time.time()
        
        try:
            # Phase 1: Environment setup
            if not await self._setup_environment():
                return findings
            
            # Phase 2: Runtime configuration
            runtime_info = self._determine_runtime(project_info, repo_path)
            if not runtime_info:
                logger.warning("Could not determine runtime configuration")
                return findings
            
            # Phase 3: Create sandbox container
            container = await self.docker_manager.create_sandbox(
                repo_path, runtime_info
            )
            if not container:
                return findings
            
            self.session['container_id'] = container.id
            
            # Phase 4: Establish MCP connection
            mcp_client = await self.connection_manager.establish_connection(
                container, runtime_info
            )
            if not mcp_client:
                logger.warning("Could not establish MCP connection")
                return findings
            
            self.session['mcp_client'] = mcp_client
            
            # Phase 5: Run security tests
            findings.extend(await self._run_security_analysis())
            
            # Phase 6: Network traffic analysis
            findings.extend(await self._run_traffic_analysis())
            
            # Phase 7: Behavioral analysis
            findings.extend(await self._run_behavioral_analysis())
            
            # Phase 8: Performance monitoring
            findings.extend(await self._run_performance_analysis())
            
        except Exception as e:
            logger.error(f"Dynamic analysis failed: {e}")
        
        finally:
            await self._cleanup()
        
        logger.info(f"Dynamic analysis completed with {len(findings)} findings")
        return findings
    
    async def _setup_environment(self) -> bool:
        """Set up the analysis environment."""
        return await self.docker_manager.initialize_environment()
    
    def _determine_runtime(self, project_info: Dict[str, Any], 
                          repo_path: str) -> Dict[str, Any]:
        """Determine MCP server runtime configuration."""
        # Simple runtime detection logic
        runtime_config = {
            'language': project_info.get('language', 'python'),
            'entry_point': self._find_entry_point(repo_path),
            'transport': 'stdio',  # Default transport
            'timeout': 30
        }
        
        return runtime_config
    
    def _find_entry_point(self, repo_path: str) -> str:
        """Find the main entry point for the MCP server."""
        # Look for common entry points
        from pathlib import Path
        repo = Path(repo_path)
        
        candidates = [
            'main.py', 'server.py', 'app.py',
            'mcp_server.py', '__main__.py'
        ]
        
        for candidate in candidates:
            if (repo / candidate).exists():
                return candidate
        
        return 'main.py'  # Default
    
    async def _run_security_analysis(self) -> List[Finding]:
        """Run comprehensive security testing."""
        if not self.session['mcp_client']:
            return []
        
        return await self.security_testing.run_comprehensive_tests(
            self.session['mcp_client']
        )
    
    async def _run_traffic_analysis(self) -> List[Finding]:
        """Run network traffic analysis."""
        if not self.session['container_id']:
            return []
        
        return await self.traffic_analysis.analyze_traffic(
            self.session['container_id']
        )
    
    async def _run_behavioral_analysis(self) -> List[Finding]:
        """Run behavioral anomaly detection."""
        if not self.session['mcp_client']:
            return []
        
        return await self.behavioral_analysis.analyze_behavior(
            self.session['mcp_client'],
            self.session['container_id']
        )
    
    async def _run_performance_analysis(self) -> List[Finding]:
        """Run performance monitoring analysis."""
        if not self.session['container_id']:
            return []
        
        return await self.performance_monitoring.analyze_performance(
            self.session['container_id']
        )
    
    async def _cleanup(self):
        """Clean up analysis resources."""
        try:
            if self.session.get('mcp_client'):
                await self.connection_manager.cleanup_connection(
                    self.session['mcp_client']
                )
            
            if self.session.get('container_id'):
                await self.docker_manager.cleanup_container(
                    self.session['container_id']
                )
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")