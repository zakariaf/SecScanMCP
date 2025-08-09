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
        
        # Analysis session state
        self.session = {
            'start_time': None,
            'container_id': None,
            'mcp_client': None,
            'findings': [],
            'metrics_history': []
        }
        
        # Initialize managers
        self.docker_manager = DockerManager()
        self.connection_manager = MCPConnectionManager()
        
        # Initialize services
        self.security_testing = SecurityTestingService()
        self.traffic_analysis = TrafficAnalysisService()
        self.behavioral_analysis = BehavioralAnalysisService()
        self.performance_monitoring = PerformanceMonitoringService()
        
        # Pass session reference to services
        self.traffic_analysis.analysis_session = self.session
        self.behavioral_analysis.analysis_session = self.session
    
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
            await self._handle_analysis_failure(e)
        
        finally:
            await self._cleanup()
        
        # Generate analysis summary
        summary = self._generate_analysis_summary(findings)
        logger.info(summary)
        
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
        findings = []
        
        if not self.session['container_id']:
            return findings
        
        # Standard traffic analysis
        findings.extend(await self.traffic_analysis.analyze_traffic(
            self.session['container_id']
        ))
        
        # Advanced network traffic analysis
        findings.extend(await self.traffic_analysis.analyze_network_traffic())
        
        # Data exfiltration detection
        findings.extend(await self.traffic_analysis.detect_data_exfiltration())
        
        return findings
    
    async def _run_behavioral_analysis(self) -> List[Finding]:
        """Run behavioral anomaly detection."""
        findings = []
        
        if not self.session['mcp_client']:
            return findings
        
        # Standard behavioral analysis
        findings.extend(await self.behavioral_analysis.analyze_behavior(
            self.session['mcp_client'],
            self.session['container_id']
        ))
        
        # ML-based anomaly detection using metrics history
        metrics_history = self.session.get('metrics_history', [])
        if metrics_history:
            findings.extend(await self.behavioral_analysis.run_ml_anomaly_detection(
                metrics_history
            ))
        
        return findings
    
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
    
    async def _handle_analysis_failure(self, error: Exception):
        """Handle analysis failure with proper cleanup and logging"""
        try:
            logger.error(f"🚨 Dynamic analysis failed: {error}")
            logger.error(f"Error type: {type(error).__name__}")
            
            # Attempt emergency cleanup
            if self.session.get('container_id'):
                try:
                    await self.docker_manager.cleanup_container(
                        self.session['container_id']
                    )
                    logger.info("Emergency container cleanup completed")
                except Exception as cleanup_error:
                    logger.error(f"Emergency cleanup failed: {cleanup_error}")
            
            # Log session state for debugging
            logger.debug(f"Session state at failure: {self.session}")
            
        except Exception as e:
            logger.error(f"Error handler failed: {e}")
    
    def _generate_analysis_summary(self, findings: List[Finding]) -> str:
        """Generate a comprehensive summary of analysis results"""
        try:
            if not findings:
                return "🟢 Dynamic analysis completed - No security issues detected"
            
            # Count findings by severity
            severity_counts = {}
            vuln_type_counts = {}
            
            for finding in findings:
                severity = finding.severity.value
                vuln_type = finding.vulnerability_type.value
                
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + 1
            
            # Build summary
            summary_parts = ["📊 Dynamic Analysis Summary:"]
            
            # Severity breakdown
            if severity_counts:
                summary_parts.append("🎯 Severity Distribution:")
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    count = severity_counts.get(severity, 0)
                    if count > 0:
                        emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🔵'}.get(severity, '⚪')
                        summary_parts.append(f"  {emoji} {severity}: {count}")
            
            # Top vulnerability types
            if vuln_type_counts:
                top_vulns = sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:5]
                summary_parts.append("🚨 Top Vulnerability Types:")
                for vuln_type, count in top_vulns:
                    summary_parts.append(f"  • {vuln_type}: {count}")
            
            # Analysis phases completed
            analysis_duration = None
            if self.session.get('start_time'):
                analysis_duration = time.time() - self.session['start_time']
                summary_parts.append(f"⏱️ Analysis Duration: {analysis_duration:.1f}s")
            
            # Recommendations
            critical_high = severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
            if critical_high > 0:
                summary_parts.append(f"⚠️ IMMEDIATE ACTION REQUIRED: {critical_high} critical/high severity issues found")
            
            return "\n".join(summary_parts)
            
        except Exception as e:
            logger.error(f"Failed to generate analysis summary: {e}")
            return f"📊 Dynamic analysis completed with {len(findings)} findings"
    
    def _calculate_cpu_percent(self, stats: Dict[str, Any]) -> float:
        """Calculate CPU percentage from Docker stats"""
        try:
            cpu_stats = stats.get('cpu_stats', {})
            precpu_stats = stats.get('precpu_stats', {})
            
            cpu_usage = cpu_stats.get('cpu_usage', {}).get('total_usage', 0)
            precpu_usage = precpu_stats.get('cpu_usage', {}).get('total_usage', 0)
            
            system_usage = cpu_stats.get('system_cpu_usage', 0)
            presystem_usage = precpu_stats.get('system_cpu_usage', 0)
            
            cpu_count = cpu_stats.get('online_cpus', 1)
            
            cpu_delta = cpu_usage - precpu_usage
            system_delta = system_usage - presystem_usage
            
            if system_delta > 0 and cpu_delta > 0:
                cpu_percent = (cpu_delta / system_delta) * cpu_count * 100.0
                return min(cpu_percent, 100.0)  # Cap at 100%
            
            return 0.0
            
        except Exception as e:
            logger.debug(f"CPU calculation error: {e}")
            return 0.0