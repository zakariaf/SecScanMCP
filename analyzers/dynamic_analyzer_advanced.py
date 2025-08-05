"""
Advanced methods for the Dynamic Analyzer
These methods implement the sophisticated security testing capabilities
"""

import asyncio
import docker
import json
import time
from typing import List, Dict, Any, Optional
import logging
from .mcp_client import MCPClient, MCPTransport
from .attack_payloads import PayloadCategory
from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class DynamicAnalyzerAdvanced:
    """
    Advanced methods for the Dynamic Analyzer
    """
    
    async def _initialize_docker_environment(self) -> bool:
        """Initialize Docker environment with enhanced security"""
        try:
            self.docker_client = docker.from_env()
            # Test Docker access
            self.docker_client.ping()
            self.logger.info("✅ Docker connection established - advanced analysis enabled")
            return True
            
        except PermissionError as pe:
            self.logger.warning(f"🔒 Docker permission denied: {pe}")
            self.logger.info("💡 Hint: Container user needs 'docker' group membership for Docker-in-Docker")
            return False
            
        except Exception as docker_error:
            self.logger.warning(f"🐳 Docker not accessible: {docker_error}")
            self.logger.info("ℹ️ Dynamic analysis requires Docker daemon access")
            return False
    
    async def _create_advanced_sandbox(self, repo_path: str, runtime_info: Dict[str, Any]) -> Optional[docker.models.containers.Container]:
        """Create an advanced security sandbox with enhanced monitoring"""
        try:
            import shutil
            import tempfile
            
            # Create secure temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Copy code with safety checks
                shutil.copytree(repo_path, temp_dir + "/app", dirs_exist_ok=True)
                
                # Enhanced container configuration
                container_config = {
                    'image': runtime_info['image'],
                    'command': '/bin/sh -c "sleep 3600"',  # Keep alive for analysis
                    'detach': True,
                    'volumes': {
                        temp_dir + "/app": {'bind': '/app', 'mode': 'ro'}  # Read-only mount
                    },
                    'working_dir': '/app',
                    'environment': {
                        **runtime_info.get('environment', {}),
                        'MCP_ANALYSIS_MODE': 'true',
                        'PYTHONUNBUFFERED': '1'
                    },
                    
                    # Enhanced security constraints
                    'network_mode': 'bridge',  # Allow monitored network access
                    'mem_limit': '1024m',  # Increased for analysis
                    'cpu_quota': 100000,  # 1.0 CPU
                    'security_opt': [
                        'no-new-privileges:true',
                        'seccomp=unconfined'  # Allow system call monitoring
                    ],
                    'cap_drop': ['ALL'],
                    'cap_add': ['NET_ADMIN'],  # For network monitoring
                    'user': 'root',  # Temporary for advanced monitoring
                    
                    # Monitoring and logging
                    'labels': {
                        'mcp.analysis': 'true',
                        'mcp.analyzer': 'dynamic',
                        'mcp.session': str(int(time.time()))
                    }
                }
                
                container = self.docker_client.containers.run(**container_config)
                
                # Install dependencies and setup monitoring
                await self._setup_container_environment(container, runtime_info, repo_path)
                
                # Start the MCP server
                await self._start_mcp_server(container, runtime_info)
                
                self.logger.info(f"🏗️ Advanced sandbox created: {container.id[:12]}")
                return container
                
        except Exception as e:
            self.logger.error(f"❌ Failed to create advanced sandbox: {e}")
            return None
    
    async def _setup_container_environment(self, container, runtime_info: Dict[str, Any], repo_path: str):
        """Setup container environment for advanced analysis"""
        try:
            # Install monitoring tools
            monitoring_setup = """
            apt-get update && apt-get install -y --no-install-recommends \\
                netstat-nat ss lsof strace tcpdump procfs \\
                curl wget nc-openbsd psmisc \\
                && rm -rf /var/lib/apt/lists/*
            """
            
            container.exec_run(f'/bin/sh -c "{monitoring_setup}"', detach=True)
            
            # Install language-specific dependencies
            if runtime_info['image'].startswith('python'):
                if (Path(repo_path) / 'requirements.txt').exists():
                    result = container.exec_run('pip install --user -r requirements.txt')
                    if result.exit_code != 0:
                        self.logger.warning("Failed to install Python dependencies")
                        
                # Install MCP monitoring utilities
                container.exec_run('pip install --user mcp psutil')
                
            elif runtime_info['image'].startswith('node'):
                if (Path(repo_path) / 'package.json').exists():
                    result = container.exec_run('npm install --production')
                    if result.exit_code != 0:
                        self.logger.warning("Failed to install Node.js dependencies")
            
            self.logger.info("🔧 Container environment configured")
            
        except Exception as e:
            self.logger.warning(f"Container setup warning: {e}")
    
    async def _start_mcp_server(self, container, runtime_info: Dict[str, Any]):
        """Start the MCP server in the container"""
        try:
            # Start server with logging
            start_command = f"nohup {runtime_info['command']} > /var/log/mcp-server.log 2>&1 &"
            container.exec_run(f'/bin/sh -c "{start_command}"', detach=True)
            
            # Wait for server to initialize
            await asyncio.sleep(5)
            
            # Verify server is running
            result = container.exec_run('ps aux | grep -v grep | grep mcp')
            if result.exit_code == 0:
                self.logger.info("🚀 MCP server started successfully")
            else:
                self.logger.warning("⚠️ MCP server may not be running properly")
                
        except Exception as e:
            self.logger.error(f"Failed to start MCP server: {e}")
    
    async def _initialize_traffic_monitoring(self, container_id: str):
        """Initialize advanced traffic monitoring"""
        try:
            self.traffic_analyzer = TrafficAnalyzer(container_id)
            
            # Start traffic monitoring in background
            asyncio.create_task(self.traffic_analyzer.start_monitoring())
            
            self.logger.info("📡 Traffic monitoring initialized")
            
        except Exception as e:
            self.logger.warning(f"Traffic monitoring setup failed: {e}")
    
    async def _establish_mcp_connection(self, container, runtime_info: Dict[str, Any]) -> Optional[MCPClient]:
        """Establish MCP protocol connection"""
        try:
            # Try different transport methods
            transports_to_try = [
                (MCPTransport.STDIO, runtime_info['command']),
                (MCPTransport.SSE, 'http://localhost:8000/mcp'),
                (MCPTransport.WEBSOCKET, 'ws://localhost:8000/mcp')
            ]
            
            for transport, endpoint in transports_to_try:
                try:
                    client = MCPClient(transport)
                    
                    if transport == MCPTransport.STDIO:
                        # Execute command in container
                        connected = await client.connect(
                            f"docker exec -i {container.id} {endpoint}"
                        )
                    else:
                        connected = await client.connect(endpoint)
                    
                    if connected:
                        self.logger.info(f"🔗 MCP connection established via {transport.value}")
                        return client
                        
                except Exception as e:
                    self.logger.debug(f"Connection failed for {transport.value}: {e}")
                    continue
            
            self.logger.warning("❌ Could not establish MCP protocol connection")
            return None
            
        except Exception as e:
            self.logger.error(f"MCP connection error: {e}")
            return None
    
    async def _run_comprehensive_security_tests(self) -> List[Finding]:
        """Run comprehensive security testing using all payload categories"""
        findings = []
        
        if not self.analysis_session.get('security_tester'):
            return findings
        
        try:
            security_tester = self.analysis_session['security_tester']
            
            self.logger.info("🔐 Running comprehensive security tests...")
            
            # Run comprehensive tests
            vulnerabilities = await security_tester.run_comprehensive_tests()
            
            # Convert to findings
            for vuln in vulnerabilities:
                finding = self._convert_vulnerability_to_finding(vuln)
                if finding:
                    findings.append(finding)
            
            self.logger.info(f"🔍 Security testing found {len(findings)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Security testing failed: {e}")
        
        return findings
    
    async def _test_tool_manipulation(self) -> List[Finding]:
        """Test for tool manipulation and poisoning vulnerabilities"""
        findings = []
        
        if not self.analysis_session.get('mcp_client'):
            return findings
        
        try:
            client = self.analysis_session['mcp_client']
            
            # Get available tools
            tools = client.get_available_tools()
            
            self.logger.info(f"🛠️ Testing {len(tools)} tools for manipulation vulnerabilities...")
            
            # Test tool manipulation payloads
            manipulation_payloads = self.payload_generator.get_payloads(PayloadCategory.TOOL_MANIPULATION)
            
            for tool in tools:
                tool_name = tool.get('name', 'unknown')
                
                for payload_data in manipulation_payloads:
                    try:
                        payload = payload_data['payload']
                        
                        # Test tool with manipulation payload
                        response = await client.call_tool(tool_name, {'input': payload})
                        
                        if response:
                            analysis = self.payload_validator.analyze_response(
                                str(response.result or response.error), payload_data
                            )
                            
                            if analysis['vulnerable']:
                                finding = self.create_finding(
                                    vulnerability_type=VulnerabilityType.TOOL_MANIPULATION,
                                    severity=SeverityLevel.HIGH,
                                    confidence=analysis['confidence'],
                                    title=f"Tool Manipulation: {tool_name}",
                                    description=f"Tool '{tool_name}' vulnerable to manipulation: {payload_data['description']}",
                                    location=f"tool:{tool_name}",
                                    recommendation="Implement input validation and sanitization for tool parameters",
                                    evidence={
                                        'tool_name': tool_name,
                                        'payload': payload,
                                        'response': str(response.result or response.error)[:500],
                                        'analysis': analysis
                                    }
                                )
                                findings.append(finding)
                                
                    except Exception as e:
                        self.logger.debug(f"Tool manipulation test error: {e}")
            
            self.logger.info(f"🔧 Tool manipulation testing found {len(findings)} issues")
            
        except Exception as e:
            self.logger.error(f"Tool manipulation testing failed: {e}")
        
        return findings
    
    async def _run_advanced_prompt_injection_tests(self) -> List[Finding]:
        """Run advanced prompt injection tests"""
        findings = []
        
        if not self.analysis_session.get('mcp_client'):
            return findings
        
        try:
            client = self.analysis_session['mcp_client']
            
            # Get available prompts
            prompts = client.get_available_prompts()
            
            self.logger.info(f"💬 Testing {len(prompts)} prompts with advanced injection techniques...")
            
            # Get advanced prompt injection payloads
            injection_payloads = self.payload_generator.get_payloads(PayloadCategory.PROMPT_INJECTION)
            
            for prompt in prompts:
                prompt_name = prompt.get('name', 'unknown')
                
                for payload_data in injection_payloads:
                    try:
                        payload = payload_data['payload']
                        
                        # Test prompt with injection payload
                        response = await client.get_prompt(prompt_name, {'input': payload})
                        
                        if response:
                            analysis = self.payload_validator.analyze_response(
                                str(response.result or response.error), payload_data
                            )
                            
                            if analysis['vulnerable']:
                                severity = SeverityLevel.CRITICAL if 'critical' in payload_data.get('severity', '') else SeverityLevel.HIGH
                                
                                finding = self.create_finding(
                                    vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                                    severity=severity,
                                    confidence=analysis['confidence'],
                                    title=f"Advanced Prompt Injection: {prompt_name}",
                                    description=f"Prompt '{prompt_name}' vulnerable to injection: {payload_data['description']}",
                                    location=f"prompt:{prompt_name}",
                                    recommendation="Implement prompt isolation and input sanitization",
                                    evidence={
                                        'prompt_name': prompt_name,
                                        'payload': payload,
                                        'response': str(response.result or response.error)[:500],
                                        'analysis': analysis,
                                        'injection_type': payload_data['description']
                                    }
                                )
                                findings.append(finding)
                                
                    except Exception as e:
                        self.logger.debug(f"Prompt injection test error: {e}")
            
            self.logger.info(f"🎯 Advanced prompt injection testing found {len(findings)} vulnerabilities")
            
        except Exception as e:
            self.logger.error(f"Prompt injection testing failed: {e}")
        
        return findings
    
    async def _run_behavioral_analysis(self, container) -> List[Finding]:
        """Run comprehensive behavioral analysis"""
        findings = []
        
        try:
            self.logger.info("🧠 Running behavioral analysis...")
            
            # Monitor behavior for analysis period
            behavior_duration = 30  # seconds
            start_time = time.time()
            
            behavior_metrics = []
            
            while time.time() - start_time < behavior_duration:
                # Collect runtime metrics
                metrics = await self._collect_runtime_metrics(container)
                if metrics:
                    behavior_metrics.append(metrics)
                    self.analysis_session['metrics_history'].append(metrics)
                
                await asyncio.sleep(2)  # Collect metrics every 2 seconds
            
            # Analyze behavioral patterns
            if behavior_metrics:
                # Create behavioral profile
                self.behavior_profiler.create_profile(behavior_metrics, "current_session")
                
                # Detect behavioral anomalies
                behavioral_findings = await self._detect_behavioral_anomalies(behavior_metrics)
                findings.extend(behavioral_findings)
            
            self.logger.info(f"🧠 Behavioral analysis found {len(findings)} anomalies")
            
        except Exception as e:
            self.logger.error(f"Behavioral analysis failed: {e}")
        
        return findings
    
    async def _collect_runtime_metrics(self, container) -> Optional[Dict[str, Any]]:
        """Collect comprehensive runtime metrics"""
        try:
            # Get container stats
            stats = container.stats(stream=False)
            
            # Extract CPU usage
            cpu_percent = self._calculate_cpu_percent(stats)
            
            # Extract memory usage
            memory_usage = stats['memory_stats']['usage'] / (1024 * 1024)  # MB
            
            # Get network connections count
            net_result = container.exec_run('netstat -an | wc -l')
            network_connections = int(net_result.output.decode().strip()) if net_result.exit_code == 0 else 0
            
            # Get process count
            proc_result = container.exec_run('ps aux | wc -l')
            process_count = int(proc_result.output.decode().strip()) if proc_result.exit_code == 0 else 0
            
            # Get file descriptor count
            fd_result = container.exec_run('ls /proc/*/fd 2>/dev/null | wc -l')
            file_descriptors = int(fd_result.output.decode().strip()) if fd_result.exit_code == 0 else 0
            
            return {
                'timestamp': time.time(),
                'cpu_percent': cpu_percent,
                'memory_mb': memory_usage,
                'network_connections': network_connections,
                'process_count': process_count,
                'file_descriptors': file_descriptors,
                'dns_queries': 0,  # Will be updated by traffic analyzer
                'file_operations': 0,  # Will be updated by monitoring
                'process_spawns': 0,  # Will be updated by monitoring
                'tool_calls': 0,  # Will be updated by MCP client
                'error_count': 0,  # Will be updated by log analysis
                'response_time_ms': 0,  # Will be updated by performance monitoring
                'data_volume_bytes': 0,  # Will be updated by traffic analyzer
                'unique_destinations': 0  # Will be updated by traffic analyzer
            }
            
        except Exception as e:
            self.logger.debug(f"Metrics collection error: {e}")
            return None
    
    def _convert_vulnerability_to_finding(self, vuln: Dict[str, Any]) -> Optional[Finding]:
        """Convert vulnerability data to Finding object"""
        try:
            # Map vulnerability types
            vuln_type_map = {
                'command_injection': VulnerabilityType.COMMAND_INJECTION,
                'code_injection': VulnerabilityType.CODE_INJECTION,
                'path_traversal': VulnerabilityType.PATH_TRAVERSAL,
                'prompt_injection': VulnerabilityType.PROMPT_INJECTION,
                'unauthorized_resource_access': VulnerabilityType.PERMISSION_ABUSE,
            }
            
            vuln_type = vuln_type_map.get(
                vuln.get('vulnerability_type', ''),
                VulnerabilityType.GENERIC
            )
            
            # Map severity
            severity_map = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW
            }
            
            severity = severity_map.get(
                vuln.get('severity', 'medium'),
                SeverityLevel.MEDIUM
            )
            
            return self.create_finding(
                vulnerability_type=vuln_type,
                severity=severity,
                confidence=0.9,  # High confidence for dynamic testing
                title=f"Dynamic Test: {vuln.get('vulnerability_type', 'Unknown')}",
                description=f"Vulnerability detected in {vuln.get('tool_name', 'unknown component')}: {vuln.get('parameter', '')}",
                location=f"dynamic:{vuln.get('tool_name', 'unknown')}",
                recommendation="Review and fix the detected vulnerability through input validation",
                evidence={
                    'payload': vuln.get('payload', ''),
                    'response': vuln.get('response', ''),
                    'parameter': vuln.get('parameter', ''),
                    'tool_name': vuln.get('tool_name', '')
                }
            )
            
        except Exception as e:
            self.logger.error(f"Failed to convert vulnerability: {e}")
            return None