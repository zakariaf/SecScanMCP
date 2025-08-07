"""
MCP (Model Context Protocol) Detection Module

Comprehensive detection of MCP servers across multiple programming languages
based on official SDKs, community packages, and configuration files.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class MCPDetector:
    """Detects MCP servers using comprehensive package-based analysis"""

    def __init__(self):
        self.detection_methods = [
            self._detect_mcp_config_files,
            self._detect_nodejs_mcp,
            self._detect_python_mcp,
            self._detect_go_mcp,
            self._detect_rust_mcp,
            self._detect_java_mcp,
            self._detect_csharp_mcp,
            self._detect_generic_project
        ]

    async def analyze_project(self, repo_path: str) -> Dict[str, Any]:
        """
        Detect project type and MCP configuration
        
        Args:
            repo_path: Path to the repository to analyze
            
        Returns:
            Dictionary containing project information and MCP detection results
        """
        project_info = {
            'type': 'unknown',
            'language': None,
            'is_mcp': False,
            'mcp_config': None,
            'dependencies': [],
            'detection_method': None,
            'confidence': 0.0
        }

        # Run detection methods in order of confidence
        for detection_method in self.detection_methods:
            result = await detection_method(repo_path, project_info)
            if result:
                project_info.update(result)
                if project_info['type'] != 'unknown':
                    break

        return project_info

    async def _detect_mcp_config_files(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect MCP configuration files (highest confidence)"""
        mcp_files = ['mcp.json', 'mcp.yaml', 'mcp.yml']
        
        for mcp_file in mcp_files:
            mcp_path = Path(repo_path) / mcp_file
            if mcp_path.exists():
                logger.info(f"Found MCP configuration file: {mcp_file}")
                
                mcp_config = None
                try:
                    with open(mcp_path) as f:
                        if mcp_file.endswith('.json'):
                            mcp_config = json.load(f)
                        else:
                            import yaml
                            mcp_config = yaml.safe_load(f)
                except Exception as e:
                    logger.warning(f"Failed to parse MCP config {mcp_file}: {e}")
                
                return {
                    'is_mcp': True,
                    'mcp_config': mcp_config,
                    'detection_method': f'mcp_config_file:{mcp_file}',
                    'confidence': 1.0
                }
        
        return None

    async def _detect_nodejs_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Node.js/JavaScript MCP servers"""
        package_json_path = Path(repo_path) / 'package.json'
        if not package_json_path.exists():
            return None

        try:
            with open(package_json_path) as f:
                pkg = json.load(f)
                deps = list(pkg.get('dependencies', {}).keys())
                deps.extend(pkg.get('devDependencies', {}).keys())

                # Official MCP SDK packages (based on research)
                official_packages = [
                    '@modelcontextprotocol/sdk',
                    '@modelcontextprotocol/inspector', 
                    '@modelcontextprotocol/server-filesystem',
                    'modelcontextprotocol'
                ]

                # Community MCP packages
                community_packages = [
                    'mcp-server',
                    'mcp-client',
                    'fastmcp',
                    'mcp-use'
                ]

                # Legacy/alternative patterns
                legacy_patterns = ['mcp', 'model-context-protocol']

                detected_packages = []
                detection_method = None
                confidence = 0.0

                # Check for official packages first (highest confidence)
                official_found = [p for p in official_packages if p in deps]
                if official_found:
                    detected_packages = official_found
                    detection_method = 'nodejs_official_packages'
                    confidence = 0.95
                    logger.info(f"Detected MCP server via official Node.js packages: {official_found}")

                # Check for community packages (medium confidence)
                elif any(pkg_name in deps for pkg_name in community_packages):
                    community_found = [p for p in community_packages if p in deps]
                    detected_packages = community_found
                    detection_method = 'nodejs_community_packages'
                    confidence = 0.8
                    logger.info(f"Detected MCP server via community Node.js packages: {community_found}")

                # Check for legacy patterns (low confidence)
                elif any(pattern in dep.lower() for dep in deps for pattern in legacy_patterns):
                    pattern_found = [dep for dep in deps for pattern in legacy_patterns if pattern in dep.lower()]
                    detected_packages = pattern_found
                    detection_method = 'nodejs_pattern_matching'
                    confidence = 0.6
                    logger.info(f"Detected MCP server via Node.js pattern matching: {pattern_found}")

                if detected_packages:
                    return {
                        'type': 'node',
                        'language': 'javascript',
                        'is_mcp': True,
                        'dependencies': deps,
                        'detection_method': detection_method,
                        'confidence': confidence,
                        'detected_packages': detected_packages
                    }

                # Node.js project but no MCP packages
                return {
                    'type': 'node',
                    'language': 'javascript',
                    'dependencies': deps,
                    'detection_method': 'nodejs_no_mcp',
                    'confidence': 0.9  # High confidence it's Node.js, just not MCP
                }

        except Exception as e:
            logger.warning(f"Failed to parse package.json: {e}")
            return {
                'type': 'node',
                'language': 'javascript',
                'detection_method': 'nodejs_parse_error',
                'confidence': 0.7
            }

    async def _detect_python_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Python MCP servers"""
        python_indicators = [
            Path(repo_path) / 'requirements.txt',
            Path(repo_path) / 'pyproject.toml',
            Path(repo_path) / 'setup.py'
        ]

        if not any(indicator.exists() for indicator in python_indicators):
            return None

        # Official MCP Python packages
        official_packages = ['mcp', 'mcp[cli]', 'mcp[server]', 'fastmcp']
        community_packages = ['mcp-agent', 'mcp-use', 'mcp-client', 'mcp-server']
        framework_packages = ['semantic-kernel', 'langchain-mcp', 'openai-mcp']

        mcp_detected = False
        detected_packages = []
        detection_method = None
        confidence = 0.0

        # Check requirements.txt
        requirements_path = Path(repo_path) / 'requirements.txt'
        if requirements_path.exists():
            try:
                with open(requirements_path) as f:
                    req_content = f.read().lower()
                    
                    # Check for official packages
                    official_found = [pkg for pkg in official_packages if pkg in req_content]
                    if official_found:
                        mcp_detected = True
                        detected_packages = official_found
                        detection_method = 'python_requirements_official'
                        confidence = 0.95
                        logger.info(f"Detected MCP server via requirements.txt official packages: {official_found}")
                    
                    # Check community packages
                    elif any(pkg in req_content for pkg in community_packages):
                        community_found = [pkg for pkg in community_packages if pkg in req_content]
                        mcp_detected = True
                        detected_packages = community_found
                        detection_method = 'python_requirements_community'
                        confidence = 0.8
                        logger.info(f"Detected MCP server via requirements.txt community packages: {community_found}")

            except Exception as e:
                logger.warning(f"Failed to parse requirements.txt: {e}")

        # Check pyproject.toml
        if not mcp_detected:
            pyproject_path = Path(repo_path) / 'pyproject.toml'
            if pyproject_path.exists():
                try:
                    with open(pyproject_path) as f:
                        toml_content = f.read().lower()
                        
                        if any(pkg in toml_content for pkg in ['mcp', 'fastmcp', 'modelcontextprotocol']):
                            mcp_detected = True
                            detection_method = 'python_pyproject_toml'
                            confidence = 0.9
                            logger.info("Detected MCP server via pyproject.toml")

                except Exception as e:
                    logger.warning(f"Failed to parse pyproject.toml: {e}")

        # Check for MCP imports in Python files
        if not mcp_detected:
            import_result = await self._detect_python_imports(repo_path)
            if import_result:
                mcp_detected = True
                detection_method = 'python_imports'
                confidence = import_result['confidence']
                detected_packages = import_result.get('patterns', [])

        if mcp_detected:
            return {
                'type': 'python',
                'language': 'python',
                'is_mcp': True,
                'detection_method': detection_method,
                'confidence': confidence,
                'detected_packages': detected_packages
            }

        # Python project but no MCP
        return {
            'type': 'python',
            'language': 'python',
            'detection_method': 'python_no_mcp',
            'confidence': 0.9
        }

    async def _detect_python_imports(self, repo_path: str) -> Optional[Dict[str, Any]]:
        """Detect MCP imports in Python files"""
        mcp_import_patterns = [
            'import mcp',
            'from mcp',
            'from mcp.server',
            'from mcp.client', 
            'from mcp.server.fastmcp import FastMCP',
            'from mcp.server.stdio',
            'from mcp_agent',
            'from mcp_use',
            'from semantic_kernel.connectors.mcp',
            'McpServer',
            'MCPServer',
            'FastMCP',
            'MCPAgent'
        ]

        found_patterns = []
        files_checked = 0

        for py_file in Path(repo_path).rglob('*.py'):
            try:
                files_checked += 1
                if files_checked > 50:  # Limit to avoid performance issues
                    break
                    
                with open(py_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for pattern in mcp_import_patterns:
                        if pattern in content:
                            found_patterns.append(pattern)
                            logger.info(f"Found MCP import pattern '{pattern}' in {py_file.name}")

                if found_patterns:
                    # High-confidence patterns
                    high_conf_patterns = [
                        'from mcp.server.fastmcp import FastMCP',
                        'from mcp.server',
                        'import mcp'
                    ]
                    
                    if any(pattern in found_patterns for pattern in high_conf_patterns):
                        confidence = 0.9
                    else:
                        confidence = 0.7

                    return {
                        'patterns': found_patterns,
                        'confidence': confidence,
                        'file': str(py_file.relative_to(repo_path))
                    }

            except Exception:
                continue

        return None

    async def _detect_go_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Go MCP servers"""
        go_mod_path = Path(repo_path) / 'go.mod'
        if not go_mod_path.exists():
            return None

        try:
            with open(go_mod_path) as f:
                go_mod_content = f.read().lower()
                
                go_mcp_packages = [
                    'modelcontextprotocol',
                    'github.com/modelcontextprotocol/go-sdk',
                    'mcp-go'
                ]
                
                found_packages = [pkg for pkg in go_mcp_packages if pkg in go_mod_content]
                
                if found_packages:
                    logger.info(f"Detected MCP server via go.mod dependencies: {found_packages}")
                    return {
                        'type': 'go',
                        'language': 'go',
                        'is_mcp': True,
                        'detection_method': 'go_mod_packages',
                        'confidence': 0.9,
                        'detected_packages': found_packages
                    }

                # Go project but no MCP
                return {
                    'type': 'go',
                    'language': 'go',
                    'detection_method': 'go_no_mcp',
                    'confidence': 0.9
                }

        except Exception as e:
            logger.warning(f"Failed to parse go.mod: {e}")
            return {
                'type': 'go',
                'language': 'go',
                'detection_method': 'go_parse_error',
                'confidence': 0.7
            }

    async def _detect_rust_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Rust MCP servers"""
        cargo_path = Path(repo_path) / 'Cargo.toml'
        if not cargo_path.exists():
            return None

        try:
            with open(cargo_path) as f:
                cargo_content = f.read().lower()
                
                rust_mcp_packages = [
                    'mcp',
                    'modelcontextprotocol',
                    'mcp-rust',
                    'mcp-server'
                ]
                
                found_packages = [pkg for pkg in rust_mcp_packages if pkg in cargo_content]
                
                if found_packages:
                    logger.info(f"Detected MCP server via Cargo.toml dependencies: {found_packages}")
                    return {
                        'type': 'rust',
                        'language': 'rust',
                        'is_mcp': True,
                        'detection_method': 'cargo_packages',
                        'confidence': 0.9,
                        'detected_packages': found_packages
                    }

                # Rust project but no MCP
                return {
                    'type': 'rust',
                    'language': 'rust',
                    'detection_method': 'rust_no_mcp',
                    'confidence': 0.9
                }

        except Exception as e:
            logger.warning(f"Failed to parse Cargo.toml: {e}")
            return {
                'type': 'rust',
                'language': 'rust',
                'detection_method': 'rust_parse_error',
                'confidence': 0.7
            }

    async def _detect_java_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect Java MCP servers"""
        java_files = [Path(repo_path) / 'pom.xml'] + list(Path(repo_path).glob('*.gradle*'))
        java_files = [f for f in java_files if f.exists()]
        
        if not java_files:
            return None

        java_mcp_packages = [
            'modelcontextprotocol',
            'mcp-java',
            'org.modelcontextprotocol'
        ]

        for java_file in java_files:
            try:
                with open(java_file) as f:
                    java_content = f.read().lower()
                    
                    found_packages = [pkg for pkg in java_mcp_packages if pkg in java_content]
                    
                    if found_packages:
                        logger.info(f"Detected MCP server via {java_file.name}: {found_packages}")
                        return {
                            'type': 'java',
                            'language': 'java',
                            'is_mcp': True,
                            'detection_method': f'java_{java_file.suffix[1:]}',
                            'confidence': 0.9,
                            'detected_packages': found_packages
                        }

            except Exception as e:
                logger.warning(f"Failed to parse {java_file.name}: {e}")

        # Java project but no MCP
        return {
            'type': 'java',
            'language': 'java',
            'detection_method': 'java_no_mcp',
            'confidence': 0.9
        }

    async def _detect_csharp_mcp(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Detect C# MCP servers"""
        csharp_files = list(Path(repo_path).glob('*.csproj')) + [Path(repo_path) / 'packages.config']
        csharp_files = [f for f in csharp_files if f.exists()]
        
        if not csharp_files:
            return None

        csharp_mcp_packages = [
            'modelcontextprotocol',
            'mcp.net',
            'microsoft.modelcontextprotocol'
        ]

        for csharp_file in csharp_files:
            try:
                with open(csharp_file) as f:
                    csharp_content = f.read().lower()
                    
                    found_packages = [pkg for pkg in csharp_mcp_packages if pkg in csharp_content]
                    
                    if found_packages:
                        logger.info(f"Detected MCP server via {csharp_file.name}: {found_packages}")
                        return {
                            'type': 'csharp',
                            'language': 'csharp',
                            'is_mcp': True,
                            'detection_method': f'csharp_{csharp_file.suffix[1:]}',
                            'confidence': 0.9,
                            'detected_packages': found_packages
                        }

            except Exception as e:
                logger.warning(f"Failed to parse {csharp_file.name}: {e}")

        # C# project but no MCP
        return {
            'type': 'csharp',
            'language': 'csharp',
            'detection_method': 'csharp_no_mcp',
            'confidence': 0.9
        }

    async def _detect_generic_project(self, repo_path: str, project_info: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Fallback detection for unknown project types"""
        # If we haven't detected any specific project type, return unknown
        if project_info['type'] == 'unknown':
            return {
                'type': 'unknown',
                'language': None,
                'detection_method': 'generic_fallback',
                'confidence': 0.1
            }
        
        return None

    def get_detection_confidence_explanation(self, project_info: Dict[str, Any]) -> str:
        """Get human-readable explanation of detection confidence"""
        method = project_info.get('detection_method', 'unknown')
        confidence = project_info.get('confidence', 0.0)
        
        explanations = {
            'mcp_config_file': "Found official MCP configuration file",
            'nodejs_official_packages': "Found official MCP SDK in package.json",
            'nodejs_community_packages': "Found community MCP packages in package.json", 
            'nodejs_pattern_matching': "Found MCP-related patterns in dependencies",
            'python_requirements_official': "Found official MCP packages in requirements.txt",
            'python_requirements_community': "Found community MCP packages in requirements.txt",
            'python_pyproject_toml': "Found MCP packages in pyproject.toml",
            'python_imports': "Found MCP imports in Python source files",
            'go_mod_packages': "Found MCP packages in go.mod",
            'cargo_packages': "Found MCP packages in Cargo.toml",
            'java_pom': "Found MCP packages in pom.xml",
            'java_gradle': "Found MCP packages in Gradle files",
            'csharp_csproj': "Found MCP packages in .csproj file",
            'generic_fallback': "No specific project type detected"
        }
        
        base_explanation = explanations.get(method, f"Detection method: {method}")
        return f"{base_explanation} (confidence: {confidence:.1%})"