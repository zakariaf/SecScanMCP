"""Advanced prompt injection analysis service."""

import re
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class AdvancedPromptInjectionService:
    """Detects advanced prompt injection vulnerabilities."""
    
    def __init__(self):
        self.injection_patterns = self._build_injection_patterns()
        self.resource_patterns = self._build_resource_patterns()
        self.indirect_patterns = self._build_indirect_patterns()
    
    def _build_injection_patterns(self) -> List[Dict[str, Any]]:
        """Build advanced prompt injection patterns."""
        return [
            {
                'pattern': r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?)',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Direct Instruction Override',
                'category': 'direct_override'
            },
            {
                'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
                'severity': SeverityLevel.HIGH,
                'title': 'Hidden System Commands',
                'category': 'hidden_commands'
            },
            {
                'pattern': r'(?i)(new\s+)?(role|persona|character)\s*:\s*(you\s+are|act\s+as|become)',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Role/Persona Injection',
                'category': 'role_injection'
            },
            {
                'pattern': r'(?i)(execute|run|eval)\s+(this|the\s+following)\s+(code|command|script)',
                'severity': SeverityLevel.HIGH,
                'title': 'Code Execution Command',
                'category': 'code_execution'
            }
        ]
    
    def _build_resource_patterns(self) -> List[Dict[str, Any]]:
        """Build resource-specific injection patterns."""
        return [
            {
                'pattern': r'(?i)resource\s*:\s*.*\b(ignore|bypass|override)\b',
                'severity': SeverityLevel.HIGH,
                'title': 'Resource Access Override',
                'category': 'resource_override'
            },
            {
                'pattern': r'(?i)(file|path|url)\s*:\s*.*\.\./.*',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Path Traversal in Resource',
                'category': 'path_traversal'
            }
        ]
    
    def _build_indirect_patterns(self) -> List[Dict[str, Any]]:
        """Build indirect injection patterns."""
        return [
            {
                'pattern': r'(?i)(when\s+)?(user\s+)?(asks?|requests?|says?)\s*.*\b(respond|answer|reply)\s+with\b',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Conditional Response Override',
                'category': 'conditional_override'
            },
            {
                'pattern': r'(?i)(if|when)\s+.*\b(detected|found|seen)\b.*\b(change|modify|alter)\b',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Behavior Modification Trigger',
                'category': 'behavior_trigger'
            }
        ]
    
    async def analyze_resource_prompt_injection(self, repo_path: str) -> List[Finding]:
        """
        Analyze resource configurations for prompt injection.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of resource prompt injection findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Analyze MCP configuration files
        findings.extend(self._analyze_resource_configs(repo))
        
        # Check resource definition files
        findings.extend(self._analyze_resource_definitions(repo))
        
        return findings
    
    async def analyze_indirect_prompt_injection(self, repo_path: str) -> List[Finding]:
        """
        Analyze for indirect prompt injection vulnerabilities.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of indirect prompt injection findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Check tool functions for indirect injection
        findings.extend(self._analyze_tool_functions(repo))
        
        # Check data processing functions
        findings.extend(self._analyze_data_processors(repo))
        
        return findings
    
    def _analyze_resource_configs(self, repo: Path) -> List[Finding]:
        """Analyze resource configurations for injection."""
        findings = []
        
        config_patterns = ['mcp.json', 'mcp.yaml', 'mcp.yml', '.mcp/**']
        
        for pattern in config_patterns:
            for config_file in repo.glob(pattern):
                if config_file.is_file():
                    findings.extend(self._check_config_resources(config_file))
        
        return findings
    
    def _check_config_resources(self, config_file: Path) -> List[Finding]:
        """Check configuration file resources for injection."""
        findings = []
        
        try:
            content = config_file.read_text()
            
            # Parse based on file type
            config_data = None
            if config_file.suffix == '.json':
                config_data = json.loads(content)
            elif config_file.suffix in ['.yaml', '.yml']:
                import yaml
                config_data = yaml.safe_load(content)
            
            if config_data and isinstance(config_data, dict):
                # Check resources section
                if 'resources' in config_data:
                    findings.extend(
                        self._analyze_resource_section(
                            config_data['resources'], str(config_file)
                        )
                    )
                
                # Check prompts section
                if 'prompts' in config_data:
                    findings.extend(
                        self._analyze_prompt_section(
                            config_data['prompts'], str(config_file)
                        )
                    )
            
            # Also check raw content for patterns
            findings.extend(self._check_content_patterns(content, str(config_file)))
            
        except Exception as e:
            logger.warning(f"Error analyzing config {config_file}: {e}")
        
        return findings
    
    def _analyze_resource_section(self, resources: Any, location: str) -> List[Finding]:
        """Analyze resources section for injection patterns."""
        findings = []
        
        if isinstance(resources, list):
            for i, resource in enumerate(resources):
                findings.extend(
                    self._check_resource_item(resource, f"{location}:resources[{i}]")
                )
        elif isinstance(resources, dict):
            for key, resource in resources.items():
                findings.extend(
                    self._check_resource_item(resource, f"{location}:resources.{key}")
                )
        
        return findings
    
    def _check_resource_item(self, resource: Any, location: str) -> List[Finding]:
        """Check individual resource for injection patterns."""
        findings = []
        
        if not isinstance(resource, dict):
            return findings
        
        # Check resource description
        if 'description' in resource:
            findings.extend(
                self._check_text_for_patterns(
                    resource['description'], 
                    location + ':description',
                    self.resource_patterns
                )
            )
        
        # Check resource URI
        if 'uri' in resource:
            findings.extend(
                self._check_text_for_patterns(
                    resource['uri'],
                    location + ':uri', 
                    self.resource_patterns
                )
            )
        
        return findings
    
    def _analyze_prompt_section(self, prompts: Any, location: str) -> List[Finding]:
        """Analyze prompts section for injection patterns."""
        findings = []
        
        if isinstance(prompts, list):
            for i, prompt in enumerate(prompts):
                findings.extend(
                    self._check_prompt_item(prompt, f"{location}:prompts[{i}]")
                )
        elif isinstance(prompts, dict):
            for key, prompt in prompts.items():
                findings.extend(
                    self._check_prompt_item(prompt, f"{location}:prompts.{key}")
                )
        
        return findings
    
    def _check_prompt_item(self, prompt: Any, location: str) -> List[Finding]:
        """Check individual prompt for injection patterns."""
        findings = []
        
        if not isinstance(prompt, dict):
            return findings
        
        # Check prompt description
        if 'description' in prompt:
            findings.extend(
                self._check_text_for_patterns(
                    prompt['description'],
                    location + ':description',
                    self.injection_patterns
                )
            )
        
        # Check prompt arguments
        if 'arguments' in prompt and isinstance(prompt['arguments'], list):
            for i, arg in enumerate(prompt['arguments']):
                if isinstance(arg, dict) and 'description' in arg:
                    findings.extend(
                        self._check_text_for_patterns(
                            arg['description'],
                            f"{location}:arguments[{i}]:description",
                            self.injection_patterns
                        )
                    )
        
        return findings
    
    def _analyze_resource_definitions(self, repo: Path) -> List[Finding]:
        """Analyze resource definition files."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_python_resources(py_file))
        
        return findings
    
    def _check_python_resources(self, file_path: Path) -> List[Finding]:
        """Check Python file for resource injection vulnerabilities."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Skip if not resource-related
            if not any(keyword in content for keyword in ['resource', 'mcp.resource', '@resource']):
                return findings
            
            # Check for injection patterns in strings
            findings.extend(
                self._check_content_patterns(content, str(file_path))
            )
            
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _analyze_tool_functions(self, repo: Path) -> List[Finding]:
        """Analyze tool functions for indirect injection."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_tool_indirect_injection(py_file))
        
        return findings
    
    def _check_tool_indirect_injection(self, file_path: Path) -> List[Finding]:
        """Check tool functions for indirect injection patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Skip if not MCP tool file
            if not any(indicator in content for indicator in ['@mcp.tool', '@tool', 'def tool_']):
                return findings
            
            # Check for indirect injection patterns
            findings.extend(
                self._check_text_for_patterns(
                    content,
                    str(file_path),
                    self.indirect_patterns
                )
            )
            
        except Exception as e:
            logger.warning(f"Error checking indirect injection in {file_path}: {e}")
        
        return findings
    
    def _analyze_data_processors(self, repo: Path) -> List[Finding]:
        """Analyze data processing functions for injection risks."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_data_processing(py_file))
        
        return findings
    
    def _check_data_processing(self, file_path: Path) -> List[Finding]:
        """Check data processing functions for injection vulnerabilities."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Look for data processing indicators
            processing_indicators = [
                'process_data', 'parse_input', 'handle_request',
                'process_response', 'format_output'
            ]
            
            if not any(indicator in content for indicator in processing_indicators):
                return findings
            
            # Check for injection risks in data processing
            risky_patterns = [
                r'(?i)(input|data|request)\s*\+\s*[\'"]',  # String concatenation
                r'(?i)f[\'"][^\'\"]*\{.*(input|data|request).*\}',  # F-string injection
                r'(?i)(format|substitute)\s*\(.*(input|data|request)',  # Format injection
            ]
            
            for pattern in risky_patterns:
                matches = re.finditer(pattern, content)
                for match in matches:
                    findings.append(Finding(
                        title="Data Processing Injection Risk",
                        description="Unsanitized user input in data processing",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                        location=str(file_path),
                        recommendation="Sanitize and validate user input before processing.",
                        evidence={'code_snippet': self._extract_context(content, match.start())},
                        tool="mcp_prompt_injection",
                        confidence=0.6
                    ))
            
        except Exception as e:
            logger.warning(f"Error checking data processing in {file_path}: {e}")
        
        return findings
    
    def _check_content_patterns(self, content: str, location: str) -> List[Finding]:
        """Check content for all injection patterns."""
        findings = []
        
        all_patterns = (
            self.injection_patterns + 
            self.resource_patterns + 
            self.indirect_patterns
        )
        
        findings.extend(
            self._check_text_for_patterns(content, location, all_patterns)
        )
        
        return findings
    
    def _check_text_for_patterns(self, text: str, location: str, 
                                patterns: List[Dict[str, Any]]) -> List[Finding]:
        """Check text for specific patterns."""
        findings = []
        
        for pattern_info in patterns:
            matches = re.finditer(pattern_info['pattern'], text, re.MULTILINE)
            
            for match in matches:
                findings.append(Finding(
                    title=f"Prompt Injection: {pattern_info['title']}",
                    description=f"Advanced prompt injection pattern detected",
                    severity=pattern_info['severity'],
                    vulnerability_type=VulnerabilityType.PROMPT_INJECTION,
                    location=location,
                    recommendation="Implement input validation and sanitization to prevent prompt injection attacks.",
                    evidence={'code_snippet': self._extract_context(text, match.start())},
                    tool="mcp_prompt_injection",
                    confidence=0.8
                ))
        
        return findings
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        exclude_patterns = [
            'test_', 'tests/', '__pycache__/',
            'node_modules/', '.git/', 'venv/'
        ]
        
        file_str = str(file_path)
        return not any(pattern in file_str for pattern in exclude_patterns)
    
    def _extract_context(self, content: str, position: int, 
                        context_chars: int = 150) -> str:
        """Extract context around match position."""
        start = max(0, position - context_chars // 2)
        end = min(len(content), position + context_chars // 2)
        return content[start:end].strip()