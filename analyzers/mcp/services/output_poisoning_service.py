"""Output poisoning vulnerability analysis service."""

import re
import ast
import logging
from pathlib import Path
from typing import List, Dict, Any

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class OutputPoisoningService:
    """Detects output poisoning vulnerabilities in MCP tool responses."""
    
    def __init__(self):
        self.poisoning_patterns = self._build_poisoning_patterns()
    
    def _build_poisoning_patterns(self) -> List[Dict[str, Any]]:
        """Build output poisoning detection patterns."""
        return [
            {
                'pattern': r'(?i)(ignore|forget|disregard)\s+(all\s+)?(previous|prior|earlier|above)\s+(instructions?|commands?|rules?)',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Instruction Override Attempt'
            },
            {
                'pattern': r'(?i)(\{INSTRUCTION:|<IMPORTANT>|<HIDDEN>|<SECRET>|SYSTEM\s*:|{{SYSTEM|ALWAYS:)',
                'severity': SeverityLevel.HIGH,
                'title': 'Hidden System Instruction'
            },
            {
                'pattern': r'(?i)(execute|run|eval)\s+(this|the\s+following)\s+(code|command|script)',
                'severity': SeverityLevel.HIGH,
                'title': 'Code Execution Injection'
            },
            {
                'pattern': r'(?i)new\s+(instruction|rule|command):\s*',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Dynamic Instruction Injection'
            },
            {
                'pattern': r'(?i)(assistant|ai|system)\s+(must|should|will)\s+(now|always|immediately)',
                'severity': SeverityLevel.MEDIUM,
                'title': 'Behavioral Override Attempt'
            }
        ]
    
    async def analyze_output_poisoning(self, repo_path: str) -> List[Finding]:
        """
        Analyze repository for output poisoning vulnerabilities.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of output poisoning findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Analyze Python tool functions
        findings.extend(self._analyze_tool_functions(repo))
        
        # Check template/response files
        findings.extend(self._analyze_response_templates(repo))
        
        # Check configuration files for malicious responses
        findings.extend(self._analyze_config_responses(repo))
        
        return findings
    
    def _analyze_tool_functions(self, repo: Path) -> List[Finding]:
        """Analyze MCP tool functions for output poisoning."""
        findings = []
        
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(self._check_python_tool_file(py_file))
        
        return findings
    
    def _check_python_tool_file(self, file_path: Path) -> List[Finding]:
        """Check Python file for tool output poisoning."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Skip if not an MCP tool file
            if not self._is_mcp_tool_file(content):
                return findings
            
            # Check for poisoning patterns in string literals
            findings.extend(self._check_string_patterns(content, file_path))
            
            # AST-based analysis for dynamic output generation
            try:
                tree = ast.parse(content)
                findings.extend(self._analyze_tool_ast(tree, content, file_path))
            except SyntaxError:
                logger.warning(f"Syntax error in {file_path}, skipping AST analysis")
        
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _is_mcp_tool_file(self, content: str) -> bool:
        """Check if file contains MCP tool definitions."""
        mcp_indicators = [
            '@mcp.tool', '@tool', 'def tool_',
            'mcp_tool', 'Tool(', 'register_tool'
        ]
        return any(indicator in content for indicator in mcp_indicators)
    
    def _check_string_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Check string literals for poisoning patterns."""
        findings = []
        
        for pattern_info in self.poisoning_patterns:
            matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
            
            for match in matches:
                # Get the line containing the match
                line_start = content.rfind('\n', 0, match.start()) + 1
                line_end = content.find('\n', match.end())
                if line_end == -1:
                    line_end = len(content)
                
                line_content = content[line_start:line_end]
                
                # Check if it's in a string literal or return statement
                if self._is_in_output_context(line_content, match.start() - line_start):
                    findings.append(Finding(
                        title=f"Output Poisoning: {pattern_info['title']}",
                        description=f"Potential output poisoning pattern in tool response",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.8
                    ))
        
        return findings
    
    def _is_in_output_context(self, line: str, position: int) -> bool:
        """Check if position is in an output context (string, return, etc.)."""
        # Simple heuristic: check if it's in quotes or after return
        before_pos = line[:position]
        
        # Count quotes to see if we're inside a string
        single_quotes = before_pos.count("'") - before_pos.count("\\'")
        double_quotes = before_pos.count('"') - before_pos.count('\\"')
        
        in_string = (single_quotes % 2 == 1) or (double_quotes % 2 == 1)
        
        # Check if line contains return statement
        has_return = 'return' in line.lower()
        
        return in_string or has_return
    
    def _analyze_tool_ast(self, tree: ast.AST, content: str, 
                         file_path: Path) -> List[Finding]:
        """Analyze AST for dynamic output poisoning."""
        findings = []
        
        class OutputVisitor(ast.NodeVisitor):
            def __init__(self, service_instance):
                self.service = service_instance
                self.findings = []
            
            def visit_FunctionDef(self, node):
                # Check if it's a tool function
                if self._is_tool_function(node):
                    # Check return statements
                    for child in ast.walk(node):
                        if isinstance(child, ast.Return) and child.value:
                            self._check_return_value(child, node.name)
                
                self.generic_visit(node)
            
            def _is_tool_function(self, func_node):
                """Check if function is an MCP tool."""
                # Check decorators
                for decorator in func_node.decorator_list:
                    if isinstance(decorator, ast.Name):
                        if 'tool' in decorator.id.lower():
                            return True
                    elif isinstance(decorator, ast.Attribute):
                        if 'tool' in decorator.attr.lower():
                            return True
                
                # Check function name
                return 'tool' in func_node.name.lower()
            
            def _check_return_value(self, return_node, func_name):
                """Check return value for poisoning patterns."""
                if isinstance(return_node.value, ast.Str):  # String literal
                    return_value = return_node.value.s
                    if self._contains_poisoning(return_value):
                        line_no = getattr(return_node, 'lineno', 0)
                        
                        self.findings.append(Finding(
                            title="Dynamic Output Poisoning in Tool Response",
                            description=f"Tool function {func_name} returns potentially poisoned output",
                            severity=SeverityLevel.HIGH,
                            vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                            location=f"{file_path}:{line_no}",
                            confidence=0.85
                        ))
                elif isinstance(return_node.value, ast.JoinedStr):  # f-string
                    # Check if f-string construction could be poisoned
                    self.findings.append(Finding(
                        title="Dynamic String Construction in Tool Output",
                        description=f"Tool function {func_name} uses dynamic string construction",
                        severity=SeverityLevel.MEDIUM,
                        vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                        location=f"{file_path}:{getattr(return_node, 'lineno', 0)}",
                        confidence=0.6
                    ))
            
            def _contains_poisoning(self, text):
                """Check if text contains poisoning patterns."""
                for pattern_info in self.service.poisoning_patterns:
                    if re.search(pattern_info['pattern'], text, re.IGNORECASE):
                        return True
                return False
        
        visitor = OutputVisitor(self)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        
        return findings
    
    def _analyze_response_templates(self, repo: Path) -> List[Finding]:
        """Analyze response template files for poisoning."""
        findings = []
        
        template_patterns = [
            '**/*.template', '**/*.tmpl', '**/*.jinja',
            '**/templates/**', '**/responses/**'
        ]
        
        for pattern in template_patterns:
            for template_file in repo.glob(pattern):
                if template_file.is_file():
                    findings.extend(self._check_template_file(template_file))
        
        return findings
    
    def _check_template_file(self, file_path: Path) -> List[Finding]:
        """Check template file for poisoning patterns."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            for pattern_info in self.poisoning_patterns:
                matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Template Output Poisoning: {pattern_info['title']}",
                        description=f"Poisoning pattern found in response template",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.9
                    ))
        
        except Exception as e:
            logger.warning(f"Error checking template {file_path}: {e}")
        
        return findings
    
    def _analyze_config_responses(self, repo: Path) -> List[Finding]:
        """Analyze configuration files for malicious response patterns."""
        findings = []
        
        config_patterns = ['*.json', '*.yaml', '*.yml', 'mcp.*']
        
        for pattern in config_patterns:
            for config_file in repo.glob(f'**/{pattern}'):
                if config_file.is_file():
                    findings.extend(self._check_config_file(config_file))
        
        return findings
    
    def _check_config_file(self, file_path: Path) -> List[Finding]:
        """Check configuration file for response poisoning."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Check for poisoning patterns in config text
            for pattern_info in self.poisoning_patterns:
                matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
                
                for match in matches:
                    findings.append(Finding(
                        title=f"Config Response Poisoning: {pattern_info['title']}",
                        description=f"Poisoning pattern in configuration file",
                        severity=pattern_info['severity'],
                        vulnerability_type=VulnerabilityType.OUTPUT_POISONING,
                        location=str(file_path),
                        code_snippet=self._extract_context(content, match.start()),
                        confidence=0.7
                    ))
        
        except Exception as e:
            logger.warning(f"Error checking config {file_path}: {e}")
        
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