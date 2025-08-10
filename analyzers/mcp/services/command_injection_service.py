"""Command injection vulnerability analysis service."""

import re
import ast
import logging
from pathlib import Path
from typing import List, Dict, Any, Set

from models import Finding, SeverityLevel, VulnerabilityType

logger = logging.getLogger(__name__)


class CommandInjectionService:
    """Detects command injection vulnerabilities in MCP tools."""
    
    def __init__(self):
        self.injection_patterns = self._build_injection_patterns()
        self.dangerous_functions = self._build_dangerous_functions()
    
    def _build_injection_patterns(self) -> List[Dict[str, Any]]:
        """Build command injection detection patterns."""
        return [
            {
                'pattern': r'(?i)(os\.system|subprocess\.call|subprocess\.run|subprocess\.Popen)\s*\([^)]*input',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Direct User Input to System Command'
            },
            {
                'pattern': r'(?i)shell\s*=\s*True.*input',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Shell Command Execution with User Input'
            },
            {
                'pattern': r'(?i)(eval|exec)\s*\([^)]*input',
                'severity': SeverityLevel.CRITICAL,
                'title': 'Code Execution with User Input'
            },
            {
                'pattern': r'(?i)f[\'"][^\'\"]*\{.*input.*\}[\'"]',
                'severity': SeverityLevel.HIGH,
                'title': 'F-string Command Injection Risk'
            },
        ]
    
    def _build_dangerous_functions(self) -> Set[str]:
        """Build set of dangerous functions for command execution."""
        return {
            'os.system', 'os.popen', 'os.spawn*',
            'subprocess.call', 'subprocess.run', 'subprocess.Popen',
            'subprocess.check_call', 'subprocess.check_output',
            'eval', 'exec', 'compile',
            'shutil.move', 'shutil.copy*', 'shutil.rmtree'
        }
    
    async def analyze_command_injection(self, repo_path: str) -> List[Finding]:
        """
        Analyze repository for command injection vulnerabilities.
        
        Args:
            repo_path: Repository path
            
        Returns:
            List of command injection findings
        """
        findings = []
        repo = Path(repo_path)
        
        # Check Python source files
        for py_file in repo.glob('**/*.py'):
            if self._should_analyze_file(py_file):
                findings.extend(
                    self._analyze_python_file(py_file)
                )
        
        return findings
    
    def _analyze_python_file(self, file_path: Path) -> List[Finding]:
        """Analyze Python file for command injection."""
        findings = []
        
        try:
            content = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # Pattern-based detection
            findings.extend(self._check_injection_patterns(content, file_path))
            
            # AST-based analysis
            try:
                tree = ast.parse(content)
                findings.extend(self._analyze_ast_for_injection(tree, content, file_path))
            except SyntaxError:
                logger.warning(f"Syntax error in {file_path}, skipping AST analysis")
        
        except Exception as e:
            logger.warning(f"Error analyzing {file_path}: {e}")
        
        return findings
    
    def _check_injection_patterns(self, content: str, file_path: Path) -> List[Finding]:
        """Check for command injection patterns using regex."""
        findings = []
        
        for pattern_info in self.injection_patterns:
            matches = re.finditer(pattern_info['pattern'], content, re.MULTILINE)
            
            for match in matches:
                findings.append(Finding(
                    title=f"Command Injection: {pattern_info['title']}",
                    description=f"Potential command injection vulnerability in {file_path.name}",
                    severity=pattern_info['severity'],
                    vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                    location=str(file_path),
                    recommendation="Sanitize user input before passing to system commands. Use parameterized commands or allowlists.",
                    evidence={'code_snippet': self._extract_context(content, match.start())},
                    tool="mcp_command_injection",
                    confidence=0.85
                ))
        
        return findings
    
    def _analyze_ast_for_injection(self, tree: ast.AST, content: str, 
                                  file_path: Path) -> List[Finding]:
        """Analyze AST for command injection patterns."""
        findings = []
        
        class InjectionVisitor(ast.NodeVisitor):
            def __init__(self, service_instance):
                self.service = service_instance
                self.findings = []
            
            def visit_Call(self, node):
                # Check for dangerous function calls
                func_name = self._get_function_name(node)
                
                if any(danger in func_name for danger in self.service.dangerous_functions):
                    # Check if arguments contain user input
                    if self._has_user_input_arg(node):
                        line_no = getattr(node, 'lineno', 0)
                        
                        self.findings.append(Finding(
                            title="AST Command Injection Detection",
                            description=f"Dangerous function {func_name} with user input",
                            severity=SeverityLevel.HIGH,
                            vulnerability_type=VulnerabilityType.COMMAND_INJECTION,
                            location=f"{file_path}:{line_no}",
                            recommendation="Sanitize user input before passing to system commands. Use parameterized commands or allowlists.",
                            evidence={'code_snippet': self._extract_node_context(content, node)},
                            tool="mcp_command_injection",
                            confidence=0.9
                        ))
                
                self.generic_visit(node)
            
            def _get_function_name(self, node):
                """Extract function name from Call node."""
                if isinstance(node.func, ast.Name):
                    return node.func.id
                elif isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name):
                        return f"{node.func.value.id}.{node.func.attr}"
                    else:
                        return node.func.attr
                return ""
            
            def _has_user_input_arg(self, node):
                """Check if call has arguments that might be user input."""
                input_indicators = ['input', 'argv', 'args', 'request', 'param']
                
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if any(indicator in arg.id.lower() for indicator in input_indicators):
                            return True
                    elif isinstance(arg, ast.JoinedStr):  # f-string
                        for value in arg.values:
                            if isinstance(value, ast.FormattedValue):
                                return True
                
                return False
            
            def _extract_node_context(self, content, node):
                """Extract context around AST node."""
                try:
                    lines = content.split('\n')
                    line_no = getattr(node, 'lineno', 1) - 1
                    start = max(0, line_no - 2)
                    end = min(len(lines), line_no + 3)
                    return '\n'.join(lines[start:end])
                except:
                    return "Context unavailable"
        
        visitor = InjectionVisitor(self)
        visitor.visit(tree)
        findings.extend(visitor.findings)
        
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