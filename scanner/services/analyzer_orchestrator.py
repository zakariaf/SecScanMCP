"""Analyzer orchestration service for running security analyzers."""

import asyncio
import logging
from typing import Dict, List, Any

from models import Finding
from analyzers import (
    BanditAnalyzer,
    OpenGrepAnalyzer,
    TrivyAnalyzer,
    GrypeAnalyzer,
    SyftAnalyzer,
    TruffleHogAnalyzer,
    MCPSpecificAnalyzer,
    DynamicAnalyzer,
    ClamAVAnalyzer,
    YARAAnalyzer,
    CodeQLAnalyzer
)

logger = logging.getLogger(__name__)


class AnalyzerOrchestrator:
    """Orchestrates the execution of security analyzers."""
    
    def __init__(self):
        self.analyzers = self._initialize_analyzers()
    
    def _initialize_analyzers(self) -> Dict:
        """Initialize all available analyzers."""
        return {
            'syft': SyftAnalyzer(),
            'trivy': TrivyAnalyzer(),
            'grype': GrypeAnalyzer(),
            'bandit': BanditAnalyzer(),
            'opengrep': OpenGrepAnalyzer(),
            'trufflehog': TruffleHogAnalyzer(),
            'mcp_specific': MCPSpecificAnalyzer(),
            'dynamic': DynamicAnalyzer(),
            'clamav': ClamAVAnalyzer(),
            'yara': YARAAnalyzer(),
            'codeql': CodeQLAnalyzer()
        }
    
    async def run_analyzers(self, repo_path: str, project_info: Dict[str, Any],
                           scan_options: Dict[str, Any]) -> List[Finding]:
        """
        Run applicable analyzers on the repository.
        
        Args:
            repo_path: Path to repository
            project_info: Project information
            scan_options: Scan configuration options
            
        Returns:
            List of findings from all analyzers
        """
        analyzers_to_run = self._select_analyzers(project_info, scan_options)
        
        tasks = self._create_analyzer_tasks(analyzers_to_run, repo_path, project_info)
        results = await self._execute_tasks(tasks)
        
        return self._collect_findings(results)
    
    def _select_analyzers(self, project_info: Dict[str, Any], 
                         scan_options: Dict[str, Any]) -> List[str]:
        """Select optimal analyzers based on project type."""
        analyzers = []
        language = project_info.get('language', 'unknown')
        is_mcp = project_info.get('is_mcp', False)
        
        # Always generate SBOM first
        analyzers.append('syft')
        
        # Core security tools
        analyzers.extend(['trufflehog', 'clamav'])
        
        # Language-specific analysis
        if language == 'python':
            analyzers.append('bandit')
        else:
            analyzers.append('opengrep')
        
        # Dependency scanning
        if scan_options.get('fast_scan', False):
            analyzers.append('grype')
        else:
            analyzers.append('trivy')
        
        # Advanced semantic analysis
        if self._should_run_codeql(language, scan_options):
            analyzers.append('codeql')
        
        # MCP-specific analysis
        if is_mcp:
            analyzers.extend(self._get_mcp_analyzers(scan_options))
        
        # Advanced pattern matching
        if not scan_options.get('skip_advanced', False):
            analyzers.append('yara')
        
        logger.info(
            f"Selected {len(analyzers)} analyzers for {language} "
            f"{'MCP ' if is_mcp else ''}project: {', '.join(analyzers)}"
        )
        
        return analyzers
    
    def _should_run_codeql(self, language: str, scan_options: Dict) -> bool:
        """Check if CodeQL should run for the language."""
        codeql_languages = [
            'python', 'javascript', 'typescript', 'java', 
            'go', 'cpp', 'csharp', 'ruby'
        ]
        return (language in codeql_languages and 
                not scan_options.get('skip_advanced', False))
    
    def _get_mcp_analyzers(self, scan_options: Dict) -> List[str]:
        """Get MCP-specific analyzers."""
        analyzers = ['mcp_specific', 'mcp_config']
        
        if scan_options.get('enable_dynamic_analysis', True):
            analyzers.append('dynamic')
        
        return analyzers
    
    def _create_analyzer_tasks(self, analyzer_names: List[str], 
                              repo_path: str, project_info: Dict) -> List:
        """Create async tasks for each analyzer."""
        tasks = []
        
        for name in analyzer_names:
            if name in self.analyzers:
                analyzer = self.analyzers[name]
                logger.info(f"Running {name} analyzer...")
                task = self._run_analyzer_safe(analyzer, repo_path, project_info)
                tasks.append(task)
        
        return tasks
    
    async def _run_analyzer_safe(self, analyzer, repo_path: str, 
                                project_info: Dict[str, Any]) -> List[Finding]:
        """Run analyzer with error handling."""
        try:
            return await analyzer.analyze(repo_path, project_info)
        except Exception as e:
            logger.error(f"Analyzer {analyzer.__class__.__name__} failed: {e}")
            return []
    
    async def _execute_tasks(self, tasks: List) -> List:
        """Execute analyzer tasks in parallel."""
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def _collect_findings(self, results: List) -> List[Finding]:
        """Collect findings from analyzer results."""
        all_findings = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.error(f"Analyzer failed: {result}")
                continue
            if result:
                all_findings.extend(result)
        
        return all_findings