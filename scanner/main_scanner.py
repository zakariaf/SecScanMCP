"""Main security scanner orchestrator with clean architecture."""

import logging
from typing import Dict, Any

from models import ScanResult
from enhanced_scoring import EnhancedSecurityScorer

from .services.repository_service import RepositoryService
from .services.analyzer_orchestrator import AnalyzerOrchestrator
from .services.finding_service import FindingService
from .services.finding_aggregator import FindingAggregator
from .services.result_builder import ResultBuilder

logger = logging.getLogger(__name__)


class SecurityScanner:
    """
    Main scanner that orchestrates all security analysis tools.
    
    This class follows clean architecture principles with clear separation
    of concerns. Each service handles a specific domain of the scanning process.
    """
    
    def __init__(self):
        # Initialize services
        self.repository_service = RepositoryService()
        self.analyzer_orchestrator = AnalyzerOrchestrator()
        self.finding_service = FindingService()
        self.finding_aggregator = FindingAggregator()
        self.result_builder = ResultBuilder()
        self.enhanced_scorer = EnhancedSecurityScorer()
    
    async def scan_repository(self, repository_url: str, temp_dir: str,
                             scan_options: Dict[str, Any] = None) -> ScanResult:
        """
        Main scanning orchestration method.
        
        Args:
            repository_url: Git repository URL to scan
            temp_dir: Temporary directory for cloning
            scan_options: Optional configuration
            
        Returns:
            Complete scan results with findings and score
        """
        scan_options = scan_options or {}
        
        # Step 1: Clone and analyze repository
        repo_path = await self.repository_service.clone_repository(
            repository_url, temp_dir
        )
        project_info = await self.repository_service.analyze_project(repo_path)
        
        # Step 2: Run security analyzers
        raw_findings = await self.analyzer_orchestrator.run_analyzers(
            repo_path, project_info, scan_options
        )
        
        # Step 3: Process findings
        deduplicated = self.finding_service.deduplicate_findings(raw_findings)
        aggregated = self.finding_aggregator.aggregate_for_scoring(deduplicated)
        
        # Step 4: Calculate scores
        enhanced_scores = self.enhanced_scorer.calculate_both_scores(aggregated)
        
        # Step 5: Categorize findings
        user_centric = self.finding_service.extract_user_centric_findings(aggregated)
        developer_centric = self.finding_service.extract_developer_centric_findings(aggregated)
        
        # Step 6: Organize findings
        organized = self.finding_service.organize_by_analyzer(aggregated)
        
        # Step 7: Build final result
        return self.result_builder.build_result(
            repository_url=repository_url,
            project_info=project_info,
            findings=aggregated,
            enhanced_scores=enhanced_scores,
            user_centric=user_centric,
            developer_centric=developer_centric,
            organized_findings=organized,
            scan_options=scan_options
        )