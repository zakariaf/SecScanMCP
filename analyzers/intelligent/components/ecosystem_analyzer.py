"""Ecosystem intelligence analysis component."""

from typing import Tuple, Dict, Any, List

from .base_analyzer import BaseAnalyzer
from ..models.analysis_models import CodeContext
from ..utils.logging_utils import get_scan_logger

logger = get_scan_logger(__name__)


class ProjectSimilarityCalculator:
    """Calculates similarity between projects."""
    
    def calculate_similarity(self, project1: Dict, project2: Dict) -> float:
        """Calculate similarity score between two projects."""
        score = 0.0
        factors = 0
        
        # Language similarity
        if project1.get('language') == project2.get('language'):
            score += 0.3
        factors += 1
        
        # Project type similarity
        if project1.get('type') == project2.get('type'):
            score += 0.4
        factors += 1
        
        # Dependency overlap
        deps1 = set(project1.get('dependencies', []))
        deps2 = set(project2.get('dependencies', []))
        if deps1 or deps2:
            overlap = len(deps1 & deps2) / len(deps1 | deps2) if (deps1 | deps2) else 0
            score += overlap * 0.3
        factors += 1
        
        return score / factors if factors > 0 else 0.0


class EcosystemDatabase:
    """Mock ecosystem database for project intelligence."""
    
    def __init__(self):
        self.projects = self._load_sample_projects()
        self.similarity_calc = ProjectSimilarityCalculator()
    
    def find_similar_projects(self, target_project: Dict, limit: int = 10) -> List[Dict]:
        """Find similar projects in the ecosystem."""
        similarities = []
        
        for project in self.projects:
            similarity = self.similarity_calc.calculate_similarity(target_project, project)
            if similarity > 0.2:  # Minimum similarity threshold
                project_with_sim = project.copy()
                project_with_sim['similarity'] = similarity
                similarities.append(project_with_sim)
        
        # Sort by similarity and return top results
        similarities.sort(key=lambda x: x['similarity'], reverse=True)
        return similarities[:limit]
    
    def get_pattern_prevalence(self, pattern_signature: str) -> Dict[str, float]:
        """Get prevalence statistics for a pattern."""
        # In production, this would query a real database
        prevalence_data = {
            'mcp_file_storage': {'prevalence': 0.7, 'legitimacy_rate': 0.85},
            'network_heavy': {'prevalence': 0.3, 'legitimacy_rate': 0.45},
            'system_commands': {'prevalence': 0.1, 'legitimacy_rate': 0.2}
        }
        
        return prevalence_data.get(pattern_signature, {
            'prevalence': 0.5,
            'legitimacy_rate': 0.5
        })
    
    def _load_sample_projects(self) -> List[Dict]:
        """Load sample projects for ecosystem comparison."""
        return [
            {
                'name': 'mcp-memory-server',
                'type': 'mcp_server',
                'language': 'typescript',
                'dependencies': ['mcp', 'node'],
                'legitimacy_score': 0.9,
                'file_operations': 3,
                'network_operations': 0,
                'system_operations': 0
            },
            {
                'name': 'mcp-filesystem-tool',
                'type': 'mcp_server',
                'language': 'python',
                'dependencies': ['mcp', 'python'],
                'legitimacy_score': 0.85,
                'file_operations': 8,
                'network_operations': 1,
                'system_operations': 0
            },
            {
                'name': 'web-scraper-tool',
                'type': 'utility',
                'language': 'python',
                'dependencies': ['requests', 'beautifulsoup'],
                'legitimacy_score': 0.6,
                'file_operations': 2,
                'network_operations': 15,
                'system_operations': 0
            },
            {
                'name': 'system-admin-helper',
                'type': 'utility',
                'language': 'bash',
                'dependencies': ['bash'],
                'legitimacy_score': 0.3,
                'file_operations': 5,
                'network_operations': 3,
                'system_operations': 8
            }
        ]


class CommunityReputationAnalyzer:
    """Analyzes community reputation signals."""
    
    def analyze_reputation(self, context: CodeContext) -> Dict[str, float]:
        """Analyze community reputation indicators."""
        reputation = {
            'dependency_trust': self._analyze_dependency_trust(context.dependencies),
            'naming_convention': self._analyze_naming_convention(context.project_name),
            'documentation_quality': self._analyze_documentation(context),
            'community_signals': self._analyze_community_signals(context)
        }
        
        # Calculate overall reputation score
        reputation['overall_score'] = sum(reputation.values()) / len(reputation)
        return reputation
    
    def _analyze_dependency_trust(self, dependencies: List[str]) -> float:
        """Analyze trustworthiness of dependencies."""
        if not dependencies:
            return 0.5
        
        trusted_deps = {'mcp', 'modelcontextprotocol', 'fastapi', 'requests', 
                       'numpy', 'pandas', 'flask', 'express', 'react'}
        
        trusted_count = sum(1 for dep in dependencies 
                           if any(trusted in dep.lower() for trusted in trusted_deps))
        
        return min(1.0, trusted_count / len(dependencies) + 0.3)
    
    def _analyze_naming_convention(self, project_name: str) -> float:
        """Analyze if project follows naming conventions."""
        if not project_name:
            return 0.5
        
        name_lower = project_name.lower()
        
        # Good indicators
        good_patterns = ['mcp-', 'server', 'client', 'tool', 'helper', 'lib']
        good_score = sum(0.2 for pattern in good_patterns if pattern in name_lower)
        
        # Suspicious patterns
        bad_patterns = ['hack', 'crack', 'exploit', 'backdoor']
        bad_score = sum(0.3 for pattern in bad_patterns if pattern in name_lower)
        
        return max(0.1, min(1.0, 0.5 + good_score - bad_score))
    
    def _analyze_documentation(self, context: CodeContext) -> float:
        """Analyze documentation quality."""
        score = 0.0
        
        if context.readme_content and len(context.readme_content) > 100:
            score += 0.4
        
        if context.docstrings and len(context.docstrings) > 0:
            score += 0.3
        
        if context.project_description and len(context.project_description) > 20:
            score += 0.3
        
        return min(1.0, score)
    
    def _analyze_community_signals(self, context: CodeContext) -> float:
        """Analyze community signals."""
        reputation = context.community_reputation
        
        if not reputation:
            return 0.5
        
        signals = {
            'stars': reputation.get('stars', 0),
            'forks': reputation.get('forks', 0),
            'issues': reputation.get('open_issues', 0),
            'contributors': reputation.get('contributors', 0)
        }
        
        # Normalize and weight signals
        score = 0.0
        if signals['stars'] > 10:
            score += 0.3
        if signals['forks'] > 2:
            score += 0.2
        if signals['contributors'] > 1:
            score += 0.3
        if signals['issues'] < signals['stars'] * 0.3:  # Reasonable issue ratio
            score += 0.2
        
        return min(1.0, score)


class EcosystemIntelligenceAnalyzer(BaseAnalyzer):
    """Analyzes project legitimacy using ecosystem intelligence."""
    
    def __init__(self):
        self.ecosystem_db = EcosystemDatabase()
        self.reputation_analyzer = CommunityReputationAnalyzer()
    
    async def analyze(self, context: CodeContext) -> Tuple[float, Dict[str, Any]]:
        """Analyze legitimacy using ecosystem intelligence."""
        evidence = {
            'similar_projects': [],
            'pattern_prevalence': {},
            'community_reputation': {},
            'ecosystem_percentile': 0.0
        }
        
        # Create project profile for comparison
        project_profile = self._create_project_profile(context)
        
        # Find similar projects
        similar_projects = self.ecosystem_db.find_similar_projects(project_profile)
        evidence['similar_projects'] = similar_projects
        
        # Analyze community reputation
        reputation = self.reputation_analyzer.analyze_reputation(context)
        evidence['community_reputation'] = reputation
        
        # Calculate pattern prevalence
        pattern_sig = self._create_pattern_signature(context)
        prevalence = self.ecosystem_db.get_pattern_prevalence(pattern_sig)
        evidence['pattern_prevalence'] = prevalence
        
        # Calculate legitimacy score
        legitimacy_score = self._calculate_ecosystem_legitimacy(
            similar_projects, reputation, prevalence
        )
        
        evidence['ecosystem_percentile'] = self._calculate_percentile(legitimacy_score)
        
        return float(legitimacy_score), evidence
    
    def _create_project_profile(self, context: CodeContext) -> Dict[str, Any]:
        """Create project profile for ecosystem comparison."""
        return {
            'name': context.project_name,
            'type': context.project_type,
            'language': context.language,
            'dependencies': context.dependencies,
            'file_operations': len(context.file_operations),
            'network_operations': len(context.network_operations),
            'system_operations': len(context.system_operations)
        }
    
    def _create_pattern_signature(self, context: CodeContext) -> str:
        """Create pattern signature for prevalence lookup."""
        file_ops = len(context.file_operations)
        net_ops = len(context.network_operations)
        sys_ops = len(context.system_operations)
        
        if file_ops > 0 and net_ops == 0 and sys_ops == 0:
            return 'mcp_file_storage'
        elif net_ops > file_ops and net_ops > 10:
            return 'network_heavy'
        elif sys_ops > 0:
            return 'system_commands'
        else:
            return 'general_utility'
    
    def _calculate_ecosystem_legitimacy(self, similar_projects: List[Dict], 
                                      reputation: Dict, prevalence: Dict) -> float:
        """Calculate legitimacy based on ecosystem intelligence."""
        scores = []
        
        # Score from similar projects
        if similar_projects:
            peer_scores = [p.get('legitimacy_score', 0.5) for p in similar_projects]
            peer_weights = [p.get('similarity', 0.5) for p in similar_projects]
            
            if peer_weights:
                weighted_peer_score = sum(s * w for s, w in zip(peer_scores, peer_weights))
                weighted_peer_score /= sum(peer_weights)
                scores.append(weighted_peer_score * 0.4)
        
        # Score from community reputation
        reputation_score = reputation.get('overall_score', 0.5)
        scores.append(reputation_score * 0.3)
        
        # Score from pattern prevalence
        prevalence_score = prevalence.get('legitimacy_rate', 0.5)
        scores.append(prevalence_score * 0.3)
        
        return sum(scores) if scores else 0.5
    
    def _calculate_percentile(self, score: float) -> float:
        """Calculate percentile rank in ecosystem."""
        # Simple percentile calculation (would use real data in production)
        return min(1.0, max(0.0, score))