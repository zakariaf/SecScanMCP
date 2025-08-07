"""Main intelligent context analyzer orchestrator."""

import logging
from typing import Dict, Any

from .models.analysis_models import CodeContext, LegitimacyAnalysis
from .models.risk_models import ComponentScores
from .components.semantic_analyzer import SemanticIntentAnalyzer
from .components.behavioral_analyzer import BehavioralPatternAnalyzer
from .components.ecosystem_analyzer import EcosystemIntelligenceAnalyzer
from .components.anomaly_detector import AnomalyDetector
from .services.risk_aggregator import RiskAggregator
from .services.learning_system import LearningSystem

logger = logging.getLogger(__name__)


class ExplanationGenerator:
    """Generates human-readable explanations for analysis results."""
    
    def generate_explanation(self, risk_assessment: Dict, 
                           component_scores: ComponentScores) -> str:
        """Generate comprehensive explanation of analysis."""
        legitimacy_score = risk_assessment['legitimacy_score']
        confidence = risk_assessment['confidence']
        
        # Base explanation
        if legitimacy_score >= 0.8:
            base = f"Analysis indicates legitimate functionality (confidence: {confidence:.1%})"
        elif legitimacy_score >= 0.6:
            base = f"Analysis suggests likely legitimate with some concerns (confidence: {confidence:.1%})"
        else:
            base = f"Analysis identifies potential security concerns (confidence: {confidence:.1%})"
        
        # Add component insights
        insights = self._generate_component_insights(component_scores)
        
        explanation = base
        if insights:
            explanation += ". " + ". ".join(insights) + "."
        
        return explanation
    
    def _generate_component_insights(self, scores: ComponentScores) -> list:
        """Generate insights from component scores."""
        insights = []
        
        if scores.intent >= 0.8:
            insights.append("Strong alignment between declared intent and actual behavior")
        elif scores.intent <= 0.4:
            insights.append("Weak alignment between declared intent and actual behavior")
        
        if scores.ecosystem >= 0.7:
            insights.append("Behavior patterns are common in similar legitimate projects")
        elif scores.ecosystem <= 0.4:
            insights.append("Behavior patterns are unusual compared to peer projects")
        
        if scores.anomaly <= 0.3:
            insights.append("Multiple anomalous patterns detected")
        
        return insights


class RecommendationEngine:
    """Generates actionable security recommendations."""
    
    def generate_recommendations(self, context: CodeContext, 
                               risk_assessment: Dict,
                               is_legitimate: bool) -> list:
        """Generate tailored recommendations."""
        recommendations = []
        
        if is_legitimate:
            recommendations.extend(self._legitimate_recommendations(context, risk_assessment))
        else:
            recommendations.extend(self._security_recommendations(context, risk_assessment))
        
        # Universal best practices
        recommendations.extend(self._universal_recommendations())
        
        return recommendations
    
    def _legitimate_recommendations(self, context: CodeContext, 
                                  risk_assessment: Dict) -> list:
        """Recommendations for legitimate code."""
        recommendations = ["Consider declaring permissions in manifest for transparency"]
        
        component_scores = risk_assessment.get('component_scores', {})
        if component_scores.get('intent', 1.0) < 0.7:
            recommendations.append(
                "Improve documentation to clearly explain functionality and required permissions"
            )
        
        return recommendations
    
    def _security_recommendations(self, context: CodeContext, 
                                risk_assessment: Dict) -> list:
        """Security-focused recommendations."""
        recommendations = [
            "Review and justify the necessity of these operations",
            "Implement proper input validation and sanitization"
        ]
        
        component_scores = risk_assessment.get('component_scores', {})
        if component_scores.get('anomaly', 1.0) < 0.5:
            recommendations.append("Address anomalous behavioral patterns identified by analysis")
        
        if len(context.system_operations) > 0:
            recommendations.append("Minimize or eliminate system command execution")
        
        return recommendations
    
    def _universal_recommendations(self) -> list:
        """Universal security best practices."""
        return [
            "Follow principle of least privilege",
            "Implement comprehensive logging for security monitoring"
        ]


class IntelligentContextAnalyzer:
    """
    Main orchestrator for intelligent context-aware security analysis.
    
    Coordinates multiple specialized analyzers following Sandi Metz principles:
    - Small, focused classes with single responsibilities
    - Clear composition over inheritance
    - Dependency injection for testability
    """
    
    def __init__(self, model_path: str = "/tmp/security_ml_models"):
        # Initialize analyzers
        self.semantic_analyzer = SemanticIntentAnalyzer()
        self.behavioral_analyzer = BehavioralPatternAnalyzer()
        self.ecosystem_analyzer = EcosystemIntelligenceAnalyzer()
        self.anomaly_detector = AnomalyDetector()
        
        # Initialize services
        self.risk_aggregator = RiskAggregator()
        self.learning_system = LearningSystem(model_path)
        
        # Initialize utilities
        self.explanation_generator = ExplanationGenerator()
        self.recommendation_engine = RecommendationEngine()
        
        logger.info("Intelligent Context Analyzer initialized with modular architecture")
    
    async def analyze_legitimacy(self, context: CodeContext) -> LegitimacyAnalysis:
        """
        Main analysis orchestration method.
        
        Coordinates all component analyzers and synthesizes results.
        """
        logger.info(f"Starting intelligent analysis for: {context.project_name}")
        
        try:
            # Run component analyses in parallel (could be async)
            component_results = await self._run_component_analyses(context)
            
            # Create component scores
            component_scores = ComponentScores(
                intent=component_results['semantic'][0],
                behavior=component_results['behavioral'][0],
                ecosystem=component_results['ecosystem'][0],
                anomaly=component_results['anomaly'][0]
            )
            
            # Aggregate risk assessment
            risk_assessment = self.risk_aggregator.aggregate_risk(component_scores)
            
            # Generate analysis result
            analysis = self._synthesize_analysis(
                context, risk_assessment, component_results
            )
            
            # Learn from this analysis
            await self.learning_system.record_analysis(context, analysis)
            
            logger.info(f"Analysis complete: legitimate={analysis.is_legitimate}, "
                       f"confidence={analysis.confidence_score:.3f}")
            
            return analysis
            
        except Exception as e:
            logger.error(f"Intelligent analysis failed: {e}")
            return self._create_fallback_analysis(context)
    
    async def _run_component_analyses(self, context: CodeContext) -> Dict[str, Any]:
        """Run all component analyses."""
        results = {}
        
        # Semantic intent analysis
        semantic_score, semantic_evidence = await self.semantic_analyzer.analyze(context)
        results['semantic'] = (semantic_score, semantic_evidence)
        
        # Behavioral pattern analysis
        behavioral_score, behavioral_evidence = await self.behavioral_analyzer.analyze(context)
        results['behavioral'] = (behavioral_score, behavioral_evidence)
        
        # Ecosystem intelligence analysis
        ecosystem_score, ecosystem_evidence = await self.ecosystem_analyzer.analyze(context)
        results['ecosystem'] = (ecosystem_score, ecosystem_evidence)
        
        # Anomaly detection
        anomaly_score, anomaly_evidence = await self.anomaly_detector.analyze(context)
        results['anomaly'] = (anomaly_score, anomaly_evidence)
        
        return results
    
    def _synthesize_analysis(self, context: CodeContext, 
                           risk_assessment: Any,
                           component_results: Dict) -> LegitimacyAnalysis:
        """Synthesize component results into final analysis."""
        
        # Determine legitimacy (adjusted threshold for better sensitivity)
        is_legitimate = (risk_assessment.legitimacy_score >= 0.55 and 
                        risk_assessment.confidence >= 0.3)
        
        # Generate explanation
        explanation = self.explanation_generator.generate_explanation(
            risk_assessment.__dict__, risk_assessment.component_scores
        )
        
        # Generate recommendations
        recommendations = self.recommendation_engine.generate_recommendations(
            context, risk_assessment.__dict__, is_legitimate
        )
        
        # Compile evidence
        evidence = {
            'risk_assessment': risk_assessment.__dict__,
            'component_evidence': {
                'semantic': component_results['semantic'][1],
                'behavioral': component_results['behavioral'][1],
                'ecosystem': component_results['ecosystem'][1],
                'anomaly': component_results['anomaly'][1]
            }
        }
        
        return LegitimacyAnalysis(
            is_legitimate=is_legitimate,
            confidence_score=risk_assessment.confidence,
            risk_level=risk_assessment.risk_level,
            explanation=explanation,
            evidence=evidence,
            recommendations=recommendations,
            intent_alignment_score=risk_assessment.component_scores.intent,
            behavioral_anomaly_score=1.0 - risk_assessment.component_scores.anomaly,
            ecosystem_similarity_score=risk_assessment.component_scores.ecosystem
        )
    
    def _create_fallback_analysis(self, context: CodeContext) -> LegitimacyAnalysis:
        """Create fallback analysis if main analysis fails."""
        return LegitimacyAnalysis(
            is_legitimate=True,
            confidence_score=0.3,
            risk_level="medium",
            explanation="Analysis failed, using conservative fallback assessment",
            evidence={"fallback": True},
            recommendations=["Manual security review recommended"],
            intent_alignment_score=0.5,
            behavioral_anomaly_score=0.5,
            ecosystem_similarity_score=0.5
        )