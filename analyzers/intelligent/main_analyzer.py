"""Main intelligent context analyzer orchestrator."""

import logging
from typing import Dict, Any
from pathlib import Path

from .models.analysis_models import CodeContext, LegitimacyAnalysis
from .models.risk_models import ComponentScores
from .components.semantic_analyzer import SemanticIntentAnalyzer
from .components.behavioral_analyzer import BehavioralPatternAnalyzer
from .components.ecosystem_analyzer import EcosystemIntelligenceAnalyzer
from .components.anomaly_detector import AnomalyDetector
from .services.risk_aggregator import RiskAggregator
from .services.learning_system import LearningSystem
from .utils.config_manager import ConfigManager
from .utils.logging_utils import get_scan_logger, scan_context

logger = get_scan_logger(__name__)


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
    
    def __init__(self, model_path: str = "/tmp/security_ml_models", config_path: str = None):
        # Initialize configuration
        self.config_manager = ConfigManager(Path(config_path) if config_path else None)
        
        # Initialize analyzers with configuration
        self.semantic_analyzer = SemanticIntentAnalyzer()
        self.behavioral_analyzer = BehavioralPatternAnalyzer()
        self.ecosystem_analyzer = EcosystemIntelligenceAnalyzer()
        self.anomaly_detector = AnomalyDetector(self.config_manager)
        
        # Initialize services with configuration
        self.risk_aggregator = RiskAggregator(self.config_manager)
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
        # Create scan context for this analysis
        async with self._analysis_context(context) as analysis_id:
            logger.info("Starting intelligent analysis", 
                       project_name=context.project_name,
                       analysis_id=analysis_id)
            
            try:
                # Run component analyses with timing
                component_results = await self._run_component_analyses(context)
                
                # Create component scores
                component_scores = ComponentScores(
                    intent=component_results['semantic'][0],
                    behavior=component_results['behavioral'][0],
                    ecosystem=component_results['ecosystem'][0],
                    anomaly=component_results['anomaly'][0]
                )
                
                logger.debug("Component analysis completed",
                           intent_score=component_scores.intent,
                           behavior_score=component_scores.behavior,
                           ecosystem_score=component_scores.ecosystem,
                           anomaly_score=component_scores.anomaly)
                
                # Aggregate risk assessment
                risk_assessment = self.risk_aggregator.aggregate_risk(component_scores)
                
                # Generate analysis result
                analysis = self._synthesize_analysis(
                    context, risk_assessment, component_results
                )
                
                # Learn from this analysis
                await self.learning_system.record_analysis(context, analysis)
                
                logger.info("Analysis completed successfully",
                           is_legitimate=analysis.is_legitimate,
                           confidence_score=analysis.confidence_score,
                           risk_level=analysis.risk_level)
                
                return analysis
                
            except Exception as e:
                logger.exception("Intelligent analysis failed", 
                               project_name=context.project_name,
                               error=str(e))
                return self._create_fallback_analysis(context)
    
    async def _analysis_context(self, context: CodeContext):
        """Create analysis context with ID."""
        from contextvars import copy_context
        from .utils.logging_utils import scan_id_context
        
        # Generate analysis-specific ID  
        analysis_id = f"analysis-{context.project_name[:8] if context.project_name else 'unknown'}"
        token = scan_id_context.set(analysis_id)
        
        class AnalysisContext:
            def __init__(self, analysis_id, token):
                self.analysis_id = analysis_id
                self.token = token
                
            async def __aenter__(self):
                return self.analysis_id
                
            async def __aexit__(self, exc_type, exc_val, exc_tb):
                scan_id_context.reset(self.token)
        
        return AnalysisContext(analysis_id, token)
    
    async def _run_component_analyses(self, context: CodeContext) -> Dict[str, Any]:
        """Run all component analyses with timing."""
        import time
        results = {}
        
        # Semantic intent analysis
        start_time = time.time()
        semantic_score, semantic_evidence = await self.semantic_analyzer.analyze(context)
        semantic_duration = time.time() - start_time
        results['semantic'] = (semantic_score, semantic_evidence)
        
        logger.debug("Semantic analysis completed",
                    component="semantic_analyzer", 
                    score=semantic_score,
                    duration_ms=int(semantic_duration * 1000))
        
        # Behavioral pattern analysis  
        start_time = time.time()
        behavioral_score, behavioral_evidence = await self.behavioral_analyzer.analyze(context)
        behavioral_duration = time.time() - start_time
        results['behavioral'] = (behavioral_score, behavioral_evidence)
        
        logger.debug("Behavioral analysis completed",
                    component="behavioral_analyzer",
                    score=behavioral_score, 
                    duration_ms=int(behavioral_duration * 1000))
        
        # Ecosystem intelligence analysis
        start_time = time.time()
        ecosystem_score, ecosystem_evidence = await self.ecosystem_analyzer.analyze(context)
        ecosystem_duration = time.time() - start_time
        results['ecosystem'] = (ecosystem_score, ecosystem_evidence)
        
        logger.debug("Ecosystem analysis completed",
                    component="ecosystem_analyzer",
                    score=ecosystem_score,
                    duration_ms=int(ecosystem_duration * 1000))
        
        # Anomaly detection
        start_time = time.time()
        anomaly_score, anomaly_evidence = await self.anomaly_detector.analyze(context)
        anomaly_duration = time.time() - start_time
        results['anomaly'] = (anomaly_score, anomaly_evidence)
        
        logger.debug("Anomaly detection completed",
                    component="anomaly_detector",
                    score=anomaly_score,
                    duration_ms=int(anomaly_duration * 1000))
        
        total_duration = semantic_duration + behavioral_duration + ecosystem_duration + anomaly_duration
        logger.info("All component analyses completed",
                   total_duration_ms=int(total_duration * 1000),
                   semantic_duration_ms=int(semantic_duration * 1000),
                   behavioral_duration_ms=int(behavioral_duration * 1000),
                   ecosystem_duration_ms=int(ecosystem_duration * 1000),
                   anomaly_duration_ms=int(anomaly_duration * 1000))
        
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