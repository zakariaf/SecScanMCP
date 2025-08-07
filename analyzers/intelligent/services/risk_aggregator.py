"""Risk assessment aggregation service."""

import numpy as np
from typing import Dict, Any, List
from ..models.risk_models import RiskAssessment, ComponentScores


class ScoreWeighter:
    """Handles weighting of component scores."""
    
    def __init__(self):
        # Default weights based on reliability and importance
        self.default_weights = {
            'intent': 0.35,      # High weight - intent alignment crucial
            'behavior': 0.25,    # Medium weight - patterns matter
            'ecosystem': 0.25,   # Medium weight - peer comparison valuable
            'anomaly': 0.15      # Lower weight - can have false positives
        }
    
    def get_weights(self, context: Dict[str, Any] = None) -> Dict[str, float]:
        """Get component weights, potentially adjusted by context."""
        weights = self.default_weights.copy()
        
        # Context-based weight adjustments could go here
        # For example, if we have high confidence in ecosystem data,
        # we might increase its weight
        
        return weights
    
    def normalize_weights(self, weights: Dict[str, float]) -> Dict[str, float]:
        """Ensure weights sum to 1.0."""
        total = sum(weights.values())
        if total == 0:
            return {k: 1.0/len(weights) for k in weights.keys()}
        return {k: v/total for k, v in weights.items()}


class ConfidenceCalculator:
    """Calculates confidence based on signal agreement."""
    
    def calculate_confidence(self, scores: List[float]) -> float:
        """Calculate confidence from score agreement."""
        if not scores or len(scores) < 2:
            return 0.5
        
        mean_score = np.mean(scores)
        if mean_score == 0:
            return 0.1
        
        # Confidence inversely related to coefficient of variation
        std_dev = np.std(scores)
        coefficient_of_variation = std_dev / mean_score
        
        # Convert to confidence (0-1 scale)
        confidence = 1.0 - min(1.0, coefficient_of_variation)
        
        # Ensure minimum confidence
        return max(0.1, confidence)


class RiskLevelClassifier:
    """Classifies risk level based on score and confidence."""
    
    def __init__(self):
        self.thresholds = {
            'high_legitimacy': 0.75,
            'medium_legitimacy': 0.55,
            'high_confidence': 0.6,
            'medium_confidence': 0.3
        }
    
    def classify_risk(self, legitimacy_score: float, confidence: float) -> str:
        """Classify risk level based on legitimacy and confidence."""
        if (legitimacy_score >= self.thresholds['high_legitimacy'] and 
            confidence >= self.thresholds['high_confidence']):
            return "low"
        elif (legitimacy_score >= self.thresholds['medium_legitimacy'] and 
              confidence >= self.thresholds['medium_confidence']):
            return "medium"
        else:
            return "high"
    
    def update_thresholds(self, new_thresholds: Dict[str, float]):
        """Update classification thresholds."""
        self.thresholds.update(new_thresholds)


class RiskAggregator:
    """Aggregates component scores into comprehensive risk assessment."""
    
    def __init__(self):
        self.weighter = ScoreWeighter()
        self.confidence_calc = ConfidenceCalculator()
        self.risk_classifier = RiskLevelClassifier()
    
    def aggregate_risk(self, component_scores: ComponentScores, 
                      context: Dict[str, Any] = None) -> RiskAssessment:
        """Aggregate component scores into risk assessment."""
        
        # Get component weights
        weights = self.weighter.get_weights(context)
        weights = self.weighter.normalize_weights(weights)
        
        # Calculate weighted legitimacy score
        legitimacy_score = self._calculate_weighted_score(
            component_scores, weights
        )
        
        # Calculate confidence from signal agreement
        scores = [
            component_scores.intent,
            component_scores.behavior,
            component_scores.ecosystem,
            component_scores.anomaly
        ]
        confidence = self.confidence_calc.calculate_confidence(scores)
        
        # Classify risk level
        risk_level = self.risk_classifier.classify_risk(
            legitimacy_score, confidence
        )
        
        # Calculate signal agreement
        signal_agreement = 1.0 - np.std(scores)
        
        return RiskAssessment(
            legitimacy_score=legitimacy_score,
            confidence=confidence,
            risk_level=risk_level,
            signal_agreement=signal_agreement,
            component_scores=component_scores
        )
    
    def _calculate_weighted_score(self, scores: ComponentScores, 
                                 weights: Dict[str, float]) -> float:
        """Calculate weighted average of component scores."""
        weighted_sum = (
            scores.intent * weights['intent'] +
            scores.behavior * weights['behavior'] +
            scores.ecosystem * weights['ecosystem'] +
            scores.anomaly * weights['anomaly']
        )
        
        return max(0.0, min(1.0, weighted_sum))
    
    def get_component_contributions(self, component_scores: ComponentScores,
                                   weights: Dict[str, float]) -> Dict[str, float]:
        """Get individual component contributions to final score."""
        return {
            'intent': component_scores.intent * weights['intent'],
            'behavior': component_scores.behavior * weights['behavior'],
            'ecosystem': component_scores.ecosystem * weights['ecosystem'],
            'anomaly': component_scores.anomaly * weights['anomaly']
        }