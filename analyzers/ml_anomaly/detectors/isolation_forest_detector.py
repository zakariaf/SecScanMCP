"""Isolation Forest detector for anomaly detection."""

import numpy as np
import logging
import math
import random
from typing import Dict, Any

logger = logging.getLogger(__name__)


class IsolationForestDetector:
    """Simplified Isolation Forest implementation for anomaly detection."""
    
    def __init__(self, n_trees: int = 100, max_depth: int = 10):
        self.n_trees = n_trees
        self.max_depth = max_depth
        self.trees = []
        self.trained = False
        self.feature_mins = None
        self.feature_maxs = None
        self.logger = logging.getLogger(__name__)
    
    def fit(self, training_data: np.ndarray):
        """Train the isolation forest."""
        if len(training_data) == 0:
            return
        
        try:
            self.feature_mins = np.min(training_data, axis=0)
            self.feature_maxs = np.max(training_data, axis=0)
            
            # Normalize training data
            normalized_data = self._normalize_features(training_data)
            
            # Build isolation trees
            self.trees = []
            n_samples = len(normalized_data)
            
            for _ in range(self.n_trees):
                # Sample subset of data
                sample_size = min(256, n_samples)  # Standard subsample size
                indices = np.random.choice(n_samples, sample_size, replace=False)
                sample_data = normalized_data[indices]
                
                # Build tree
                tree = self._build_tree(sample_data, 0)
                self.trees.append(tree)
            
            self.trained = True
            self.logger.info(f"Isolation Forest trained with {self.n_trees} trees")
            
        except Exception as e:
            self.logger.error(f"Isolation Forest training failed: {e}")
    
    def predict_anomaly_score(self, data_point: np.ndarray) -> float:
        """Predict anomaly score for a data point."""
        if not self.trained or len(self.trees) == 0:
            return 0.5  # Neutral score if not trained
        
        try:
            # Normalize the data point
            normalized_point = self._normalize_features(data_point.reshape(1, -1))[0]
            
            # Calculate average path length across all trees
            path_lengths = []
            for tree in self.trees:
                length = self._calculate_path_length(normalized_point, tree, 0)
                path_lengths.append(length)
            
            avg_path_length = np.mean(path_lengths)
            
            # Convert to anomaly score (0-1, higher = more anomalous)
            n_samples = 256  # Standard sample size used in training
            expected_length = self._expected_path_length(n_samples)
            
            if expected_length > 0:
                anomaly_score = 2 ** (-avg_path_length / expected_length)
            else:
                anomaly_score = 0.5
            
            return min(max(anomaly_score, 0.0), 1.0)  # Clamp to [0, 1]
            
        except Exception as e:
            self.logger.debug(f"Anomaly score prediction failed: {e}")
            return 0.5
    
    def _normalize_features(self, data: np.ndarray) -> np.ndarray:
        """Normalize features to [0, 1] range."""
        if self.feature_mins is None or self.feature_maxs is None:
            return data
        
        # Avoid division by zero
        ranges = self.feature_maxs - self.feature_mins
        ranges[ranges == 0] = 1.0
        
        return (data - self.feature_mins) / ranges
    
    def _build_tree(self, data: np.ndarray, depth: int) -> Dict[str, Any]:
        """Build an isolation tree recursively."""
        n_samples, n_features = data.shape
        
        # Stop conditions
        if depth >= self.max_depth or n_samples <= 1:
            return {'type': 'leaf', 'size': n_samples}
        
        # Random feature and split point
        feature_idx = random.randint(0, n_features - 1)
        feature_values = data[:, feature_idx]
        
        if len(np.unique(feature_values)) <= 1:
            return {'type': 'leaf', 'size': n_samples}
        
        min_val, max_val = np.min(feature_values), np.max(feature_values)
        if min_val == max_val:
            return {'type': 'leaf', 'size': n_samples}
        
        split_value = random.uniform(min_val, max_val)
        
        # Split data
        left_mask = feature_values < split_value
        right_mask = ~left_mask
        
        left_data = data[left_mask]
        right_data = data[right_mask]
        
        # Handle edge cases
        if len(left_data) == 0 or len(right_data) == 0:
            return {'type': 'leaf', 'size': n_samples}
        
        # Recursive build
        return {
            'type': 'node',
            'feature': feature_idx,
            'threshold': split_value,
            'left': self._build_tree(left_data, depth + 1),
            'right': self._build_tree(right_data, depth + 1)
        }
    
    def _calculate_path_length(self, point: np.ndarray, tree: Dict[str, Any], depth: int) -> float:
        """Calculate path length of a point through a tree."""
        if tree['type'] == 'leaf':
            # Adjust for unfinished path
            size = tree['size']
            if size > 1:
                return depth + self._expected_path_length(size)
            return depth
        
        feature_value = point[tree['feature']]
        if feature_value < tree['threshold']:
            return self._calculate_path_length(point, tree['left'], depth + 1)
        else:
            return self._calculate_path_length(point, tree['right'], depth + 1)
    
    def _expected_path_length(self, n: int) -> float:
        """Calculate expected path length for BST with n points."""
        if n <= 1:
            return 0
        if n == 2:
            return 1
        
        # Harmonic number approximation
        return 2 * (math.log(n - 1) + 0.5772156649) - (2 * (n - 1) / n)
    
    def is_trained(self) -> bool:
        """Check if the detector is trained."""
        return self.trained