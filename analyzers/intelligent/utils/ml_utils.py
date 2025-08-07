"""ML utility functions and configuration."""

import logging

logger = logging.getLogger(__name__)

# ML availability check
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    from sklearn.cluster import KMeans
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    logger.warning("ML libraries not available")


def is_ml_available() -> bool:
    """Check if ML libraries are available."""
    return ML_AVAILABLE


def get_tfidf_vectorizer() -> 'TfidfVectorizer':
    """Get configured TF-IDF vectorizer."""
    if not ML_AVAILABLE:
        raise ImportError("ML libraries not available")
        
    return TfidfVectorizer(
        max_features=1000,
        stop_words='english',
        ngram_range=(1, 3),
        min_df=2
    )


def get_kmeans_clusterer() -> 'KMeans':
    """Get configured K-Means clusterer."""
    if not ML_AVAILABLE:
        raise ImportError("ML libraries not available")
        
    return KMeans(n_clusters=20, random_state=42)


def get_isolation_forest() -> 'IsolationForest':
    """Get configured Isolation Forest detector.""" 
    if not ML_AVAILABLE:
        raise ImportError("ML libraries not available")
        
    return IsolationForest(contamination=0.1, random_state=42)