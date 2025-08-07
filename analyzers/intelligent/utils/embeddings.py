"""Frozen embeddings system using sentence-transformers."""

import numpy as np
import pickle
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any
import hashlib
import os

logger = logging.getLogger(__name__)

try:
    from sentence_transformers import SentenceTransformer
    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning("sentence-transformers not available, using TF-IDF fallback")

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class FrozenEmbedder:
    """Frozen embeddings system that doesn't retrain at runtime."""
    
    def __init__(self, model_path: Path, model_name: str = "all-MiniLM-L6-v2"):
        self.model_path = model_path
        self.model_name = model_name
        self.model = None
        self.fallback_vectorizer = None
        self._vocabulary_cache = {}
        
        # Ensure model directory exists
        self.model_path.mkdir(parents=True, exist_ok=True)
        
        self._initialize_embedder()
    
    def _initialize_embedder(self):
        """Initialize the embeddings system."""
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                self._load_or_download_transformer()
            except Exception as e:
                logger.warning(f"Failed to load transformer model: {e}")
                self._initialize_tfidf_fallback()
        else:
            self._initialize_tfidf_fallback()
    
    def _load_or_download_transformer(self):
        """Load or download sentence transformer model."""
        model_cache_path = self.model_path / self.model_name
        
        if model_cache_path.exists():
            logger.info(f"Loading cached transformer model from {model_cache_path}")
            self.model = SentenceTransformer(str(model_cache_path))
        else:
            # In production container, model should be pre-cached
            # Check if running in container (environment variable set in Dockerfile)
            in_container = os.environ.get('INTELLIGENT_ANALYZER_MODEL_PATH') is not None
            
            if in_container:
                logger.warning(f"Model not found in container cache: {model_cache_path}")
                logger.info("Attempting to download model at runtime (not recommended for production)")
            else:
                logger.info(f"Downloading transformer model {self.model_name} (development mode)")
            
            self.model = SentenceTransformer(self.model_name)
            # Save to cache
            try:
                self.model.save(str(model_cache_path))
                logger.info(f"Cached transformer model to {model_cache_path}")
            except Exception as e:
                logger.warning(f"Failed to cache model: {e} (using in-memory model)")
    
    def _initialize_tfidf_fallback(self):
        """Initialize TF-IDF fallback system."""
        if not SKLEARN_AVAILABLE:
            logger.error("Neither sentence-transformers nor scikit-learn available")
            return
        
        vectorizer_path = self.model_path / "tfidf_vectorizer.pkl"
        
        if vectorizer_path.exists():
            logger.info("Loading cached TF-IDF vectorizer")
            with open(vectorizer_path, 'rb') as f:
                self.fallback_vectorizer = pickle.load(f)
        else:
            # Create and cache a basic vectorizer with common vocabulary
            logger.info("Creating TF-IDF fallback vectorizer")
            self.fallback_vectorizer = TfidfVectorizer(
                max_features=1000,
                stop_words='english',
                ngram_range=(1, 2),
                min_df=1,  # More permissive for small datasets
                lowercase=True
            )
            
            # Pre-train on a basic vocabulary to avoid runtime fitting
            basic_vocab = [
                "storage memory cache data persist save write read",
                "server tool function provide enable allow",
                "mcp protocol client interface api",
                "file operations network requests system commands",
                "security vulnerability malware exploit",
                "legitimate functionality behavior pattern"
            ]
            
            self.fallback_vectorizer.fit(basic_vocab)
            
            # Cache the vectorizer
            with open(vectorizer_path, 'wb') as f:
                pickle.dump(self.fallback_vectorizer, f)
            logger.info(f"Cached TF-IDF vectorizer to {vectorizer_path}")
    
    def encode(self, texts: List[str]) -> np.ndarray:
        """Encode texts to embeddings."""
        if not texts:
            return np.array([])
        
        if self.model is not None:
            return self._encode_transformer(texts)
        elif self.fallback_vectorizer is not None:
            return self._encode_tfidf(texts)
        else:
            logger.error("No embeddings system available")
            return np.zeros((len(texts), 384))  # Return zero vectors
    
    def _encode_transformer(self, texts: List[str]) -> np.ndarray:
        """Encode using sentence transformer."""
        try:
            embeddings = self.model.encode(texts, convert_to_tensor=False)
            return embeddings
        except Exception as e:
            logger.error(f"Transformer encoding failed: {e}")
            return self._encode_tfidf(texts)
    
    def _encode_tfidf(self, texts: List[str]) -> np.ndarray:
        """Encode using TF-IDF fallback."""
        try:
            # Use transform (not fit_transform) to avoid runtime training
            vectors = self.fallback_vectorizer.transform(texts)
            return vectors.toarray()
        except Exception as e:
            logger.error(f"TF-IDF encoding failed: {e}")
            return np.zeros((len(texts), 1000))
    
    def calculate_similarity(self, embeddings1: np.ndarray, embeddings2: np.ndarray) -> np.ndarray:
        """Calculate cosine similarity between embeddings."""
        if embeddings1.size == 0 or embeddings2.size == 0:
            return np.array([[0.0]])
        
        if not SKLEARN_AVAILABLE:
            # Simple dot product similarity if sklearn not available
            norm1 = np.linalg.norm(embeddings1, axis=1, keepdims=True)
            norm2 = np.linalg.norm(embeddings2, axis=1, keepdims=True)
            
            norm1[norm1 == 0] = 1  # Avoid division by zero
            norm2[norm2 == 0] = 1
            
            embeddings1_norm = embeddings1 / norm1
            embeddings2_norm = embeddings2 / norm2
            
            return np.dot(embeddings1_norm, embeddings2_norm.T)
        
        return cosine_similarity(embeddings1, embeddings2)
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get information about cached models."""
        info = {
            'model_path': str(self.model_path),
            'transformer_available': self.model is not None,
            'tfidf_available': self.fallback_vectorizer is not None,
            'sentence_transformers_installed': SENTENCE_TRANSFORMERS_AVAILABLE,
            'sklearn_installed': SKLEARN_AVAILABLE,
            'in_container': os.environ.get('INTELLIGENT_ANALYZER_MODEL_PATH') is not None,
            'model_cached': (self.model_path / self.model_name).exists() if self.model_path else False
        }
        
        if self.model is not None:
            info['transformer_model'] = self.model_name
            info['embedding_dimension'] = self.model.get_sentence_embedding_dimension()
        
        return info


class EmbeddingsManager:
    """Manages frozen embeddings across the intelligent analyzer."""
    
    _instance = None
    
    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self, model_path: Optional[Path] = None):
        if hasattr(self, '_initialized'):
            return
        
        # Use container-aware path resolution
        if model_path is None:
            # Check environment variable (set in Dockerfile)
            env_path = os.environ.get('INTELLIGENT_ANALYZER_MODEL_PATH')
            if env_path:
                model_path = Path(env_path)
            else:
                # Fallback to relative path for development
                model_path = Path(__file__).parent.parent.parent / "models" / "embeddings"
            
        self.model_path = model_path
        self.embedder = FrozenEmbedder(self.model_path)
        self._initialized = True
        
        logger.info(f"Embeddings manager initialized: {self.embedder.get_cache_info()}")
    
    def encode_texts(self, texts: List[str]) -> np.ndarray:
        """Encode texts to embeddings."""
        return self.embedder.encode(texts)
    
    def calculate_similarity(self, texts1: List[str], texts2: List[str]) -> float:
        """Calculate maximum similarity between two text groups."""
        if not texts1 or not texts2:
            return 0.0
        
        embeddings1 = self.encode_texts(texts1)
        embeddings2 = self.encode_texts(texts2)
        
        similarity_matrix = self.embedder.calculate_similarity(embeddings1, embeddings2)
        
        if similarity_matrix.size > 0:
            return float(np.max(similarity_matrix))
        
        return 0.0
    
    def find_best_matches(self, texts1: List[str], texts2: List[str], 
                         threshold: float = 0.3) -> List[Dict[str, Any]]:
        """Find best semantic matches between text groups."""
        if not texts1 or not texts2:
            return []
        
        embeddings1 = self.encode_texts(texts1)
        embeddings2 = self.encode_texts(texts2)
        
        similarity_matrix = self.embedder.calculate_similarity(embeddings1, embeddings2)
        
        matches = []
        for i, text1 in enumerate(texts1):
            for j, text2 in enumerate(texts2):
                if i < similarity_matrix.shape[0] and j < similarity_matrix.shape[1]:
                    score = similarity_matrix[i, j]
                    if score > threshold:
                        matches.append({
                            'text1': text1,
                            'text2': text2,
                            'similarity': float(score)
                        })
        
        # Sort by similarity and return top matches
        matches.sort(key=lambda x: x['similarity'], reverse=True)
        return matches[:5]