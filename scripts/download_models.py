#!/usr/bin/env python3
"""Download and cache transformer models for production deployment."""

import os
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

def download_models():
    """Download and cache transformer models."""
    try:
        from sentence_transformers import SentenceTransformer
        
        # Create model cache directory
        model_cache = Path('/app/models/embeddings')
        model_cache.mkdir(parents=True, exist_ok=True)
        
        # Download and cache the model used by the intelligent analyzer
        model_name = 'all-MiniLM-L6-v2'
        logger.info(f'Downloading transformer model: {model_name}')
        
        model = SentenceTransformer(model_name)
        model_path = model_cache / model_name
        model.save(str(model_path))
        
        logger.info(f'Cached transformer model to {model_path}')
        logger.info(f'Model embedding dimension: {model.get_sentence_embedding_dimension()}')
        
        return True
        
    except ImportError as e:
        logger.warning(f'sentence-transformers not available: {e}')
        logger.info('Will use TF-IDF fallback at runtime')
        return False
    except Exception as e:
        logger.error(f'Failed to cache transformer model: {e}')
        logger.info('Container will attempt model download at runtime')
        return False

if __name__ == "__main__":
    success = download_models()
    if success:
        logger.info("✅ Model download and caching completed successfully")
    else:
        logger.warning("⚠️ Model caching failed, will use fallback")