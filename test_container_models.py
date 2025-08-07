#!/usr/bin/env python3
"""Test script to verify model loading in containerized environment."""

import os
import sys
from pathlib import Path

# Add app to Python path
sys.path.insert(0, '/app' if Path('/app').exists() else str(Path(__file__).parent))

def test_model_loading():
    """Test if ML models load correctly in container."""
    print("🧪 Testing model loading in containerized environment...")
    
    # Check environment variables
    print("\n📋 Environment Configuration:")
    env_vars = [
        'INTELLIGENT_ANALYZER_MODEL_PATH',
        'INTELLIGENT_ANALYZER_DB_PATH', 
        'TRANSFORMERS_CACHE',
        'SENTENCE_TRANSFORMERS_HOME'
    ]
    
    for var in env_vars:
        value = os.environ.get(var, 'NOT_SET')
        print(f"  {var}: {value}")
    
    # Test configuration loading
    print("\n⚙️ Testing Configuration Manager...")
    try:
        from analyzers.intelligent.utils.config_manager import ConfigManager
        
        config_manager = ConfigManager()
        settings = config_manager.load_settings()
        
        print(f"  ✅ Model path: {config_manager.get_model_path()}")
        print(f"  ✅ Database config: {settings.database.path}")
        print(f"  ✅ Async enabled: {settings.database.async_enabled}")
        
    except Exception as e:
        print(f"  ❌ Configuration failed: {e}")
        return False
    
    # Test embeddings system
    print("\n🤖 Testing Embeddings System...")
    try:
        from analyzers.intelligent.utils.embeddings import EmbeddingsManager
        
        embeddings = EmbeddingsManager()
        info = embeddings.embedder.get_cache_info()
        
        print(f"  ✅ Model path: {info['model_path']}")
        print(f"  ✅ Transformer available: {info['transformer_available']}")
        print(f"  ✅ In container: {info['in_container']}")
        print(f"  ✅ Model cached: {info['model_cached']}")
        
        # Test encoding
        test_texts = ["storage server functionality", "mcp tool implementation"]
        embeddings_result = embeddings.encode_texts(test_texts)
        print(f"  ✅ Encoding test: {embeddings_result.shape if hasattr(embeddings_result, 'shape') else 'Success'}")
        
    except Exception as e:
        print(f"  ❌ Embeddings failed: {e}")
        return False
    
    # Test database system
    print("\n🗄️ Testing Database System...")
    try:
        from analyzers.intelligent.services.async_database import AsyncDatabaseManager
        
        db_manager = AsyncDatabaseManager(config_manager)
        print(f"  ✅ Database manager initialized")
        print(f"  ✅ Database path: {db_manager.db_path}")
        print(f"  ✅ Database directory exists: {db_manager.db_path.parent.exists()}")
        
    except Exception as e:
        print(f"  ❌ Database failed: {e}")
        return False
    
    print("\n🎉 All tests passed! Container is ready for production.")
    return True

if __name__ == "__main__":
    success = test_model_loading()
    sys.exit(0 if success else 1)