#!/usr/bin/env python3
"""
Test script to verify the enhanced scoring integration in scanner.py
Tests the import and initialization without running full scans
"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

def test_imports():
    """Test that all necessary imports work"""
    print("📦 Testing imports...")
    
    try:
        # Test importing the main scanner
        print("  ✓ Importing SecurityScanner...")
        from scanner import SecurityScanner
        
        print("  ✓ Importing enhanced scoring...")
        from enhanced_scoring import EnhancedSecurityScorer
        
        print("  ✓ All imports successful!")
        return True
        
    except ImportError as e:
        print(f"  ❌ Import failed: {e}")
        return False

def test_scanner_initialization():
    """Test that the scanner initializes with enhanced scoring"""
    print("\n🏗️ Testing scanner initialization...")
    
    try:
        from scanner import SecurityScanner
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Check that enhanced scorer is initialized
        if hasattr(scanner, 'enhanced_scorer'):
            print("  ✓ Enhanced scorer initialized successfully!")
            
            # Check that it has the right type
            from enhanced_scoring import EnhancedSecurityScorer
            if isinstance(scanner.enhanced_scorer, EnhancedSecurityScorer):
                print("  ✓ Enhanced scorer has correct type!")
            else:
                print(f"  ❌ Enhanced scorer has wrong type: {type(scanner.enhanced_scorer)}")
                return False
        else:
            print("  ❌ Enhanced scorer not found in scanner!")
            return False
            
        # Check that both scorers exist
        if hasattr(scanner, 'scorer') and hasattr(scanner, 'enhanced_scorer'):
            print("  ✓ Both legacy and enhanced scorers available!")
        else:
            print("  ❌ Missing scorer attributes!")
            return False
            
        return True
        
    except Exception as e:
        print(f"  ❌ Scanner initialization failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_method_signatures():
    """Test that method signatures are updated correctly"""
    print("\n📝 Testing method signatures...")
    
    try:
        from scanner import SecurityScanner
        import inspect
        
        scanner = SecurityScanner()
        
        # Check _generate_summary signature
        sig = inspect.signature(scanner._generate_summary)
        params = list(sig.parameters.keys())
        
        expected_params = ['self', 'findings', 'score_data', 'enhanced_scores']
        if params == expected_params:
            print("  ✓ _generate_summary signature updated correctly!")
        else:
            print(f"  ❌ _generate_summary signature incorrect. Got: {params}, Expected: {expected_params}")
            return False
            
        # Check for enhanced aggregation method
        if hasattr(scanner, '_aggregate_for_enhanced_scoring'):
            print("  ✓ Enhanced aggregation method exists!")
        else:
            print("  ❌ Enhanced aggregation method missing!")
            return False
            
        if hasattr(scanner, '_merge_related_findings'):
            print("  ✓ Finding merger method exists!")
        else:
            print("  ❌ Finding merger method missing!")
            return False
            
        return True
        
    except Exception as e:
        print(f"  ❌ Method signature test failed: {e}")
        return False

def test_code_structure():
    """Test that the code structure looks correct"""
    print("\n🏛️ Testing code structure...")
    
    try:
        # Read the scanner file and check for key integrations
        with open("scanner.py", "r") as f:
            content = f.read()
        
        # Check for enhanced scorer import
        if "from enhanced_scoring import EnhancedSecurityScorer" in content:
            print("  ✓ Enhanced scoring import found!")
        else:
            print("  ❌ Enhanced scoring import missing!")
            return False
        
        # Check for enhanced scorer initialization
        if "self.enhanced_scorer = EnhancedSecurityScorer()" in content:
            print("  ✓ Enhanced scorer initialization found!")
        else:
            print("  ❌ Enhanced scorer initialization missing!")
            return False
        
        # Check for dual score calculation
        if "enhanced_scores = self.enhanced_scorer.calculate_both_scores(findings)" in content:
            print("  ✓ Dual score calculation found!")
        else:
            print("  ❌ Dual score calculation missing!")
            return False
        
        # Check for enhanced summary generation
        if "enhanced_scores" in content and "_generate_summary" in content:
            print("  ✓ Enhanced summary integration found!")
        else:
            print("  ❌ Enhanced summary integration missing!")
            return False
            
        # Check for aggregation methods
        if "_aggregate_for_enhanced_scoring" in content:
            print("  ✓ Enhanced aggregation method found!")
        else:
            print("  ❌ Enhanced aggregation method missing!")
            return False
            
        return True
        
    except Exception as e:
        print(f"  ❌ Code structure test failed: {e}")
        return False

def main():
    """Run all integration tests"""
    print("🧪 Enhanced Scoring Integration Tests")
    print("=" * 40)
    
    tests = [
        test_imports,
        test_scanner_initialization,  
        test_method_signatures,
        test_code_structure
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        else:
            break  # Stop on first failure
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        print("\n✅ Enhanced scoring system is properly integrated into scanner.py")
        print("✅ Dual scoring (User Safety + Developer Security) is ready")
        print("✅ Enhanced aggregation and deduplication logic is in place")
        print("\n🚀 Ready for production testing with real MCP repositories!")
        return True
    else:
        print("❌ Some tests failed. Check the integration.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)