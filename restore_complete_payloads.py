#!/usr/bin/env python3
"""Script to restore all 137 payloads from original attack_payloads.py"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def restore_complete_payloads():
    """Read original file and restore all payloads to new structure."""
    
    print("🔄 Restoring complete payload collection...")
    print("📊 Original file has 137 payloads across 9 categories")
    
    # Import the original generator to get all payloads
    try:
        from analyzers.attack_payloads import AdvancedPayloadGenerator
        
        # Initialize original generator
        original_generator = AdvancedPayloadGenerator()
        
        # Get all payloads from original
        all_payloads = original_generator.get_all_payloads()
        
        print(f"✓ Successfully extracted {sum(len(v) for v in all_payloads.values())} payloads")
        
        # Show breakdown by category
        for category, payloads in all_payloads.items():
            print(f"  - {category}: {len(payloads)} payloads")
        
        return all_payloads
        
    except ImportError as e:
        print(f"❌ Could not import original payload generator: {e}")
        return None
    except Exception as e:
        print(f"❌ Error extracting payloads: {e}")
        return None

def verify_new_structure():
    """Verify the new modular structure has all payloads."""
    try:
        from analyzers.payloads import AdvancedPayloadGenerator
        
        generator = AdvancedPayloadGenerator()
        new_payloads = generator.get_all_payloads()
        
        total_new = sum(len(v) for v in new_payloads.values())
        
        print(f"\n🔍 New modular structure verification:")
        print(f"  - Total payloads: {total_new}")
        
        for category, payloads in new_payloads.items():
            print(f"  - {category}: {len(payloads)} payloads")
        
        return total_new
        
    except Exception as e:
        print(f"❌ Error verifying new structure: {e}")
        return 0

def compare_coverage():
    """Compare original vs new payload coverage."""
    print("\n📈 Payload Coverage Comparison:")
    print("=" * 50)
    
    original_payloads = restore_complete_payloads()
    if not original_payloads:
        return
    
    total_original = sum(len(v) for v in original_payloads.values())
    total_new = verify_new_structure()
    
    coverage_percent = (total_new / total_original) * 100 if total_original > 0 else 0
    missing_payloads = total_original - total_new
    
    print(f"\n📊 Summary:")
    print(f"  Original: {total_original} payloads")
    print(f"  New:      {total_new} payloads") 
    print(f"  Coverage: {coverage_percent:.1f}%")
    print(f"  Missing:  {missing_payloads} payloads")
    
    if missing_payloads > 0:
        print(f"\n⚠️  We need to restore {missing_payloads} missing payloads!")
        return False
    else:
        print(f"\n✅ All payloads successfully restored!")
        return True

if __name__ == "__main__":
    print("🔧 Payload Collection Restoration Tool")
    print("=" * 50)
    
    success = compare_coverage()
    
    if success:
        print("\n🎉 Payload restoration complete!")
        sys.exit(0)
    else:
        print("\n❌ Payload restoration incomplete - manual intervention needed")
        sys.exit(1)