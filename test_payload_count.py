#!/usr/bin/env python3
"""
Test script to verify we have 1000+ unique attack payloads
"""

from analyzers.attack_payloads import AdvancedPayloadGenerator

def test_payload_generation():
    """Test that we can generate 1000+ unique payloads"""
    generator = AdvancedPayloadGenerator()
    
    print("=" * 60)
    print("PAYLOAD GENERATION STATISTICS")
    print("=" * 60)
    
    # Get base payload counts
    base_counts = {}
    total_base = 0
    for category, payloads in generator.payloads.items():
        count = len(payloads)
        base_counts[category.value] = count
        total_base += count
        print(f"{category.value:25s}: {count:4d} base payloads")
    
    print("-" * 60)
    print(f"{'Total Base Payloads':25s}: {total_base:4d}")
    print("=" * 60)
    
    # Generate all variations
    print("\nGenerating all variations...")
    counts = generator.get_payload_count()
    
    print("\n" + "=" * 60)
    print("PAYLOAD COUNTS WITH VARIATIONS")
    print("=" * 60)
    
    for category, count in counts.items():
        if category != 'total':
            print(f"{category:25s}: {count:4d} unique payloads")
    
    print("-" * 60)
    print(f"{'TOTAL UNIQUE PAYLOADS':25s}: {counts['total']:4d}")
    print("=" * 60)
    
    # Verification
    if counts['total'] >= 1000:
        print(f"\n✅ SUCCESS: Generated {counts['total']} unique payloads (>= 1000)")
    else:
        print(f"\n❌ FAILED: Only generated {counts['total']} unique payloads (< 1000)")
    
    # Show sample variations for a payload
    print("\n" + "=" * 60)
    print("SAMPLE VARIATIONS")
    print("=" * 60)
    sample_payload = "'; DROP TABLE users; --"
    print(f"Original: {sample_payload}")
    print("\nVariations:")
    variations = generator.generate_mutation_variants(sample_payload, 15)
    for i, variant in enumerate(variations, 1):
        print(f"{i:2d}. {variant}")
    
    # Show encoding examples
    print("\n" + "=" * 60)
    print("ENCODING EXAMPLES")
    print("=" * 60)
    test_payload = "SELECT * FROM users"
    encodings = ["url", "double_url", "base64", "hex", "unicode", "html_entity", "mixed"]
    
    for encoding in encodings:
        encoded = generator.encode_payload(test_payload, encoding)
        print(f"{encoding:12s}: {encoded[:60]}{'...' if len(encoded) > 60 else ''}")
    
    return counts['total'] >= 1000

if __name__ == "__main__":
    success = test_payload_generation()
    exit(0 if success else 1)