from enhanced_detector import enhanced_detector

# Test cases
test_texts = [
    "Green Gate WATERMARKET premium seeds for farming",
    "Get 100% guaranteed profit in farming within 15 days",
    "Buy 1 get 3 free seeds limited offer",
    "Tractor parts and farming equipment wholesale"
]

print("Testing ML Model...\n")

for text in test_texts:
    print(f"Text: {text[:50]}...")
    result = enhanced_detector.enhanced_detect(text)
    print(f"Result: {result.get('result', 'N/A')}")
    print(f"Confidence: {result.get('confidence', 0)}%")
    print(f"Message: {result.get('message', 'N/A')}")
    print("-" * 50)