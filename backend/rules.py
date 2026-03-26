FRAUD_WORDS = [
    "click here", "urgent", "limited offer",
    "free fertilizer", "100 subsidy", "whatsapp"
]

def rule_check(text):
    text = text.lower()
    return any(word in text for word in FRAUD_WORDS)
