import re
from typing import Dict, Any

URGENCY_WORDS = ['urgent', 'immediately', 'suspended', '24 hours', 'action required', 'alert', 'expired', 'compromised', 'locked']
FINANCIAL_WORDS = ['bank', 'paypal', 'transfer', 'credit card', 'refund', 'payment', 'cash', 'gift card', 'bitcoin', 'crypto', 'invoice']
CREDENTIAL_WORDS = ['password', 'login', 'verify account', 'security update', 'authenticator', 'pin', 'ssn']

def extract_text_indicators(text: str) -> Dict[str, Any]:
    """Extract linguistic and structural markers from SMS or email content."""
    text_lower = text.lower()
    
    # Extract embedded URLs
    url_pattern = r'https?://[^\s]+|www\.[^\s]+'
    extracted_urls = re.findall(url_pattern, text)
    
    urgency_hits = [word for word in URGENCY_WORDS if word in text_lower]
    financial_hits = [word for word in FINANCIAL_WORDS if word in text_lower]
    credential_hits = [word for word in CREDENTIAL_WORDS if word in text_lower]
    
    # Structural features
    has_exclamation = 1 if '!' in text else 0
    all_caps_words = len([w for w in text.split() if w.isupper() and len(w) > 2])
    
    return {
        "text_length": len(text),
        "word_count": len(text.split()),
        "extracted_urls": extracted_urls,
        "urgency_score": len(urgency_hits),
        "urgency_hits": urgency_hits,
        "financial_score": len(financial_hits),
        "financial_hits": financial_hits,
        "credential_score": len(credential_hits),
        "credential_hits": credential_hits,
        "has_exclamation": has_exclamation,
        "all_caps_count": all_caps_words
    }
