import re
import math
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'account', 'banking', 'secure',
    'security', 'confirm', 'paypal', 'appleid', 'microsoft', 'google',
    'wallet', 'billing', 'service', 'authenticate', 'token', 'recover', 'claim'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.info', '.biz', '.gq', '.cf', '.tk', '.ml', '.online', '.site']

def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy -= p_x * math.log2(p_x)
    return float(entropy)

def extract_url_features(url: str) -> dict:
    """Extract numeric feature dictionary for machine learning classifier."""
    if not url.startswith(('http://', 'https://')):
        url_formatted = 'http://' + url
    else:
        url_formatted = url

    parsed = urlparse(url_formatted)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path
    query = parsed.query

    url_length = len(url)
    domain_length = len(domain)
    path_length = len(path)
    
    # Structural counts
    num_dots = url.count('.')
    num_hyphens = url.count('-')
    num_at = url.count('@')
    num_question = url.count('?')
    num_equals = url.count('=')
    num_slashes = url.count('/')
    num_digits = sum(c.isdigit() for c in url)
    num_special_chars = sum(not c.isalnum() for c in url)

    # Subdomains check
    domain_parts = domain.split('.')
    num_subdomains = max(0, len(domain_parts) - 2)

    # IP Address presence
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$'
    has_ip = 1 if re.match(ip_pattern, domain) else 0

    # HTTPS presence
    is_https = 1 if url.startswith('https://') else 0

    # Suspicious keywords match count
    url_lower = url.lower()
    keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)

    # Suspicious TLD check
    has_suspicious_tld = 1 if any(url_lower.endswith(tld) or (tld + '/') in url_lower for tld in SUSPICIOUS_TLDS) else 0

    # Shannon entropy of URL
    entropy = calculate_entropy(url)

    features = {
        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_at": num_at,
        "num_question": num_question,
        "num_equals": num_equals,
        "num_slashes": num_slashes,
        "num_digits": num_digits,
        "num_special_chars": num_special_chars,
        "num_subdomains": num_subdomains,
        "has_ip": has_ip,
        "is_https": is_https,
        "keyword_count": keyword_count,
        "has_suspicious_tld": has_suspicious_tld,
        "entropy": round(entropy, 4)
    }

    return features

def feature_dict_to_list(features: dict) -> list:
    """Return ordered feature list for model input."""
    return [
        features["url_length"],
        features["domain_length"],
        features["path_length"],
        features["num_dots"],
        features["num_hyphens"],
        features["num_at"],
        features["num_question"],
        features["num_equals"],
        features["num_slashes"],
        features["num_digits"],
        features["num_special_chars"],
        features["num_subdomains"],
        features["has_ip"],
        features["is_https"],
        features["keyword_count"],
        features["has_suspicious_tld"],
        features["entropy"]
    ]
