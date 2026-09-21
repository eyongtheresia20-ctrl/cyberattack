import re
import math
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'account', 'banking', 'secure',
    'security', 'confirm', 'paypal', 'appleid', 'microsoft', 'google',
    'wallet', 'billing', 'service', 'authenticate', 'token', 'recover', 'claim'
]

SUSPICIOUS_TLDS = ['.xyz', '.top', '.club', '.work', '.info', '.biz', '.gq', '.cf', '.tk', '.ml', '.online', '.site']

# ─── VT / Brand Impersonation Simulation ────────────────────────────────────
MAJOR_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram',
    'netflix', 'twitter', 'whatsapp', 'linkedin', 'tiktok', 'discord', 'steam',
    'binance', 'coinbase', 'metamask', 'ebay', 'walmart', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'irs', 'dhl', 'fedex', 'ups', 'usps',
    'laposte', 'bnp', 'societegenerale', 'creditagricole', 'boursorama', 'impots',
    'ameli', 'caf', 'spotify', 'office365', 'sharepoint', 'outlook', 'dropbox'
]

# GSB social engineering patterns
SOCIAL_ENGINEERING_PATTERNS = [
    'verify', 'confirm', 'suspend', 'locked', 'urgent', 'alert', 'warning',
    'unusual', 'activity', 'claim', 'reward', 'prize', 'winner', 'giftcard',
    'free', 'limited', 'expire', 'update', 'billing', 'recover', 'restore',
    'unlock', 'reactivate', 'validate', 'authenticate', 'checkpoint'
]

# GSB malware patterns (drive-by download / malware distribution)
MALWARE_PATTERNS = [
    'download', 'setup', 'install', 'crack', 'keygen', 'patch', 'serial',
    'activation', 'loader', 'dropper', 'payload', 'exploit', 'exe', 'dll',
    'bat', 'vbs', 'ps1', 'zip-free', 'full-version', 'torrent'
]

# GeoIP/ASN: Known high-risk datacenter/hosting IP prefixes (CIDR approximation)
HIGH_RISK_IP_PREFIXES = [
    '185.220.', '185.100.', '185.130.', '185.38.',  # Tor/Bulletproof hosting
    '45.33.', '45.55.', '45.79.',                    # Linode/Akamai bulletproof
    '192.99.', '192.168.', '10.', '172.16.',          # Private / RFC-1918 attack
    '5.188.', '5.61.', '5.135.',                      # OVH bulletproof subrange
    '91.108.', '91.109.', '91.121.',                  # Eastern European abuse
    '194.165.', '194.87.',                             # Known phishing hosting
    '104.244.', '104.244.72.',                         # Known phishing CDN abuse
]

# GeoIP/ASN: CDN ASN ranges (legitimate)
LEGIT_CDN_ORGS = [
    'cloudflare', 'akamai', 'fastly', 'amazon', 'google', 'microsoft azure',
    'cloudfront', 'incapsula', 'edgecast', 'stackpath', 'cdn77', 'bunnycdn'
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon Entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    for char in set(text):
        p_x = float(text.count(char)) / len(text)
        entropy -= p_x * math.log2(p_x)
    return float(entropy)


def compute_vt_positives_sim(url: str, domain: str, has_ip: int,
                              keyword_count: int, has_suspicious_tld: int,
                              num_subdomains: int) -> float:
    """
    Simulate VirusTotal positives count using structural URL heuristics.
    Replicates the multi-engine consensus signal that VT provides.
    Returns a 0-90 normalized count (simulating engines that flagged it).
    """
    score = 0
    url_lower = url.lower()

    # Brand impersonation + domain mismatch (VT detects this via multiple engines)
    for brand in MAJOR_BRANDS:
        if brand in url_lower:
            # Legit brand domain would not have suspicious co-TLD
            brand_in_domain = brand in domain.lower()
            if brand_in_domain and has_suspicious_tld:
                score += 25  # Brand in suspicious TLD = strong VT signal
            elif brand in url_lower and brand not in domain.lower():
                score += 18  # Brand in path but not domain = spoofing
            elif brand in url_lower and has_ip:
                score += 30  # Brand URL + IP host = direct phishing
            break

    score += keyword_count * 8          # Each high-risk keyword
    score += 15 if has_ip else 0        # Direct IP usage
    score += 12 if has_suspicious_tld else 0
    score += 8 if num_subdomains >= 3 else 0

    # High-entropy random-looking domains (DGA pattern) — VT detects these
    domain_entropy = calculate_entropy(domain.split('.')[0])
    if domain_entropy > 3.8:
        score += 10

    return min(90.0, float(score))


def compute_gsb_social_engineering(url: str) -> float:
    """
    Simulate Google Safe Browsing SOCIAL_ENGINEERING threat type.
    Returns 0.0 (clean) to 1.0 (definite social engineering).
    """
    url_lower = url.lower()
    hits = sum(1 for p in SOCIAL_ENGINEERING_PATTERNS if p in url_lower)
    brand_hits = sum(1 for b in MAJOR_BRANDS if b in url_lower)
    score = (hits * 0.12) + (brand_hits * 0.20)
    return round(min(1.0, score), 4)


def compute_gsb_malware_sim(url: str, has_ip: int, has_suspicious_tld: int) -> float:
    """
    Simulate Google Safe Browsing MALWARE threat type.
    Returns 0.0 (clean) to 1.0 (definite malware distribution pattern).
    """
    url_lower = url.lower()
    malware_hits = sum(1 for p in MALWARE_PATTERNS if p in url_lower)
    score = (malware_hits * 0.15)
    score += 0.3 if has_ip else 0.0
    score += 0.2 if has_suspicious_tld else 0.0
    return round(min(1.0, score), 4)


def compute_asn_risk_score(domain: str, has_ip: int, ip_str: str = "") -> float:
    """
    Simulate GeoIP/ASN risk score from domain/IP structure.
    Returns 0.0 (clean ASN/CDN) to 1.0 (high-risk bulletproof/datacenter).
    """
    # Known high-risk IP prefix
    for prefix in HIGH_RISK_IP_PREFIXES:
        if ip_str.startswith(prefix) or domain.startswith(prefix.rstrip('.')):
            return 0.90

    # Private/RFC-1918 IP in URL — always suspicious
    if has_ip and (domain.startswith('192.168.') or domain.startswith('10.')
                   or domain.startswith('172.16.')):
        return 0.95

    # Raw IP with no domain = high risk
    if has_ip:
        return 0.70

    # Very short random-looking domain (DGA pattern typical of bulletproof hosting)
    base_domain = domain.split('.')[0] if '.' in domain else domain
    if len(base_domain) <= 6 and calculate_entropy(base_domain) > 3.2:
        return 0.55

    return 0.0


def compute_is_hosting_server(domain: str, has_ip: int) -> int:
    """
    Detect if host appears to be a datacenter/hosting server rather than CDN edge.
    GeoIP 'hosting' flag equivalent. Returns 1 if hosting-like, 0 otherwise.
    """
    domain_lower = domain.lower()
    # Check for typical hosting provider subdomains
    hosting_patterns = ['server', 'vps', 'host', 'node', 'web', 'srv', 'instance', 'ec2', 'compute']
    if any(p in domain_lower for p in hosting_patterns):
        return 1
    if has_ip:
        return 1
    return 0


def compute_proxy_vpn_sim(url: str, domain: str) -> int:
    """
    Detect URL patterns associated with proxy/VPN/anonymization services.
    GeoIP proxy flag equivalent. Returns 1 if proxy-associated, 0 otherwise.
    """
    url_lower = url.lower()
    proxy_patterns = ['proxy', 'vpn', 'tor', 'anon', 'hide', 'tunnel', 'relay', 'exit-node', 'socks']
    return 1 if any(p in url_lower for p in proxy_patterns) else 0


def compute_domain_age_risk(domain: str, has_suspicious_tld: int) -> float:
    """
    Estimate domain age risk from structural signals.
    New/disposable domains (high entropy + suspicious TLD) are flagged.
    Returns 0.0 (established-looking) to 1.0 (very new/disposable).
    """
    base = domain.split('.')[0] if '.' in domain else domain
    entropy = calculate_entropy(base)

    risk = 0.0
    # Very random looking = likely DGA / recently registered disposable domain
    if entropy > 3.5:
        risk += 0.45
    elif entropy > 2.8:
        risk += 0.20

    # Suspicious TLD is strongly correlated with newly registered phishing domains
    if has_suspicious_tld:
        risk += 0.40

    # Long numeric sequences in domain = auto-generated
    digit_ratio = sum(c.isdigit() for c in base) / max(len(base), 1)
    if digit_ratio > 0.4:
        risk += 0.25

    return round(min(1.0, risk), 4)


def compute_brand_impersonation_sim(url: str, domain: str) -> float:
    """
    Multi-brand impersonation score — replicates VT/GSB brand spoofing detection.
    Returns 0.0 (no impersonation) to 1.0 (definite brand impersonation).
    """
    url_lower = url.lower()
    domain_lower = domain.lower()
    score = 0.0

    for brand in MAJOR_BRANDS:
        if brand in url_lower:
            # True brand would be brand.com, not random-tld or subpath-trick
            if brand in domain_lower:
                # Brand name IS in domain — only suspicious if TLD is bad
                if any(domain_lower.endswith(tld) for tld in SUSPICIOUS_TLDS):
                    score = max(score, 0.85)
            else:
                # Brand in path/query but not domain = URL spoofing trick
                score = max(score, 0.70)

    return round(min(1.0, score), 4)


def compute_threat_category_sim(gsb_social: float, gsb_malware: float,
                                  vt_positives: float) -> int:
    """
    Encode unified threat category:
    0 = Clean, 1 = Social Engineering / Phishing, 2 = Malware / Drive-by, 3 = Multi-threat
    Replicates VT category classification.
    """
    is_social = gsb_social >= 0.4 or vt_positives >= 15
    is_malware = gsb_malware >= 0.4
    if is_social and is_malware:
        return 3
    if is_malware:
        return 2
    if is_social:
        return 1
    return 0


def compute_multi_engine_consensus(vt_positives: float, gsb_social: float,
                                    gsb_malware: float, asn_risk: float,
                                    brand_sim: float) -> float:
    """
    Compute normalized multi-engine consensus score (0.0 to 1.0).
    Replicates the aggregate signal from multiple threat intelligence sources.
    """
    vt_norm   = min(1.0, vt_positives / 90.0)
    gsb_norm  = max(gsb_social, gsb_malware)
    asn_norm  = asn_risk
    brand_norm = brand_sim

    consensus = (vt_norm * 0.35) + (gsb_norm * 0.30) + (asn_norm * 0.20) + (brand_norm * 0.15)
    return round(min(1.0, consensus), 4)


def extract_url_features(url: str, host_ip: str = "") -> dict:
    """
    Extract enriched numeric feature dictionary for ML classifiers.
    Includes 17 original structural features + 10 threat-intel-equivalent features.
    Total: 27 features.
    """
    if not url.startswith(('http://', 'https://')):
        url_formatted = 'http://' + url
    else:
        url_formatted = url

    parsed = urlparse(url_formatted)
    domain = parsed.netloc or parsed.path.split('/')[0]
    path = parsed.path
    query = parsed.query

    url_length    = len(url)
    domain_length = len(domain)
    path_length   = len(path)

    # ── Original 17 structural features ─────────────────────────────────────
    num_dots         = url.count('.')
    num_hyphens      = url.count('-')
    num_at           = url.count('@')
    num_question     = url.count('?')
    num_equals       = url.count('=')
    num_slashes      = url.count('/')
    num_digits       = sum(c.isdigit() for c in url)
    num_special_chars = sum(not c.isalnum() for c in url)

    domain_parts   = domain.split('.')
    num_subdomains = max(0, len(domain_parts) - 2)

    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$'
    has_ip     = 1 if re.match(ip_pattern, domain) else 0
    is_https   = 1 if url.startswith('https://') else 0

    url_lower      = url.lower()
    keyword_count  = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in url_lower)
    has_suspicious_tld = 1 if any(url_lower.endswith(tld) or (tld + '/') in url_lower
                                   for tld in SUSPICIOUS_TLDS) else 0
    entropy        = calculate_entropy(url)

    # ── NEW: 10 Threat-Intel-Equivalent ML Features ─────────────────────────
    vt_positives_sim     = compute_vt_positives_sim(url, domain, has_ip, keyword_count,
                                                      has_suspicious_tld, num_subdomains)
    gsb_social_sim       = compute_gsb_social_engineering(url)
    gsb_malware_sim      = compute_gsb_malware_sim(url, has_ip, has_suspicious_tld)
    asn_risk_score       = compute_asn_risk_score(domain, has_ip, host_ip)
    is_hosting_server    = compute_is_hosting_server(domain, has_ip)
    is_proxy_vpn_sim     = compute_proxy_vpn_sim(url, domain)
    domain_age_risk      = compute_domain_age_risk(domain, has_suspicious_tld)
    brand_impersonation  = compute_brand_impersonation_sim(url, domain)
    threat_category_sim  = compute_threat_category_sim(gsb_social_sim, gsb_malware_sim,
                                                         vt_positives_sim)
    multi_engine_consensus = compute_multi_engine_consensus(vt_positives_sim, gsb_social_sim,
                                                             gsb_malware_sim, asn_risk_score,
                                                             brand_impersonation)

    features = {
        # ── Original 17 ───────────────────────────────────
        "url_length":          url_length,
        "domain_length":       domain_length,
        "path_length":         path_length,
        "num_dots":            num_dots,
        "num_hyphens":         num_hyphens,
        "num_at":              num_at,
        "num_question":        num_question,
        "num_equals":          num_equals,
        "num_slashes":         num_slashes,
        "num_digits":          num_digits,
        "num_special_chars":   num_special_chars,
        "num_subdomains":      num_subdomains,
        "has_ip":              has_ip,
        "is_https":            is_https,
        "keyword_count":       keyword_count,
        "has_suspicious_tld":  has_suspicious_tld,
        "entropy":             round(entropy, 4),
        # ── New 10: Threat Intel Replication ──────────────
        "vt_positives_sim":       round(vt_positives_sim, 2),
        "gsb_social_sim":         gsb_social_sim,
        "gsb_malware_sim":        gsb_malware_sim,
        "asn_risk_score":         asn_risk_score,
        "is_hosting_server":      is_hosting_server,
        "is_proxy_vpn_sim":       is_proxy_vpn_sim,
        "domain_age_risk":        domain_age_risk,
        "brand_impersonation_sim": brand_impersonation,
        "threat_category_sim":    threat_category_sim,
        "multi_engine_consensus": multi_engine_consensus,
    }

    return features


def feature_dict_to_list(features: dict) -> list:
    """Return ordered feature list for model input (27 features)."""
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
        features["entropy"],
        # New 10
        features["vt_positives_sim"],
        features["gsb_social_sim"],
        features["gsb_malware_sim"],
        features["asn_risk_score"],
        features["is_hosting_server"],
        features["is_proxy_vpn_sim"],
        features["domain_age_risk"],
        features["brand_impersonation_sim"],
        features["threat_category_sim"],
        features["multi_engine_consensus"],
    ]
