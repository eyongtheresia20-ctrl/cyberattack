"""
PhishGuard — Unit Tests: URL Feature Extractor
===============================================
Tests all 17 extracted features from extract_url_features()
Run with: pytest tests/test_feature_extractor.py -v
"""

import sys
import os

# Make sure the backend root is importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.ml.url_feature_extractor import extract_url_features, calculate_entropy, feature_dict_to_list


# ══════════════════════════════════════════════════
#  FIXTURES
# ══════════════════════════════════════════════════

LEGIT_URL_GOOGLE    = "https://www.google.com/search?q=cybersecurity"
LEGIT_URL_GITHUB    = "https://github.com/torvalds/linux"
LEGIT_URL_WIKIPEDIA = "https://wikipedia.org/wiki/Machine_learning"

PHISHING_IP         = "http://192.168.1.100/paypal.com/login-verify.php?id=99"
PHISHING_KEYWORDS   = "http://secure-update-appleid-billing.xyz/login.html?token=abc"
PHISHING_LONG       = "http://verify-bank-account-security-alert-urgent-action.club/update-pin.asp?session=xxx"
PHISHING_NO_HTTPS   = "http://microsoft-online-account-recovery.top/auth/signin"


# ══════════════════════════════════════════════════
#  1. BASIC OUTPUT STRUCTURE
# ══════════════════════════════════════════════════

def test_output_is_dict():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert isinstance(result, dict), "Output must be a dictionary"


def test_output_has_17_features():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert len(result) == 17, f"Expected 17 features, got {len(result)}"


def test_all_expected_keys_present():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    expected_keys = [
        "url_length", "domain_length", "path_length",
        "num_dots", "num_hyphens", "num_at",
        "num_question", "num_equals", "num_slashes",
        "num_digits", "num_special_chars", "num_subdomains",
        "has_ip", "is_https", "keyword_count",
        "has_suspicious_tld", "entropy"
    ]
    for key in expected_keys:
        assert key in result, f"Missing feature key: '{key}'"


def test_feature_list_has_17_elements():
    feats = extract_url_features(LEGIT_URL_GOOGLE)
    feat_list = feature_dict_to_list(feats)
    assert len(feat_list) == 17, f"feature_dict_to_list must return 17 values, got {len(feat_list)}"


# ══════════════════════════════════════════════════
#  2. HTTPS DETECTION
# ══════════════════════════════════════════════════

def test_https_flagged_as_1_for_secure_url():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert result["is_https"] == 1, "HTTPS URL should have is_https = 1"


def test_http_flagged_as_0_for_insecure_url():
    result = extract_url_features(PHISHING_IP)
    assert result["is_https"] == 0, "HTTP URL should have is_https = 0"


def test_url_without_scheme_handled():
    result = extract_url_features("paypal.com/login")
    assert isinstance(result, dict), "Should handle URLs without scheme prefix"


# ══════════════════════════════════════════════════
#  3. IP ADDRESS DETECTION
# ══════════════════════════════════════════════════

def test_ip_detected_in_phishing_url():
    result = extract_url_features(PHISHING_IP)
    assert result["has_ip"] == 1, "IP-based URL should have has_ip = 1"


def test_ip_not_detected_in_legit_domain():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert result["has_ip"] == 0, "Legitimate domain URL should have has_ip = 0"


# ══════════════════════════════════════════════════
#  4. SUSPICIOUS TLD DETECTION
# ══════════════════════════════════════════════════

def test_suspicious_tld_detected_xyz():
    result = extract_url_features(PHISHING_KEYWORDS)  # .xyz
    assert result["has_suspicious_tld"] == 1, ".xyz should be flagged as suspicious TLD"


def test_suspicious_tld_detected_club():
    result = extract_url_features(PHISHING_LONG)  # .club
    assert result["has_suspicious_tld"] == 1, ".club should be flagged as suspicious TLD"


def test_no_suspicious_tld_for_legit():
    result = extract_url_features(LEGIT_URL_GITHUB)  # .com
    assert result["has_suspicious_tld"] == 0, ".com should NOT be flagged as suspicious TLD"


# ══════════════════════════════════════════════════
#  5. SUSPICIOUS KEYWORD COUNT
# ══════════════════════════════════════════════════

def test_keyword_count_positive_for_phishing():
    result = extract_url_features(PHISHING_KEYWORDS)  # contains: secure, update, appleid, billing, login, token
    assert result["keyword_count"] >= 3, f"Expected ≥3 keyword hits, got {result['keyword_count']}"


def test_keyword_count_low_for_legit():
    result = extract_url_features(LEGIT_URL_WIKIPEDIA)
    assert result["keyword_count"] <= 1, f"Wikipedia should have ≤1 keyword hit, got {result['keyword_count']}"


# ══════════════════════════════════════════════════
#  6. URL LENGTH
# ══════════════════════════════════════════════════

def test_url_length_is_positive():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert result["url_length"] > 0


def test_long_phishing_url_has_greater_length():
    legit = extract_url_features(LEGIT_URL_GITHUB)
    phish = extract_url_features(PHISHING_LONG)
    assert phish["url_length"] > legit["url_length"], "Phishing URL should be longer"


# ══════════════════════════════════════════════════
#  7. ENTROPY
# ══════════════════════════════════════════════════

def test_entropy_is_float():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert isinstance(result["entropy"], float)


def test_entropy_greater_than_zero_for_real_url():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    assert result["entropy"] > 0.0


def test_entropy_function_empty_string():
    assert calculate_entropy("") == 0.0


def test_entropy_function_single_char():
    # P(a) = 1 → entropy = 0
    assert calculate_entropy("aaaa") == 0.0


def test_entropy_function_diverse_string():
    entropy = calculate_entropy("abcdefgh")
    assert entropy > 2.0, "Diverse string should have entropy > 2 bits"


# ══════════════════════════════════════════════════
#  8. STRUCTURAL COUNTS
# ══════════════════════════════════════════════════

def test_num_dots_counted_correctly():
    result = extract_url_features("https://sub.example.co.uk/path")
    assert result["num_dots"] >= 3


def test_num_hyphens_counted():
    result = extract_url_features("http://secure-update-verify.xyz/login")
    assert result["num_hyphens"] >= 2


def test_num_at_detected():
    result = extract_url_features("http://fake-site.xyz/login@paypal.com")
    assert result["num_at"] >= 1, "@ in URL should be counted"


def test_num_subdomains_counted():
    result = extract_url_features("http://sub1.sub2.evil.xyz/path")
    assert result["num_subdomains"] >= 2


def test_num_digits_counted():
    result = extract_url_features("http://secure123-login456.xyz/confirm99")
    assert result["num_digits"] >= 7


# ══════════════════════════════════════════════════
#  9. EDGE CASES
# ══════════════════════════════════════════════════

def test_empty_url_does_not_crash():
    try:
        result = extract_url_features("")
        assert isinstance(result, dict)
    except Exception as e:
        pytest.fail(f"extract_url_features('') raised an exception: {e}")


def test_url_with_no_path():
    result = extract_url_features("https://google.com")
    assert result["url_length"] > 0


def test_all_values_are_numeric():
    result = extract_url_features(LEGIT_URL_GOOGLE)
    for key, val in result.items():
        assert isinstance(val, (int, float)), f"Feature '{key}' value '{val}' is not numeric"
