"""
PhishGuard — Unit Tests: Text NLP Indicators
=============================================
Tests the extract_text_indicators() function from text_nlp_pipeline.py
Run with: pytest tests/test_text_pipeline.py -v
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from app.ml.text_nlp_pipeline import extract_text_indicators


# ══════════════════════════════════════════════════
#  FIXTURES
# ══════════════════════════════════════════════════

LEGIT_MSG  = "Your order #49204 has shipped and will arrive on Friday. Thank you!"
PHISH_MSG  = "URGENT! Your PayPal account has been SUSPENDED! Verify immediately at http://paypal-verify.xyz or lose access within 24 hours!"
LEGIT_FR   = "Bonjour, votre rendez-vous est confirmé pour mardi à 14h30."
PHISH_FR   = "ALERTE: Votre compte bancaire est compromis! Vérifiez maintenant: http://bank-verify.xyz"
EMPTY_MSG  = ""


# ══════════════════════════════════════════════════
#  1. OUTPUT STRUCTURE
# ══════════════════════════════════════════════════

def test_output_is_dict():
    result = extract_text_indicators(LEGIT_MSG)
    assert isinstance(result, dict)


def test_all_expected_keys_present():
    result = extract_text_indicators(LEGIT_MSG)
    expected = [
        "text_length", "word_count", "extracted_urls",
        "urgency_score", "urgency_hits",
        "financial_score", "financial_hits",
        "credential_score", "credential_hits",
        "has_exclamation", "all_caps_count"
    ]
    for key in expected:
        assert key in result, f"Missing key: '{key}'"


# ══════════════════════════════════════════════════
#  2. URGENCY DETECTION
# ══════════════════════════════════════════════════

def test_urgency_score_high_for_phishing():
    result = extract_text_indicators(PHISH_MSG)
    assert result["urgency_score"] >= 2, f"Expected urgency ≥2, got {result['urgency_score']}"


def test_urgency_score_zero_for_legit():
    result = extract_text_indicators(LEGIT_MSG)
    assert result["urgency_score"] == 0, f"Legit message should have urgency=0, got {result['urgency_score']}"


def test_urgency_hits_are_list():
    result = extract_text_indicators(PHISH_MSG)
    assert isinstance(result["urgency_hits"], list)


def test_urgency_suspended_detected():
    result = extract_text_indicators("Your account has been suspended immediately!")
    assert "suspended" in result["urgency_hits"]


# ══════════════════════════════════════════════════
#  3. FINANCIAL KEYWORD DETECTION
# ══════════════════════════════════════════════════

def test_financial_score_positive_for_paypal():
    result = extract_text_indicators(PHISH_MSG)
    assert result["financial_score"] >= 1, f"PayPal mention should trigger financial score"


def test_financial_hits_contain_paypal():
    result = extract_text_indicators("Your paypal payment failed. Update your credit card.")
    assert "paypal" in result["financial_hits"] or "credit card" in result["financial_hits"]


def test_financial_score_zero_for_legit():
    result = extract_text_indicators(LEGIT_FR)
    assert result["financial_score"] == 0


# ══════════════════════════════════════════════════
#  4. CREDENTIAL KEYWORD DETECTION
# ══════════════════════════════════════════════════

def test_credential_score_for_login_message():
    result = extract_text_indicators("Please login and verify account with your password and pin.")
    assert result["credential_score"] >= 2


def test_credential_score_zero_for_legit():
    result = extract_text_indicators(LEGIT_MSG)
    assert result["credential_score"] == 0


# ══════════════════════════════════════════════════
#  5. URL EXTRACTION
# ══════════════════════════════════════════════════

def test_url_extracted_from_phishing_message():
    result = extract_text_indicators(PHISH_MSG)
    assert len(result["extracted_urls"]) >= 1, "Should extract at least 1 URL from phishing message"
    assert any("paypal-verify" in u for u in result["extracted_urls"])


def test_no_url_in_legit_message():
    result = extract_text_indicators(LEGIT_MSG)
    assert result["extracted_urls"] == [], "Legit message has no URLs"


def test_multiple_urls_extracted():
    msg = "Visit http://site1.xyz and also http://site2.top for details"
    result = extract_text_indicators(msg)
    assert len(result["extracted_urls"]) == 2


# ══════════════════════════════════════════════════
#  6. EXCLAMATION & ALL CAPS
# ══════════════════════════════════════════════════

def test_exclamation_detected_in_phishing():
    result = extract_text_indicators(PHISH_MSG)
    assert result["has_exclamation"] == 1


def test_no_exclamation_in_calm_message():
    result = extract_text_indicators("Your appointment is confirmed for Thursday.")
    assert result["has_exclamation"] == 0


def test_all_caps_count_positive_for_phishing():
    result = extract_text_indicators(PHISH_MSG)
    assert result["all_caps_count"] >= 1, f"Expected all_caps_count ≥1, got {result['all_caps_count']}"


def test_all_caps_count_zero_for_legit():
    result = extract_text_indicators("Your order has shipped and will arrive on Friday.")
    assert result["all_caps_count"] == 0


# ══════════════════════════════════════════════════
#  7. TEXT METRICS
# ══════════════════════════════════════════════════

def test_text_length_correct():
    msg = "Hello world"
    result = extract_text_indicators(msg)
    assert result["text_length"] == len(msg)


def test_word_count_correct():
    msg = "Hello world this is a test"
    result = extract_text_indicators(msg)
    assert result["word_count"] == 6


def test_empty_message_does_not_crash():
    try:
        result = extract_text_indicators(EMPTY_MSG)
        assert isinstance(result, dict)
    except Exception as e:
        pytest.fail(f"extract_text_indicators('') raised: {e}")


def test_empty_message_has_zero_scores():
    result = extract_text_indicators(EMPTY_MSG)
    assert result["urgency_score"] == 0
    assert result["financial_score"] == 0
    assert result["credential_score"] == 0
