import pytest
from app.services.network_inspector import resolve_dns_records, inspect_ssl_certificate, inspect_http_connection

def test_resolution_dns_dnspython_enregistrements_a_et_mx():
    """Test 1: Resolution DNS via Dnspython pour extraire les enregistrements A, AAAA et MX."""
    dns_info = resolve_dns_records("google.com")
    assert isinstance(dns_info, dict)
    assert "a_records" in dns_info
    assert len(dns_info["a_records"]) > 0
    assert "has_mx" in dns_info

def test_audit_certificat_ssl_et_en_tetes_securite():
    """Test 2: Inspection SSL/TLS et verification de la chaine de confiance."""
    ssl_info = inspect_ssl_certificate("google.com", 443)
    assert isinstance(ssl_info, dict)
    assert ssl_info["ssl_active"] is True
    assert ssl_info["is_trusted"] is True
    assert "issuer" in ssl_info
    assert ssl_info["days_remaining"] is not None and ssl_info["days_remaining"] > 0
