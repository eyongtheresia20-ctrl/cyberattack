import re
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, Any, List
from urllib.parse import urlparse
import requests
import urllib3
import dns.resolver

# Disable SSL verification warnings for inspection of self-signed/untrusted target certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

POPULAR_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "apple": ["apple.com", "icloud.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "google": ["google.com", "gmail.com", "google.fr"],
    "facebook": ["facebook.com", "meta.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.fr", "aws.amazon.com"],
    "binance": ["binance.com"],
    "dhl": ["dhl.com", "dhl.fr"],
    "chase": ["chase.com"],
    "steam": ["steampowered.com", "steamcommunity.com"],
    "discord": ["discord.com", "discord.gg"],
    "whatsapp": ["whatsapp.com"],
    "bnp": ["mabanque.bnpparibas", "bnpparibas.com"],
    "societegenerale": ["societegenerale.fr", "societegenerale.com"],
    "creditagricole": ["credit-agricole.fr"]
}

def clean_url_and_domain(raw_input: str):
    """Normalize input into target URL, hostname, and scheme."""
    raw = raw_input.strip()
    if not raw.startswith(('http://', 'https://')):
        target_url = 'https://' + raw
        scheme = 'https'
    else:
        target_url = raw
        scheme = 'https' if raw.startswith('https://') else 'http'

    parsed = urlparse(target_url)
    hostname = parsed.netloc.split(':')[0] or parsed.path.split('/')[0]
    return target_url, hostname.lower(), scheme

def resolve_dns_records(hostname: str) -> Dict[str, Any]:
    """Resolve A, AAAA, and MX records using low-latency public DNS."""
    dns_res = {
        "a_records": [],
        "aaaa_records": [],
        "mx_records": [],
        "has_mx": False,
        "dns_error": None
    }
    
    # Check if hostname is already raw IP
    parts = hostname.split('.')
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        dns_res["a_records"] = [hostname]
        return dns_res

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1']
    resolver.lifetime = 1.8
    resolver.timeout = 1.5

    # A Records
    try:
        answers = resolver.resolve(hostname, 'A')
        dns_res["a_records"] = [str(r) for r in answers]
    except Exception:
        # Fallback to system socket
        try:
            ip = socket.gethostbyname(hostname)
            dns_res["a_records"] = [ip]
        except Exception as e:
            dns_res["dns_error"] = str(e)

    # AAAA Records
    try:
        answers = resolver.resolve(hostname, 'AAAA')
        dns_res["aaaa_records"] = [str(r) for r in answers]
    except Exception:
        pass

    # MX Records
    try:
        answers = resolver.resolve(hostname, 'MX')
        dns_res["mx_records"] = [str(r.exchange).rstrip('.') for r in answers]
        dns_res["has_mx"] = len(dns_res["mx_records"]) > 0
    except Exception:
        dns_res["has_mx"] = False

    return dns_res

def inspect_ssl_certificate(hostname: str, port: int = 443) -> Dict[str, Any]:
    """Inspect live SSL/TLS peer certificate for the given hostname."""
    ssl_data = {
        "ssl_active": False,
        "ssl_status": "Non Détecté (HTTP ou Hors Ligne)",
        "issuer": "Inconnu",
        "issuer_org": "Inconnu",
        "subject_cn": "Inconnu",
        "subject_alt_names": [],
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "is_expired": False,
        "is_trusted": True,
        "tls_version": None,
        "cipher_suite": None,
        "error": None
    }

    try:
        # First attempt with standard verification to check trust & full cert
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=2.5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    ssl_data["tls_version"] = ssock.version()
                    cipher = ssock.cipher()
                    ssl_data["cipher_suite"] = f"{cipher[0]} ({cipher[2]} bits)" if cipher else None
                    ssl_data["ssl_active"] = True
                    ssl_data["is_trusted"] = True
                    ssl_data["ssl_status"] = "VALIDE & CHIFFRÉ"

                    if cert:
                        issuer_dict = dict(x[0] for x in cert.get('issuer', []))
                        ssl_data["issuer"] = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Inconnu'
                        ssl_data["issuer_org"] = issuer_dict.get('organizationName', ssl_data["issuer"])

                        subject_dict = dict(x[0] for x in cert.get('subject', []))
                        ssl_data["subject_cn"] = subject_dict.get('commonName', hostname)

                        sans = [item[1] for item in cert.get('subjectAltName', []) if item[0] == 'DNS']
                        ssl_data["subject_alt_names"] = sans[:6]

                        not_after = cert.get('notAfter')
                        not_before = cert.get('notBefore')
                        if not_after:
                            ssl_data["valid_to"] = not_after
                            try:
                                exp_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                                now = datetime.utcnow()
                                days_left = (exp_date - now).days
                                ssl_data["days_remaining"] = days_left
                                if days_left < 0:
                                    ssl_data["is_expired"] = True
                                    ssl_data["ssl_status"] = "EXPIRÉ ❌"
                            except Exception:
                                pass
                        if not_before:
                            ssl_data["valid_from"] = not_before
        except ssl.SSLCertVerificationError as cert_err:
            # Self-signed, mismatched hostname or expired certificate
            ssl_data["ssl_active"] = True
            ssl_data["is_trusted"] = False
            ssl_data["ssl_status"] = "CERTIFICAT NON APPROUVÉ / AUTO-SIGNÉ ⚠️"
            ssl_data["error"] = str(cert_err)
    except Exception as e:
        ssl_data["error"] = str(e)
        ssl_data["ssl_status"] = "Non Sécurisé / Échec TLS"

    return ssl_data

def inspect_http_connection(target_url: str) -> Dict[str, Any]:
    """Perform live HTTP/HTTPS request, measure latency, headers, and security posture."""
    http_data = {
        "is_reachable": False,
        "status_code": 0,
        "status_text": "Injoignable",
        "latency_ms": 0,
        "final_url": target_url,
        "redirect_count": 0,
        "server_banner": "Non Divulgué",
        "content_type": "Inconnu",
        "content_length_bytes": 0,
        "page_title": "",
        "security_headers": {
            "hsts": {"present": False, "value": None, "grade_points": 0, "status": "Manquant (Risque Downgrade HTTP)"},
            "csp": {"present": False, "value": None, "grade_points": 0, "status": "Manquant (Risque Injections XSS)"},
            "x_frame_options": {"present": False, "value": None, "grade_points": 0, "status": "Manquant (Risque Clickjacking)"},
            "x_content_type_options": {"present": False, "value": None, "grade_points": 0, "status": "Manquant (Risque MIME Sniffing)"},
            "referrer_policy": {"present": False, "value": None, "grade_points": 0, "status": "Non Restreint"},
            "permissions_policy": {"present": False, "value": None, "grade_points": 0, "status": "Non Configuré"}
        },
        "security_score": 0,
        "security_grade": "F"
    }

    start_time = time.time()
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PhishGuard-Auditor/2.0"
        }
        res = requests.get(target_url, headers=headers, timeout=3.0, allow_redirects=True, verify=False)
        latency = int((time.time() - start_time) * 1000)

        http_data["is_reachable"] = True
        http_data["status_code"] = res.status_code
        http_data["status_text"] = f"{res.status_code} {res.reason}"
        http_data["latency_ms"] = latency
        http_data["final_url"] = res.url
        http_data["redirect_count"] = len(res.history)
        http_data["server_banner"] = res.headers.get("Server", "Non Divulgué (Masqué par WAF ou Hébergeur)")
        http_data["content_type"] = res.headers.get("Content-Type", "Inconnu")
        http_data["content_length_bytes"] = len(res.content) if res.content else int(res.headers.get("Content-Length", 0))

        # Extract <title> if HTML
        if "html" in http_data["content_type"].lower() and res.text:
            title_match = re.search(r'<title[^>]*>(.*?)</title>', res.text, re.IGNORECASE | re.DOTALL)
            if title_match:
                http_data["page_title"] = title_match.group(1).strip()[:100]

        # Audit Security Headers
        resp_headers = {k.lower(): v for k, v in res.headers.items()}
        sec = http_data["security_headers"]
        total_points = 0

        # 1. HSTS
        if "strict-transport-security" in resp_headers:
            hsts_val = resp_headers["strict-transport-security"]
            sec["hsts"] = {
                "present": True,
                "value": hsts_val,
                "grade_points": 30,
                "status": "Actif & Conforme (Protection SSL-Strip)"
            }
            total_points += 30

        # 2. CSP
        if "content-security-policy" in resp_headers:
            csp_val = resp_headers["content-security-policy"]
            sec["csp"] = {
                "present": True,
                "value": csp_val[:80] + "..." if len(csp_val) > 80 else csp_val,
                "grade_points": 25,
                "status": "Configuré (Atténuation XSS / Injection)"
            }
            total_points += 25

        # 3. X-Frame-Options
        if "x-frame-options" in resp_headers:
            xfo_val = resp_headers["x-frame-options"].upper()
            sec["x_frame_options"] = {
                "present": True,
                "value": xfo_val,
                "grade_points": 15,
                "status": f"{xfo_val} (Anti-Clickjacking Actif)"
            }
            total_points += 15

        # 4. X-Content-Type-Options
        if "x-content-type-options" in resp_headers:
            sec["x_content_type_options"] = {
                "present": True,
                "value": resp_headers["x-content-type-options"],
                "grade_points": 10,
                "status": "nosniff (Protection MIME Sniffing Actif)"
            }
            total_points += 10

        # 5. Referrer-Policy
        if "referrer-policy" in resp_headers:
            sec["referrer_policy"] = {
                "present": True,
                "value": resp_headers["referrer-policy"],
                "grade_points": 10,
                "status": f"{resp_headers['referrer-policy']} (Contrôle Fuite d'URL)"
            }
            total_points += 10

        # 6. Permissions-Policy
        if "permissions-policy" in resp_headers or "feature-policy" in resp_headers:
            sec["permissions_policy"] = {
                "present": True,
                "value": "Actif",
                "grade_points": 10,
                "status": "Restreint (APIs Navigateur Sécurisées)"
            }
            total_points += 10

        http_data["security_score"] = total_points
        if total_points >= 80:
            http_data["security_grade"] = "A+"
        elif total_points >= 65:
            http_data["security_grade"] = "A"
        elif total_points >= 45:
            http_data["security_grade"] = "B"
        elif total_points >= 25:
            http_data["security_grade"] = "C"
        elif total_points >= 10:
            http_data["security_grade"] = "D"
        else:
            http_data["security_grade"] = "F (Vulnérable)"

    except Exception as e:
        http_data["is_reachable"] = False
        http_data["status_text"] = f"Échec de Connexion ({type(e).__name__})"

    return http_data

def detect_brand_impersonation(hostname: str) -> Dict[str, Any]:
    """Identify if target domain appears to spoof or impersonate a major trusted brand."""
    hostname_clean = hostname.lower()
    for brand, legit_domains in POPULAR_BRANDS.items():
        if brand in hostname_clean:
            # Check if this hostname actually belongs to the authentic brand
            is_legit = any(hostname_clean == d or hostname_clean.endswith('.' + d) for d in legit_domains)
            if not is_legit:
                return {
                    "is_impersonating": True,
                    "brand_name": brand.upper(),
                    "official_domains": legit_domains,
                    "severity": "CRITIQUE",
                    "explanation": f"Le domaine cible contient le mot-clé protégé '{brand}' mais n'appartient PAS aux domaines officiels vérifiés ({', '.join(legit_domains)}). C'est un indicateur majeur d'usurpation de marque / phishing."
                }

    return {
        "is_impersonating": False,
        "brand_name": None,
        "official_domains": [],
        "severity": "AUCUNE",
        "explanation": "Aucune usurpation de marque notoire détectée dans le nom de domaine."
    }

def inspect_endpoint_deeply(url_or_domain: str) -> Dict[str, Any]:
    """
    Perform a complete, fast, non-blocking real-world technical audit:
    - Live DNS records (A, AAAA, MX)
    - Live SSL/TLS Peer Certificate details
    - Live HTTP Connection, Latency, Server Banner, Title, and 6 Security Headers
    - Brand Impersonation Check
    """
    target_url, hostname, scheme = clean_url_and_domain(url_or_domain)

    # 1. DNS Resolution
    dns_info = resolve_dns_records(hostname)

    # 2. SSL/TLS Certificate (if https or port 443 accessible)
    ssl_info = inspect_ssl_certificate(hostname, port=443)

    # 3. HTTP Connection & Security Headers
    http_info = inspect_http_connection(target_url)

    # 4. Brand Impersonation check
    brand_info = detect_brand_impersonation(hostname)

    return {
        "hostname": hostname,
        "target_url": target_url,
        "dns": dns_info,
        "ssl": ssl_info,
        "http": http_info,
        "brand_impersonation": brand_info,
        "inspected_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    }
