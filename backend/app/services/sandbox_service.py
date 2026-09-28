import re
import time
import base64
from typing import Dict, Any, List
from urllib.parse import urlparse, urljoin
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def analyze_url_sandbox(target_url: str) -> Dict[str, Any]:
    """
    Headless Browser Sandbox & Dynamic DOM Analysis Engine.
    Simulates dynamic page detonation, inspects DOM elements, forms,
    redirect chains, scripts, and captures visual page preview metadata.
    """
    clean_url = target_url.strip()
    if not clean_url.startswith(('http://', 'https://')):
        clean_url = 'https://' + clean_url

    parsed = urlparse(clean_url)
    hostname = parsed.netloc.split(':')[0]

    result = {
        "target_url": clean_url,
        "hostname": hostname,
        "sandbox_status": "COMPLETED",
        "redirect_chain": [],
        "dom_analysis": {
            "forms": [],
            "password_inputs_count": 0,
            "credit_card_inputs_count": 0,
            "external_scripts": [],
            "iframes": [],
            "has_hidden_iframes": False,
            "has_deceptive_login_form": False,
            "page_title": "",
            "favicon_url": ""
        },
        "behavioral_indicators": [],
        "sandbox_risk_score": 0,
        "sandbox_verdict": "BENIGN",
        "visual_preview": None,
        "detonated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    }

    start_time = time.time()
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 CyberGuard-Sandbox/3.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7"
        }
        session = requests.Session()
        res = session.get(clean_url, headers=headers, timeout=4.5, allow_redirects=True, verify=False)
        duration_ms = int((time.time() - start_time) * 1000)

        # 1. Trace Full Redirect Chain
        chain = []
        for hop in res.history:
            chain.append({
                "status_code": hop.status_code,
                "url": hop.url,
                "location": hop.headers.get("Location", "")
            })
        chain.append({
            "status_code": res.status_code,
            "url": res.url,
            "location": "FINAL_DESTINATION"
        })
        result["redirect_chain"] = chain
        result["duration_ms"] = duration_ms

        html = res.text or ""
        html_lower = html.lower()

        # 2. Extract Title & Favicon
        title_m = re.search(r'<title[^>]*>(.*?)</title>', html, re.I | re.S)
        if title_m:
            result["dom_analysis"]["page_title"] = title_m.group(1).strip()[:100]

        fav_m = re.search(r'<link[^>]*rel=[\'"](?:shortcut )?icon[\'"][^>]*href=[\'"]([^\'"]+)[\'"]', html, re.I)
        if fav_m:
            result["dom_analysis"]["favicon_url"] = urljoin(res.url, fav_m.group(1))

        # 3. Form & Credential Theft Inspection
        forms = []
        form_matches = re.finditer(r'<form\b([^>]*)>(.*?)</form>', html, re.I | re.S)
        for fm in form_matches:
            attrs = fm.group(1)
            body = fm.group(2)
            action_m = re.search(r'action=[\'"]([^\'"]*)[\'"]', attrs, re.I)
            method_m = re.search(r'method=[\'"]([^\'"]*)[\'"]', attrs, re.I)
            action_url = action_m.group(1) if action_m else ""
            method = method_m.group(1).upper() if method_m else "GET"

            has_pwd = bool(re.search(r'type=[\'"]password[\'"]', body, re.I))
            has_cc = bool(re.search(r'(card|cvv|expir|credit|carte|banque)', body, re.I))
            forms.append({
                "action": action_url,
                "full_action_url": urljoin(res.url, action_url) if action_url else res.url,
                "method": method,
                "has_password_field": has_pwd,
                "has_financial_field": has_cc
            })
            if has_pwd:
                result["dom_analysis"]["password_inputs_count"] += 1
            if has_cc:
                result["dom_analysis"]["credit_card_inputs_count"] += 1

        result["dom_analysis"]["forms"] = forms[:5]

        # 4. External Scripts
        script_srcs = re.findall(r'<script\b[^>]*src=[\'"]([^\'"]+)[\'"]', html, re.I)
        ext_scripts = []
        for s in script_srcs:
            full_s = urljoin(res.url, s)
            ext_scripts.append(full_s)
        result["dom_analysis"]["external_scripts"] = ext_scripts[:8]

        # 5. Iframes
        iframes = re.findall(r'<iframe\b[^>]*src=[\'"]([^\'"]+)[\'"]', html, re.I)
        result["dom_analysis"]["iframes"] = iframes[:4]
        if "<iframe" in html_lower and ("display:none" in html_lower or "visibility:hidden" in html_lower or "width=0" in html_lower or "height=0" in html_lower):
            result["dom_analysis"]["has_hidden_iframes"] = True

        # 6. Behavioral Heuristics Scoring
        risk_score = 0
        indicators = []

        if len(chain) > 2:
            risk_score += 25
            indicators.append(f"Chaîne de redirection suspecte ({len(chain)} rebonds détectés)")

        if result["dom_analysis"]["password_inputs_count"] > 0:
            if not res.url.startswith("https://"):
                risk_score += 45
                indicators.append("Formulaire de saisie de mot de passe transmis sur HTTP non chiffré")
            else:
                risk_score += 15
                indicators.append("Formulaire de collecte d'identifiants (mot de passe)")

        if result["dom_analysis"]["credit_card_inputs_count"] > 0:
            risk_score += 35
            indicators.append("Champs de collecte de données bancaires / cartes de crédit détectés")

        if result["dom_analysis"]["has_hidden_iframes"]:
            risk_score += 30
            indicators.append("Iframe masqué détecté (technique classique de Clickjacking / Drive-By)")

        # Brand Spoofing in Title/DOM vs domain
        for brand in ["paypal", "apple", "microsoft", "google", "netflix", "binance"]:
            if brand in (result["dom_analysis"]["page_title"].lower() + " " + html_lower[:5000]):
                if brand not in hostname:
                    risk_score += 40
                    indicators.append(f"Usurpation visuelle / de marque détectée dans le DOM (Référence à '{brand.upper()}' hors du domaine officiel)")
                    result["dom_analysis"]["has_deceptive_login_form"] = True
                    break

        result["behavioral_indicators"] = indicators
        result["sandbox_risk_score"] = min(100, risk_score)
        result["sandbox_verdict"] = "MALICIOUS" if risk_score >= 60 else ("SUSPICIOUS" if risk_score >= 30 else "CLEAN")

        # 7. Rendered Visual Preview Metadata
        result["visual_preview"] = {
            "title": result["dom_analysis"]["page_title"] or hostname,
            "status": f"{res.status_code} {res.reason}",
            "dom_elements_count": len(re.findall(r'<[a-zA-Z0-9]+', html)),
            "content_size_kb": round(len(html) / 1024, 1),
            "final_host": urlparse(res.url).netloc,
            "is_ssl_secured": res.url.startswith("https://")
        }

    except Exception as exc:
        result["sandbox_status"] = "ERROR_DETONATION_FAILED"
        result["error"] = str(exc)
        result["sandbox_verdict"] = "UNREACHABLE"

    return result
