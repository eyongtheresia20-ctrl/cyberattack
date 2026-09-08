import requests
import urllib3
from typing import Dict, Any
from app.core.config import settings

# Disable insecure request warnings when ssl verification is bypassed locally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def query_virustotal_url_reputation(url: str) -> Dict[str, Any]:
    """Query VirusTotal v3 API for URL threat reputation with intelligent mock fallback."""
    api_key = settings.VIRUSTOTAL_API_KEY
    if not api_key:
        # Realistic Threat Intelligence Simulation / Heuristic check
        suspicious_terms = [
            'paypal', 'appleid', 'microsoft', 'google', 'bank', 'login', 'signin', 'verify', 'update',
            'account', 'claim', 'wallet', 'crypto', 'billing', 'secure', 'token', 'recover', 'ssn',
            '.xyz', '.top', '.club', '.work', '.info', '.biz', '.gq', '.cf', '.tk', '.ml', '.online', '.site', '192.168.'
        ]
        is_suspicious_domain = any(bad in url.lower() for bad in suspicious_terms)
        return {
            "status": "simulated",
            "positives": 7 if is_suspicious_domain else 0,
            "total_engines": 90,
            "reputation_score": -45 if is_suspicious_domain else 85,
            "categories": ["Phishing", "Malware"] if is_suspicious_domain else ["Clean"],
            "source": "VirusTotal Intelligence (Simulated)"
        }

    headers = {"x-apikey": api_key}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=1.5, verify=False)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "status": "live",
                "positives": stats.get("malicious", 0) + stats.get("suspicious", 0),
                "total_engines": sum(stats.values()),
                "reputation_score": data.get("data", {}).get("attributes", {}).get("reputation", 0),
                "categories": list(data.get("data", {}).get("attributes", {}).get("categories", {}).values()),
                "source": "VirusTotal Live API"
            }
    except Exception as e:
        print(f"[Warning] VirusTotal API lookup error: {e}")

    return {
        "status": "fallback",
        "positives": 0,
        "total_engines": 90,
        "reputation_score": 0,
        "categories": ["Unknown"],
        "source": "VirusTotal (Offline Fallback)"
    }

def query_google_safebrowsing(url: str) -> Dict[str, Any]:
    """Query Google Safe Browsing v4 API with mock fallback."""
    suspicious_terms = [
        'verify', 'suspend', 'claim', 'paypal', 'appleid', 'bank', 'login', 'signin', 'update',
        'billing', 'secure', 'crypto', 'wallet', '.xyz', '.top', '.club', '.work', '.site', '.online'
    ]
    heuristic_bad = any(bad in url.lower() for bad in suspicious_terms)

    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return {
            "is_flagged": heuristic_bad,
            "threat_types": ["MALWARE", "SOCIAL_ENGINEERING"] if heuristic_bad else [],
            "platform_type": "ANY_PLATFORM",
            "source": "Google Safe Browsing (Simulated)"
        }
    
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(endpoint, json=payload, timeout=2.0, verify=False)
        if res.status_code == 200:
            matches = res.json().get("matches", [])
            is_flagged = len(matches) > 0 or heuristic_bad
            return {
                "is_flagged": is_flagged,
                "threat_types": [m.get("threatType") for m in matches] if matches else (["SOCIAL_ENGINEERING"] if heuristic_bad else []),
                "platform_type": "ALL",
                "source": "Google Safe Browsing Live API"
            }
    except Exception as e:
        print(f"[Warning] Google Safe Browsing API lookup error: {e}")

    return {
        "is_flagged": heuristic_bad,
        "threat_types": ["SOCIAL_ENGINEERING"] if heuristic_bad else [],
        "source": "Google Safe Browsing (Offline Fallback)"
    }

