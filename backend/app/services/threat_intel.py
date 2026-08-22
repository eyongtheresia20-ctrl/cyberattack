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
        is_suspicious_domain = any(bad in url.lower() for bad in ['paypal', 'verify', 'bank', 'login', 'claim', 'xyz', 'top', '192.168.'])
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
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5, verify=False)
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
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        is_bad = any(bad in url.lower() for bad in ['verify', 'suspend', 'claim', 'paypal', 'appleid'])
        return {
            "is_flagged": is_bad,
            "threat_types": ["MALWARE", "SOCIAL_ENGINEERING"] if is_bad else [],
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
        res = requests.post(endpoint, json=payload, timeout=5, verify=False)
        if res.status_code == 200:
            matches = res.json().get("matches", [])
            return {
                "is_flagged": len(matches) > 0,
                "threat_types": [m.get("threatType") for m in matches],
                "platform_type": "ALL",
                "source": "Google Safe Browsing Live API"
            }
    except Exception as e:
        print(f"[Warning] Google Safe Browsing API lookup error: {e}")

    return {
        "is_flagged": False,
        "threat_types": [],
        "source": "Google Safe Browsing (Offline Fallback)"
    }

