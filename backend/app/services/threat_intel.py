import requests
import urllib3
from typing import Dict, Any, Tuple
from app.core.config import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SUSPICIOUS_TERMS = [
    'paypal', 'appleid', 'microsoft', 'google', 'bank', 'login', 'signin', 'verify', 'update',
    'account', 'claim', 'wallet', 'crypto', 'billing', 'secure', 'token', 'recover', 'ssn',
    '.xyz', '.top', '.club', '.work', '.info', '.biz', '.gq', '.cf', '.tk', '.ml', '.online', '.site', '192.168.'
]

class ServicePipelineException(Exception):
    """Exception raised when an essential external investigation service fails (quota, network, auth)."""
    def __init__(self, stage_name: str, service_name: str, user_message: str, admin_diagnostic: str, error_type: str = "SERVICE_FAILURE"):
        self.stage_name = stage_name
        self.service_name = service_name
        self.user_message = user_message
        self.admin_diagnostic = admin_diagnostic
        self.error_type = error_type
        super().__init__(user_message)


def _ml_simulate_vt(url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    ML-powered VirusTotal simulation.
    Derives positives count and categories from the enriched 27-feature set.
    Used when VT API is unavailable (quota, timeout, no key).
    """
    if features is None:
        from app.ml.url_feature_extractor import extract_url_features
        features = extract_url_features(url)

    vt_pos_sim = features.get("vt_positives_sim", 0.0)
    brand_sim   = features.get("brand_impersonation_sim", 0.0)
    threat_cat  = features.get("threat_category_sim", 0)
    consensus   = features.get("multi_engine_consensus", 0.0)

    positives = int(round(vt_pos_sim))
    total_engines = 90

    # Derive category labels from threat_category_sim
    if threat_cat == 3:
        categories = ["Phishing", "Malware", "Social Engineering"]
    elif threat_cat == 2:
        categories = ["Malware", "Drive-By Download"]
    elif threat_cat == 1:
        categories = ["Phishing", "Social Engineering"]
    elif brand_sim >= 0.5:
        categories = ["Phishing", "Brand Impersonation"]
    else:
        categories = ["Clean / Legitimate"]

    reputation_score = -int(consensus * 100) if positives > 0 else max(0, int((1 - consensus) * 85))

    return {
        "status": "ml_autonomous",
        "positives": positives,
        "total_engines": total_engines,
        "reputation_score": reputation_score,
        "categories": categories,
        "source": "Moteur ML Autonome — Émulation VirusTotal (27 Indicateurs)",
        "ml_features_used": ["vt_positives_sim", "brand_impersonation_sim",
                              "threat_category_sim", "multi_engine_consensus"],
        "api_status": "fallback"
    }


def _ml_simulate_gsb(url: str, features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    ML-powered Google Safe Browsing simulation.
    Uses gsb_social_sim and gsb_malware_sim features from the enriched extractor.
    Used when GSB API is unavailable (quota, timeout, no key).
    """
    if features is None:
        from app.ml.url_feature_extractor import extract_url_features
        features = extract_url_features(url)

    gsb_social = features.get("gsb_social_sim", 0.0)
    gsb_malware = features.get("gsb_malware_sim", 0.0)

    threat_types = []
    if gsb_social >= 0.35:
        threat_types.append("SOCIAL_ENGINEERING")
    if gsb_malware >= 0.35:
        threat_types.append("MALWARE")
    if features.get("brand_impersonation_sim", 0) >= 0.5:
        threat_types.append("SOCIAL_ENGINEERING")  # ensure set
    threat_types = list(set(threat_types))

    is_flagged = len(threat_types) > 0

    return {
        "is_flagged": is_flagged,
        "threat_types": threat_types,
        "platform_type": "ANY_PLATFORM",
        "source": "Moteur ML Autonome — Émulation Google Safe Browsing (27 Indicateurs)",
        "gsb_social_score": round(gsb_social, 4),
        "gsb_malware_score": round(gsb_malware, 4),
        "ml_features_used": ["gsb_social_sim", "gsb_malware_sim", "brand_impersonation_sim"],
        "api_status": "fallback"
    }


def query_virustotal_url_reputation(url: str,
                                     features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Query VirusTotal v3 API for URL threat reputation.

    Priority chain:
      1. Live VT API call — if key present and service reachable
      2. ML-powered simulation — on quota (429), auth failure, or timeout
    The analysis NEVER stops; ML fills in seamlessly.
    """
    api_key = settings.VIRUSTOTAL_API_KEY

    if not api_key:
        result = _ml_simulate_vt(url, features)
        result["status"] = "ml_autonomous_no_key"
        return result

    headers = {"x-apikey": api_key}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=4.0, verify=False
        )

        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
            categories = list(attrs.get("categories", {}).values()) or []
            if not categories:
                # Enrich with ML categories when VT doesn't return them
                sim = _ml_simulate_vt(url, features)
                categories = sim["categories"]

            return {
                "status": "live",
                "positives": positives,
                "total_engines": sum(stats.values()) or 90,
                "reputation_score": attrs.get("reputation", 0),
                "categories": categories,
                "source": "VirusTotal Live API v3",
                "api_status": "live"
            }

        # HTTP 429 = quota exhausted; 401 = bad key; 5xx = VT outage
        print(f"[VT] HTTP {response.status_code} — switching to ML autonomous mode.")
        result = _ml_simulate_vt(url, features)
        result["status"] = f"ml_fallback_http_{response.status_code}"
        return result

    except Exception as exc:
        print(f"[VT] Network exception ({exc}) — switching to ML autonomous mode.")
        result = _ml_simulate_vt(url, features)
        result["status"] = "ml_fallback_timeout"
        return result


def query_google_safebrowsing(url: str,
                               features: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Query Google Safe Browsing v4 API.

    Priority chain:
      1. Live GSB API call — if key present and service reachable
      2. ML-powered simulation — on quota, auth failure, or timeout
    The analysis NEVER stops; ML fills in seamlessly.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_API_KEY

    if not api_key:
        result = _ml_simulate_gsb(url, features)
        result["status"] = "ml_autonomous_no_key"
        return result

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        res = requests.post(endpoint, json=payload, timeout=4.0, verify=False)

        if res.status_code == 200:
            matches = res.json().get("matches", [])
            is_flagged = len(matches) > 0
            threat_types = [m.get("threatType") for m in matches] if matches else []

            # Augment with ML features when GSB returns clean but ML disagrees
            if not is_flagged:
                ml_sim = _ml_simulate_gsb(url, features)
                if ml_sim["is_flagged"]:
                    # ML detected threat GSB missed — add ML signal as enrichment
                    threat_types = ml_sim["threat_types"]
                    is_flagged = True

            return {
                "is_flagged": is_flagged,
                "threat_types": list(set(threat_types)),
                "platform_type": "ANY_PLATFORM",
                "source": "Google Safe Browsing Live API v4 + ML Enrichment",
                "api_status": "live"
            }

        print(f"[GSB] HTTP {res.status_code} — switching to ML autonomous mode.")
        result = _ml_simulate_gsb(url, features)
        result["status"] = f"ml_fallback_http_{res.status_code}"
        return result

    except Exception as exc:
        print(f"[GSB] Network exception ({exc}) — switching to ML autonomous mode.")
        result = _ml_simulate_gsb(url, features)
        result["status"] = "ml_fallback_timeout"
        return result
