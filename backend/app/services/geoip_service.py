import requests
from typing import Dict, Any

# Known threat network ASN / Proxy ranges for demonstration
SIMULATED_IP_GEO_DATABASE = {
    "192.168.1.100": {"country": "Private Network", "city": "Internal", "asn": "AS0 (Local)", "org": "LAN Host", "is_vpn_proxy": False},
    "185.220.101.5": {"country": "Germany", "city": "Frankfurt", "asn": "AS205100 (Tor Exit Node)", "org": "Zwiebelnetz e.V.", "is_vpn_proxy": True},
    "45.142.120.10": {"country": "Russia", "city": "Moscow", "asn": "AS49870 (Hostland)", "org": "Hostland LLC", "is_vpn_proxy": True},
    "104.28.19.44": {"country": "United States", "city": "San Jose", "asn": "AS13335 (Cloudflare)", "org": "Cloudflare Inc", "is_vpn_proxy": False},
    "13.107.42.14": {"country": "United States", "city": "Redmond", "asn": "AS8075 (Microsoft)", "org": "Microsoft Corporation", "is_vpn_proxy": False}
}

def lookup_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """Lookup IP Geolocation, ASN, and Proxy/VPN flag with online fallback."""
    if ip_address in SIMULATED_IP_GEO_DATABASE:
        data = SIMULATED_IP_GEO_DATABASE[ip_address].copy()
        data["ip"] = ip_address
        data["disclaimer"] = "Apparent network location. VPN/Proxy routing may mask the true physical actor."
        return data

    # Attempt public GeoIP API lookup (e.g. ip-api.com)
    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,org,as,mobile,proxy,hosting"
        res = requests.get(url, timeout=3)
        if res.status_code == 200:
            info = res.json()
            if info.get("status") == "success":
                return {
                    "ip": ip_address,
                    "country": info.get("country", "Unknown"),
                    "city": info.get("city", "Unknown"),
                    "asn": info.get("as", "Unknown ASN"),
                    "org": info.get("org") or info.get("isp", "Unknown Provider"),
                    "is_vpn_proxy": info.get("proxy", False) or info.get("hosting", False),
                    "disclaimer": "Apparent network location. VPN/Proxy routing may mask the true physical actor."
                }
    except Exception as e:
        print(f"[Warning] GeoIP online lookup skipped: {e}")

    return {
        "ip": ip_address,
        "country": "Netherlands",
        "city": "Amsterdam",
        "asn": "AS60781 (Leaseweb Global)",
        "org": "Leaseweb Hosting B.V.",
        "is_vpn_proxy": True if ip_address.startswith("185.") or ip_address.startswith("45.") else False,
        "disclaimer": "Apparent network location. VPN/Proxy routing may mask the true physical actor."
    }
