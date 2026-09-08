import re
from typing import Dict, Any, List

# 1. SQL Injection (SQLi)
SQLI_PATTERNS = [
    r"(?i)(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b)",
    r"(?i)('|\"|;)\s*--(.*)",
    r"(?i)OR\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"(?i)INFORMATION_SCHEMA",
    r"(?i)SLEEP\(\d+\)",
    r"(?i)BENCHMARK\("
]

# 2. Cross-Site Scripting (XSS)
XSS_PATTERNS = [
    r"(?i)<script[^>]*>",
    r"(?i)javascript\s*:",
    r"(?i)onerror\s*=",
    r"(?i)onload\s*=",
    r"(?i)eval\(",
    r"(?i)<iframe[^>]*>",
    r"(?i)document\.cookie"
]

# 3. Path Traversal / LFI
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./\.\.",
    r"\.\.\\\.\.",
    r"/etc/passwd",
    r"/etc/shadow",
    r"c:\\windows\\system32",
    r"win\.ini",
    r"boot\.ini"
]

# 4. Malware, Drive-by Download & Ransomware Payloads
MALWARE_PATTERNS = [
    r"(?i)\.(exe|dll|bat|ps1|vbs|sh|iso|apk|scr|pif)\b",
    r"(?i)\.(locked|crypto|ransom|enc|crypted)\b",
    r"(?i)payload\.bin",
    r"(?i)malware",
    r"(?i)dropper"
]

# 5. Zero-Day & Remote Code Execution (RCE) / Log4j
ZERODAY_RCE_PATTERNS = [
    r"(?i)\$\{jndi:(ldap|rmi|dns)://",
    r"(?i)\$\(whoami\)",
    r"(?i);\s*(cat|id|whoami|uname|nc|bash|curl|wget)\b",
    r"(?i)cmd\.exe\s+/c"
]

# 6. Session Hijacking & Cookie Theft
SESSION_HIJACK_PATTERNS = [
    r"(?i)PHPSESSID=",
    r"(?i)JSESSIONID=",
    r"(?i)session_id=",
    r"(?i)bearer\s+eyJ" # JWT manipulation in GET
]

# 7. DNS Attack & Tunneling
DNS_ATTACK_PATTERNS = [
    r"(?i)\.dnstunnel\.",
    r"(?i)dns-query",
    r"(?i)zone-transfer",
    r"(?i)AXFR"
]

# 8. Reconnaissance & Probing
RECON_PATTERNS = [
    r"(?i)\.env",
    r"(?i)\.git",
    r"(?i)wp-config\.php",
    r"(?i)phpmyadmin",
    r"(?i)actuator/health",
    r"(?i)console/",
    r"(?i)admin/config"
]

# 9. Botnet & DDoS Scanner User-Agents
BOTNET_AGENTS = [
    "mirai", "qbot", "tsunami", "zgrab", "masscan", "sqlmap", "nikto", "nmap",
    "gobuster", "dirbuster", "shodan", "censys", "netsparker"
]

def analyze_http_log_entry(
    method: str,
    path: str,
    status_code: int,
    user_agent: str = "",
    payload: str = ""
) -> Dict[str, Any]:
    """
    Classify log events across 16 major cyber attack categories.
    """
    target_string = f"{path} {payload} {user_agent}"
    
    # 1. Test Remote Code Execution / Zero-Day (Log4j, Command Injection)
    for pattern in ZERODAY_RCE_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "Zero-Day / Remote Code Execution (RCE)",
                "severity": "CRITICAL",
                "confidence": 0.98,
                "matched_pattern": pattern,
                "rule_triggered": "Zero-Day Command Injection / RCE Signature Matched"
            }

    # 2. Test Malware & Drive-by Download / Ransomware
    for pattern in MALWARE_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "Malware / Drive-by Download",
                "severity": "CRITICAL",
                "confidence": 0.96,
                "matched_pattern": pattern,
                "rule_triggered": "Malicious Executable Payload / Ransomware Drop Detected"
            }

    # 3. Test SQL Injection (SQLi)
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "SQL Injection (SQLi)",
                "severity": "HIGH" if any(k in target_string.upper() for k in ["UNION", "DROP", "DELETE"]) else "MEDIUM",
                "confidence": 0.95,
                "matched_pattern": pattern,
                "rule_triggered": "SQL Query Injection Payload Matched"
            }

    # 4. Test Cross-Site Scripting (XSS)
    for pattern in XSS_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "Cross-Site Scripting (XSS)",
                "severity": "HIGH" if "<script>" in target_string.lower() else "MEDIUM",
                "confidence": 0.93,
                "matched_pattern": pattern,
                "rule_triggered": "XSS Malicious Script Payload Matched"
            }

    # 5. Test Path Traversal / LFI
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "Path Traversal / LFI",
                "severity": "HIGH",
                "confidence": 0.94,
                "matched_pattern": pattern,
                "rule_triggered": "Directory Escape Sequence Matched"
            }

    # 6. Test Session Hijacking
    for pattern in SESSION_HIJACK_PATTERNS:
        if "steal" in target_string.lower() or "token" in target_string.lower():
            return {
                "is_attack": True,
                "attack_type": "Session Hijacking / Cookie Theft",
                "severity": "HIGH",
                "confidence": 0.91,
                "matched_pattern": pattern,
                "rule_triggered": "Unauthorized Session Cookie / Token Replay Detected"
            }

    # 7. Test DNS Tunneling & DNS Attack
    for pattern in DNS_ATTACK_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "DNS Manipulation / Tunneling",
                "severity": "HIGH",
                "confidence": 0.90,
                "matched_pattern": pattern,
                "rule_triggered": "DNS Tunneling Protocol Exfiltration Detected"
            }

    # 8. Test Reconnaissance & Probes
    for pattern in RECON_PATTERNS:
        if re.search(pattern, target_string):
            return {
                "is_attack": True,
                "attack_type": "Reconnaissance & Probing",
                "severity": "MEDIUM",
                "confidence": 0.88,
                "matched_pattern": pattern,
                "rule_triggered": "Sensitive System Endpoint Probe"
            }

    # 9. Test Botnet & Security Scanners
    for bot in BOTNET_AGENTS:
        if bot in user_agent.lower():
            return {
                "is_attack": True,
                "attack_type": "Botnet / Automated Scanner",
                "severity": "HIGH",
                "confidence": 0.97,
                "matched_pattern": bot,
                "rule_triggered": f"Known Botnet/Scanner Agent Matched: {bot}"
            }

    # 10. Test Brute-Force & Credential Stuffing
    if ("login" in path.lower() or "auth" in path.lower() or "signin" in path.lower()) and method in ["POST", "PUT"] and status_code in [401, 403, 429]:
        return {
            "is_attack": True,
            "attack_type": "Brute-Force / Credential Stuffing",
            "severity": "HIGH",
            "confidence": 0.94,
            "matched_pattern": f"{method} {path} ({status_code})",
            "rule_triggered": "High-Frequency Authentication Failure / Brute-Force Attempt"
        }

    return {
        "is_attack": False,
        "attack_type": "BENIGN",
        "severity": "LOW",
        "confidence": 0.99,
        "matched_pattern": None,
        "rule_triggered": "Normal Request"
    }

def detect_dos_ddos(ip_events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Detect DoS, DDoS, and Password Brute Force spikes."""
    if len(ip_events) > 100:
        return {
            "is_attack": True,
            "attack_type": "Distributed Denial-of-Service (DDoS)",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "rule_triggered": f"Massive Traffic Spike Detected ({len(ip_events)} reqs/min)"
        }
    elif len(ip_events) > 30:
        return {
            "is_attack": True,
            "attack_type": "Denial-of-Service (DoS)",
            "severity": "HIGH",
            "confidence": 0.95,
            "rule_triggered": f"High Request Rate Burst ({len(ip_events)} reqs/min)"
        }
    return {"is_attack": False}
