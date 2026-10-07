"""
========================================================================================
CYBERGUARD SOC — SERVICE DU PARE-FEU DYNAMIQUE ACTIF & PIÈGES HONEYPOT
========================================================================================
Rôle et Responsabilités :
- Gestion de la liste noire (Blacklist) en mémoire vive et synchronisée avec le WAF.
- Interception dynamique en ligne de toute requête provenant d'une adresse IP hostile.
- Détection et capture proactive des attaquants via les endpoints leurres (Honeypot).
- Bannissement automatique et immédiat dès qu'un attaquant touche un leurre sensible.
========================================================================================
"""

import time
from typing import Dict, Any, List

# --------------------------------------------------------------------------------------
# 1. TABLEAU DE BORD DE LA LISTE NOIRE DU PARE-FEU (WAF Blacklist en mémoire)
# --------------------------------------------------------------------------------------
# Dictionnaire indexé par adresse IP contenant les détails d'audit et la sévérité.
_BLOCKED_IPS: Dict[str, Dict[str, Any]] = {
    "185.220.101.5": {
        "ip": "185.220.101.5",
        "reason": "Attaques répétées par Force Brute (45 tentatives/60s) & Braconnage WAF",
        "severity": "CRITICAL",
        "blocked_at": "2026-09-28 04:30:10 UTC",
        "expires_in_minutes": 1440,
        "is_permanent": True,
        "blocked_by": "CyberGuard WAF Auto-Defend",
        "attacks_intercepted_count": 8
    },
    "45.154.255.87": {
        "ip": "45.154.255.87",
        "reason": "Exploitation Path Traversal / LFI (/../../etc/passwd)",
        "severity": "HIGH",
        "blocked_at": "2026-09-28 04:32:00 UTC",
        "expires_in_minutes": 720,
        "is_permanent": False,
        "blocked_by": "CyberGuard WAF Auto-Defend",
        "attacks_intercepted_count": 3
    }
}

# --------------------------------------------------------------------------------------
# 2. JOURNAL DES ATTAQUANTS PIÉGÉS PAR LES LEURRES HONEYPOT
# --------------------------------------------------------------------------------------
# Enregistre les sondes hostiles attirées par les faux points d'entrée (/wp-login.php, /.env)
_HONEYPOT_HITS: List[Dict[str, Any]] = [
    {
        "id": "HNY-01",
        "trap_endpoint": "/wp-login.php",
        "attacker_ip": "194.26.29.112",
        "country": "Germany",
        "timestamp": "28/09/2026 05:12:00",
        "user_agent": "Mozilla/5.0 (Hydra Bot)",
        "payload": "user=admin&pass=admin123",
        "status": "PIÉGÉ & BANNI AUTOMATIQUEMENT"
    },
    {
        "id": "HNY-02",
        "trap_endpoint": "/.env",
        "attacker_ip": "91.108.12.44",
        "country": "Russia",
        "timestamp": "28/09/2026 05:25:30",
        "user_agent": "python-requests/2.31",
        "payload": "Reconnaissance clé secrète AWS/DB",
        "status": "PIÉGÉ & BANNI AUTOMATIQUEMENT"
    }
]

def is_ip_blocked(ip: str) -> bool:
    """
    Vérifie si une adresse IP cliente est présente dans la liste noire active du pare-feu.
    Utilisé en amont par le middleware WAF pour bloquer l'accès en < 1 milliseconde.
    """
    return ip in _BLOCKED_IPS

def get_blocked_ip_info(ip: str) -> Dict[str, Any]:
    """
    Récupère les détails et la justification du blocage pour une adresse IP donnée.
    """
    return _BLOCKED_IPS.get(ip)

def list_all_blocked_ips() -> List[Dict[str, Any]]:
    """
    Retourne la liste intégrale de toutes les adresses IP actuellement sous embargo.
    """
    return list(_BLOCKED_IPS.values())

def block_ip_address(ip: str, reason: str = "Interception WAF d'attaque critique", severity: str = "HIGH", blocked_by: str = "Administrateur SOC") -> Dict[str, Any]:
    """
    Ajoute ou actualise une adresse IP dans la liste noire active du pare-feu dynamique.
    Appliqué immédiatement sans redémarrage du serveur.
    """
    entry = {
        "ip": ip,
        "reason": reason,
        "severity": severity,
        "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "expires_in_minutes": 1440,
        "is_permanent": True,
        "blocked_by": blocked_by,
        "attacks_intercepted_count": 1
    }
    _BLOCKED_IPS[ip] = entry
    return entry

def unblock_ip_address(ip: str) -> bool:
    """
    Lève le blocage d'une adresse IP et lui réautorise l'accès normal à la plateforme.
    """
    if ip in _BLOCKED_IPS:
        del _BLOCKED_IPS[ip]
        return True
    return False

def record_honeypot_hit(trap_endpoint: str, attacker_ip: str, user_agent: str = "", payload: str = "") -> Dict[str, Any]:
    """
    Enregistre une tentative d'intrusion sur un leurre Honeypot et applique
    instantanément un bannissement automatique de l'IP hostile dans le pare-feu.
    """
    # Bannissement automatique immédiat de l'attaquant dans la blacklist active
    block_ip_address(
        ip=attacker_ip,
        reason=f"Sonde hostile interceptée sur le piège Honeypot {trap_endpoint}",
        severity="CRITICAL",
        blocked_by="CyberGuard Honeypot Auto-Blacklist"
    )
    hit = {
        "id": f"HNY-{len(_HONEYPOT_HITS) + 1:02d}",
        "trap_endpoint": trap_endpoint,
        "attacker_ip": attacker_ip,
        "country": "Inconnu",
        "timestamp": time.strftime("%d/%m/%Y %H:%M:%S", time.localtime()),
        "user_agent": user_agent[:60],
        "payload": payload[:100] or "Sonde d'empreinte automatisée",
        "status": "PIÉGÉ & BANNI AUTOMATIQUEMENT"
    }
    _HONEYPOT_HITS.insert(0, hit)
    return hit

def get_honeypot_hits() -> List[Dict[str, Any]]:
    """
    Retourne la liste chronologique des intrusions leurrées par le module Honeypot.
    """
    return _HONEYPOT_HITS
