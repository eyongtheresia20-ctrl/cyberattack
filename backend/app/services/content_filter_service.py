"""
CyberGuard SOC — Service de Filtrage de Contenu & Contrôle Parental (MINESEC Policy)
======================================================================================
Ce module assure la détection et le blocage automatique des contenus adultes (pornographie,
contenus explicites, cam/escort) ainsi que des jeux de hasard / paris en ligne (gambling/casinos),
conformément à la politique de sécurité des établissements scolaires et administratifs (MINESEC).

Fonctionnalités :
1. Détection par signatures de domaines réputés adultes / casinos.
2. Détection par mots-clés lexicaux et sous-domaines (FR & EN).
3. Détection par extensions de domaines réservées (.xxx, .porn, .adult, .bet, etc.).
4. Paramétrage dynamique (activable / désactivable en temps réel via les paramètres).
5. Persistance de la configuration dans un fichier d'état JSON.
"""

import os
import json
import re
from urllib.parse import urlparse
from typing import Dict, Any, List

SETTINGS_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "db", "policy_settings.json")

# Configuration par défaut conforme aux exigences du MINESEC (Protection scolaire active)
DEFAULT_SETTINGS: Dict[str, Any] = {
    "block_adult_content": True,
    "block_gambling": True,
    "enforcement_mode": "BLOCK",  # "BLOCK" (Blocage automatique) | "WARN" (Avertissement) | "ALLOW" (Autoriser)
    "school_shield_active": True,
    "redirect_to_block_page": True,
    "custom_blacklist": [],
    "custom_whitelist": [],
    "ml_auto_block_phishing": True,
    "shannon_entropy_detection": True,
    "external_threat_intel": True,
    "waf_autoban_hostile_ips": True,
    "honeypot_active_defense": True,
    "sha256_forensic_sealing": True,
    "sentinel_realtime_protection": True,
    "audio_alert_chimes": True
}

# ── 1. SIGNATURES DE DOMAINES ADULTES & EXPLICITES CONNUS ───────────────────────
KNOWN_ADULT_DOMAINS = {
    # Portails vidéo / streaming adulte majeurs
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com", "youporn.com",
    "redtube.com", "tube8.com", "spankbang.com", "eporner.com", "beeg.com",
    "brazzers.com", "bangbros.com", "naughtyamerica.com", "realitykings.com",
    "chaturbate.com", "cam4.com", "bongacams.com", "myfreecams.com", "livejasmin.com",
    "stripchat.com", "camsoda.com", "onlyfans.com", "fansly.com", "manyvids.com",
    "fapello.com", "coomer.party", "kemono.party", "erome.com", "thothub.to",
    "hentaihaven.xxx", "nhentai.net", "hanime.tv", "rule34.xxx", "gelbooru.com"
}

# ── 2. SIGNATURES DE SITES DE JEUX D'ARGENT / PARIS / CASINOS ───────────────────
KNOWN_GAMBLING_DOMAINS = {
    "1xbet.com", "1xbet.cm", "betway.com", "bet9ja.com", "betclic.fr",
    "winamax.fr", "pmu.fr", "bwin.com", "bet365.com", "pokerstars.com",
    "888casino.com", "stake.com", "roobet.com", "rollbit.com", "premierbet.cm",
    "supergoal.cm", "cameroon-bet.com"
}

# ── 3. TLDs SPÉCIALISÉS DANS LE CONTENU ADULTE & LES PARIS ─────────────────────
ADULT_TLDS = {".xxx", ".porn", ".adult", ".sex", ".sexy", ".cam", ".tube"}
GAMBLING_TLDS = {".bet", ".casino", ".poker", ".bingo", ".lotto"}

# ── 4. MOTS-CLÉS LEXICAUX SUSPECTS (FR / EN) ───────────────────────────────────
ADULT_KEYWORDS = [
    "porn", "porno", "xxx", "sex", "sexe", "nude", "nu", "erotic", "erotique",
    "hardcore", "hentai", "camgirl", "webcam-sex", "escort", "escort-girl",
    "anal", "blowjob", "milf", "bdsm", "fetish", "voyeur", "peepshow",
    "masturbat", "orgasm", "gangbang", "nsfw", "adult-video", "adult-content",
    "striptease", "sexchat"
]

GAMBLING_KEYWORDS = [
    "casino", "roulette", "blackjack", "slot-machine", "pari-sportif",
    "paris-sportifs", "poker", "jackpot", "betting", "bookmaker", "sportsbet",
    "jeu-hasard", "loterie", "free-spins", "crypto-casino"
]


def load_policy_settings() -> Dict[str, Any]:
    """Charge les paramètres de sécurité actuels depuis le stockage persistant."""
    if not os.path.exists(SETTINGS_FILE):
        save_policy_settings(DEFAULT_SETTINGS)
        return dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Compléter avec les valeurs par défaut au cas où de nouveaux champs ont été ajoutés
            for k, v in DEFAULT_SETTINGS.items():
                if k not in data:
                    data[k] = v
            return data
    except Exception as e:
        print(f"[ContentFilter] Erreur lecture settings : {e}")
        return dict(DEFAULT_SETTINGS)


def save_policy_settings(settings: Dict[str, Any]) -> bool:
    """Enregistre les paramètres de filtrage de contenu dans le stockage persistant."""
    try:
        os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"[ContentFilter] Erreur écriture settings : {e}")
        return False


def check_url_content_policy(raw_url: str, user: Any = None) -> Dict[str, Any]:
    """
    Inspecte une URL contre les politiques de filtrage de contenu (globales et spécifiques à l'utilisateur).
    Renvoie le verdict, la catégorie, les raisons et l'action à appliquer (BLOCK / WARN / ALLOW).
    """
    settings = load_policy_settings()
    block_adult = settings.get("block_adult_content", True)
    block_gambling = settings.get("block_gambling", True)
    enforcement = settings.get("enforcement_mode", "BLOCK")

    url = (raw_url or "").strip().lower()
    if not url:
        return {
            "is_restricted": False,
            "category": "CLEAN",
            "action": "ALLOW",
            "reasons": [],
            "redirect_to_block_page": settings.get("redirect_to_block_page", True)
        }

    # Extraction du domaine et du chemin
    parsed = urlparse(url if "://" in url else f"http://{url}")
    domain = parsed.hostname or url.split("/")[0]
    path = parsed.path or ""
    query = parsed.query or ""
    full_target = f"{domain}{path}?{query}"

    # 0. VÉRIFICATION STRICTE DES SITES BLOQUÉS SPÉCIFIQUEMENT POUR CET UTILISATEUR
    if user:
        raw_bs = getattr(user, "blocked_sites", None)
        user_blocked_sites = []
        if isinstance(raw_bs, list):
            user_blocked_sites = list(raw_bs)
        elif isinstance(raw_bs, str):
            try:
                user_blocked_sites = json.loads(raw_bs)
            except Exception:
                user_blocked_sites = []

        # Check real-time user restrictions dynamically synced in settings
        u_id = str(getattr(user, "id", ""))
        u_email = str(getattr(user, "email", "")).lower()
        user_res_map = settings.get("user_restrictions", {})
        specific_res = user_res_map.get(u_id) or user_res_map.get(u_email) or {}
        if specific_res.get("blocked_sites"):
            for s in specific_res["blocked_sites"]:
                if s not in user_blocked_sites:
                    user_blocked_sites.append(s)

        for bs in user_blocked_sites:
            clean_bs = (bs or "").strip().lower()
            if clean_bs and (domain == clean_bs or domain.endswith("." + clean_bs) or clean_bs in domain):
                return {
                    "url": raw_url,
                    "is_restricted": True,
                    "is_adult": False,
                    "is_gambling": False,
                    "category": "SITE BLOQUÉ PAR L'ADMINISTRATEUR",
                    "action": "BLOCK",
                    "reasons": [f"L'accès au site '{clean_bs}' est formellement interdit pour votre compte par l'Administrateur SOC."],
                    "blocked_by_user_policy": True,
                    "redirect_to_block_page": True,
                    "enforcement_mode": "BLOCK"
                }

        # Vérification des catégories personnalisées de l'utilisateur
        raw_perms = getattr(user, "permissions", None)
        user_perms = {}
        if isinstance(raw_perms, dict):
            user_perms = dict(raw_perms)
        elif isinstance(raw_perms, str):
            try:
                user_perms = json.loads(raw_perms)
            except Exception:
                user_perms = {}
        if specific_res.get("permissions"):
            user_perms.update(specific_res["permissions"])
        # Si l'administrateur a coché "Bloquer tous les sites assignés dans les paramètres"
        if user_perms.get("block_all_settings_sites"):
            blacklist = settings.get("custom_blacklist", [])
            for b in blacklist:
                clean_b = (b or "").strip().lower()
                if clean_b and (domain == clean_b or domain.endswith("." + clean_b) or clean_b in domain):
                    return {
                        "url": raw_url,
                        "is_restricted": True,
                        "is_adult": False,
                        "is_gambling": False,
                        "category": "SITE BLOQUÉ PAR L'ADMINISTRATEUR",
                        "action": "BLOCK",
                        "reasons": [f"Ce site '{clean_b}' fait partie des sites interdits assignés depuis les Paramètres pour votre compte."],
                        "blocked_by_user_policy": True,
                        "redirect_to_block_page": True,
                        "enforcement_mode": "BLOCK"
                    }

        if user_perms.get("block_social_media"):
            social_domains = ["facebook.com", "instagram.com", "twitter.com", "x.com", "tiktok.com", "linkedin.com", "snapchat.com", "reddit.com", "pinterest.com"]
            if any(domain == sd or domain.endswith("." + sd) or sd in domain for sd in social_domains):
                return {
                    "url": raw_url,
                    "is_restricted": True,
                    "is_adult": False,
                    "is_gambling": False,
                    "category": "RÉSEAU SOCIAL BLOQUÉ",
                    "action": "BLOCK",
                    "reasons": ["Les réseaux sociaux sont bloqués pour votre profil utilisateur par l'administrateur."],
                    "blocked_by_user_policy": True,
                    "redirect_to_block_page": True
                }

        if user_perms.get("block_streaming"):
            stream_domains = ["youtube.com", "netflix.com", "twitch.tv", "dailymotion.com", "disneyplus.com", "primevideo.com", "tiktok.com"]
            if any(domain == st or domain.endswith("." + st) or st in domain for st in stream_domains):
                return {
                    "url": raw_url,
                    "is_restricted": True,
                    "is_adult": False,
                    "is_gambling": False,
                    "category": "STREAMING VIDÉO BLOQUÉ",
                    "action": "BLOCK",
                    "reasons": ["Les plateformes de streaming vidéo sont bloquées pour votre profil utilisateur."],
                    "blocked_by_user_policy": True,
                    "redirect_to_block_page": True
                }

    if not settings.get("school_shield_active", True):
        return {
            "is_restricted": False,
            "category": "CLEAN",
            "action": "ALLOW",
            "reasons": [],
            "redirect_to_block_page": settings.get("redirect_to_block_page", True)
        }

    matched_reasons: List[str] = []
    category = "CLEAN"
    is_adult = False
    is_gambling = False

    # 1. Vérification Whitelist personnalisée
    whitelist = settings.get("custom_whitelist", [])
    if any(w.lower() in domain for w in whitelist if w.strip()):
        return {
            "is_restricted": False,
            "category": "WHITELISTED",
            "action": "ALLOW",
            "reasons": ["Domaine explicitement autorisé dans la liste blanche de l'établissement"]
        }

    # 2. Vérification Blacklist personnalisée
    blacklist = settings.get("custom_blacklist", [])
    for b in blacklist:
        clean_b = (b or "").strip().lower()
        if clean_b and (domain == clean_b or domain.endswith("." + clean_b) or clean_b in domain):
            return {
                "url": raw_url,
                "is_restricted": True,
                "is_adult": False,
                "is_gambling": False,
                "category": "SITE BLOQUÉ PAR L'ADMINISTRATEUR (PARAMÈTRES)",
                "action": "BLOCK",
                "reasons": [f"Ce domaine '{clean_b}' est expressément bloqué dans les Paramètres de sécurité SOC."],
                "blocked_by_user_policy": False,
                "redirect_to_block_page": settings.get("redirect_to_block_page", True),
                "enforcement_mode": "BLOCK"
            }

    # 3. Vérification des Domaines Adultes Réputés
    if not is_adult:
        for ad in KNOWN_ADULT_DOMAINS:
            if domain == ad or domain.endswith("." + ad) or ad in domain:
                is_adult = True
                category = "ADULT_PORNOGRAPHY"
                matched_reasons.append(f"Domaine répertorié dans la base mondiale de contenu adulte ({ad})")
                break

    # 4. Vérification des TLDs Adultes (.xxx, .porn, etc.)
    if not is_adult:
        for tld in ADULT_TLDS:
            if domain.endswith(tld):
                is_adult = True
                category = "ADULT_PORNOGRAPHY"
                matched_reasons.append(f"Extension de domaine explicitement réservée au contenu adulte ({tld})")
                break

    # 5. Vérification Lexicale & Mots-clés Adultes dans le domaine et le chemin
    if not is_adult:
        tokens = re.split(r"[\.\-\_\/\?\=\&]", full_target)
        found_kw = [kw for kw in ADULT_KEYWORDS if any(kw == t or t.startswith(kw) for t in tokens)]
        if found_kw:
            is_adult = True
            category = "ADULT_CONTENT"
            matched_reasons.append(f"Présence de mots-clés de contenu adulte explicite : {', '.join(set(found_kw[:3]))}")

    # 6. Vérification des Jeux d'argent / Paris (Gambling)
    if not is_adult:
        for gd in KNOWN_GAMBLING_DOMAINS:
            if domain == gd or domain.endswith("." + gd) or gd in domain:
                is_gambling = True
                category = "GAMBLING_CASINO"
                matched_reasons.append(f"Site de jeux d'argent / paris en ligne répertorié ({gd})")
                break

        if not is_gambling:
            for gtld in GAMBLING_TLDS:
                if domain.endswith(gtld):
                    is_gambling = True
                    category = "GAMBLING_CASINO"
                    matched_reasons.append(f"Extension de domaine de jeux d'argent ({gtld})")
                    break

        if not is_gambling:
            tokens = re.split(r"[\.\-\_\/\?\=\&]", full_target)
            found_gkw = [kw for kw in GAMBLING_KEYWORDS if any(kw == t for t in tokens)]
            if found_gkw:
                is_gambling = True
                category = "GAMBLING_CASINO"
                matched_reasons.append(f"Présence d'indicateurs de paris ou casino en ligne : {', '.join(set(found_gkw[:2]))}")

    # 7. Détermination de la restriction selon la politique configurée
    effective_is_adult = is_adult if block_adult else False
    effective_is_gambling = is_gambling if block_gambling else False

    is_restricted = False
    action = "ALLOW"

    if enforcement == "ALLOW":
        is_restricted = False
        action = "ALLOW"
    elif effective_is_adult:
        is_restricted = True
        action = enforcement
    elif effective_is_gambling:
        is_restricted = True
        action = enforcement

    return {
        "url": raw_url,
        "is_restricted": is_restricted,
        "is_adult": effective_is_adult,
        "is_gambling": effective_is_gambling,
        "raw_is_adult": is_adult,
        "raw_is_gambling": is_gambling,
        "category": category if is_restricted else "CLEAN",
        "action": action,
        "reasons": matched_reasons if is_restricted else [],
        "enforcement_mode": enforcement,
        "redirect_to_block_page": settings.get("redirect_to_block_page", True),
        "school_shield_active": settings.get("school_shield_active", True)
    }
