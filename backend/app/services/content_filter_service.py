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
    "custom_whitelist": []
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


def check_url_content_policy(raw_url: str) -> Dict[str, Any]:
    """
    Inspecte une URL contre les politiques de filtrage de contenu adulte et de jeux d'argent.
    Renvoie le verdict, la catégorie, les raisons et l'action à appliquer (BLOCK / WARN / ALLOW).
    """
    settings = load_policy_settings()
    block_adult = settings.get("block_adult_content", True)
    block_gambling = settings.get("block_gambling", True)
    enforcement = settings.get("enforcement_mode", "BLOCK")

    url = (raw_url or "").strip().lower()
    if not url or not settings.get("school_shield_active", True):
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
        if b.strip() and b.lower() in domain:
            is_adult = True
            category = "CUSTOM_BLACKLIST"
            matched_reasons.append(f"Domaine explicitement bloqué par l'administrateur ({b})")
            break

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
    is_restricted = False
    action = "ALLOW"

    if is_adult and block_adult:
        is_restricted = True
        action = enforcement
    elif is_gambling and block_gambling:
        is_restricted = True
        action = enforcement
    elif (is_adult or is_gambling) and enforcement == "WARN":
        is_restricted = True
        action = "WARN"

    return {
        "url": raw_url,
        "is_restricted": is_restricted,
        "is_adult": is_adult,
        "is_gambling": is_gambling,
        "category": category,
        "action": action,
        "reasons": matched_reasons,
        "enforcement_mode": enforcement,
        "redirect_to_block_page": settings.get("redirect_to_block_page", True),
        "school_shield_active": settings.get("school_shield_active", True)
    }
