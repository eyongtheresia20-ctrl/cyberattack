"""
Module de Sécurité Cryptographique et Authentification — PhishGuard Core
========================================================================
Ce module fournit les primitives cryptographiques fondamentales de la plateforme :
  1. Hachage et vérification des mots de passe utilisateurs via PBKDF2-HMAC-SHA256 (100 000 itérations).
  2. Création et validation sécurisée de jetons d'accès JWT (HS256) avec encodage Base64URL et protection contre les attaques de temporisation (hmac.compare_digest).
  3. Scellé d'intégrité SHA-256 pour les rapports d'incidents, preuves judiciaires et analyses de sécurité.
"""

import hashlib
import json
import base64
import hmac
from datetime import datetime, timezone, timedelta
from app.core.config import settings

# Clé secrète de signature HMAC pour les JWT (chargée depuis les variables d'environnement)
SECRET_KEY = settings.SECRET_KEY if hasattr(settings, 'SECRET_KEY') and settings.SECRET_KEY else "phishguard_super_secret_jwt_key_2026"


def base64url_encode(data: bytes) -> str:
    """
    Encode des octets au format Base64URL selon la norme RFC 7515 (JWT).
    Remplace '+' par '-', '/' par '_' et supprime les caractères de remplissage '='.
    """
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data_str: str) -> bytes:
    """
    Décode une chaîne Base64URL en restaurant le remplissage '=' requis.
    """
    padding = '=' * (4 - (len(data_str) % 4))
    return base64.urlsafe_b64decode(data_str + padding)


def generate_sha256_hash(data: str | bytes | dict) -> str:
    """
    Génère une empreinte numérique d'intégrité SHA-256 (scellé judiciaire).
    
    Utilisé pour sceller les rapports d'analyse et garantir l'inviolabilité
    des preuves transmises aux enquêteurs du SOC.
    
    Paramètres :
      data : Chaîne de caractères, octets bruts ou dictionnaire JSON.
      
    Retour :
      str : Empreinte hexadécimale de 64 caractères (SHA-256).
    """
    if isinstance(data, dict):
        # Tri déterministe des clés JSON pour garantir la reproductibilité du hachage
        data_str = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(data_str.encode('utf-8')).hexdigest()
    elif isinstance(data, str):
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    elif isinstance(data, bytes):
        return hashlib.sha256(data).hexdigest()
    raise ValueError("Format de données non supporté pour le hachage cryptographique")


def format_timestamp(dt: datetime = None) -> str:
    """
    Génère un horodatage ISO-8601 standardisé en temps universel coordonné (UTC).
    """
    if dt is None:
        dt = datetime.now(timezone.utc)
    return dt.isoformat()


def hash_password(password: str) -> str:
    """
    Hache le mot de passe utilisateur avec dérivation PBKDF2-HMAC-SHA256.
    
    Paramètres de robustesse :
      - Sel fixe d'application
      - 100 000 itérations de calcul pour résister aux attaques par force brute GPU
    """
    salt = "phishguard_secure_salt_2026".encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key.hex()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Vérifie la conformité d'un mot de passe en clair par rapport à son empreinte stockée.
    """
    return hash_password(plain_password) == hashed_password


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Génère un jeton d'accès JWT signé cryptographiquement (HS256).
    
    Structure du jeton : <En-tête Base64URL>.<Charge utile Base64URL>.<Signature HMAC-SHA256>
    
    Paramètres :
      data (dict) : Réclamations (claims) du jeton (ex: sub, email, role).
      expires_delta (timedelta) : Durée de validité optionnelle (par défaut 24h).
      
    Retour :
      str : Chaîne JWT compacte prête à être transmise dans l'en-tête Authorization Bearer.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(hours=24)
    to_encode.update({"exp": int(expire.timestamp())})
    
    # 1. En-tête JWT (Algorithme HMAC-SHA256)
    header = {"alg": "HS256", "typ": "JWT"}
    header_bytes = json.dumps(header, separators=(',', ':')).encode('utf-8')
    payload_bytes = json.dumps(to_encode, separators=(',', ':')).encode('utf-8')
    
    encoded_header = base64url_encode(header_bytes)
    encoded_payload = base64url_encode(payload_bytes)
    
    # 2. Signature HMAC-SHA256
    signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
    signature = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
    encoded_signature = base64url_encode(signature)
    
    return f"{encoded_header}.{encoded_payload}.{encoded_signature}"


def decode_access_token(token: str) -> dict | None:
    """
    Décode, vérifie la signature cryptographique et contrôle l'expiration d'un JWT.
    
    Sécurité :
      - Utilise hmac.compare_digest pour prévenir les attaques temporelles (timing attacks).
      - Vérifie la date d'expiration "exp" par rapport à l'heure UTC courante.
      
    Retour :
      dict : Charge utile décodée si valide, None en cas d'altération ou d'expiration.
    """
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        encoded_header, encoded_payload, encoded_signature = parts
        
        # Vérification d'intégrité de la signature
        signing_input = f"{encoded_header}.{encoded_payload}".encode('utf-8')
        expected_sig = hmac.new(SECRET_KEY.encode('utf-8'), signing_input, hashlib.sha256).digest()
        actual_sig = base64url_decode(encoded_signature)
        
        if not hmac.compare_digest(expected_sig, actual_sig):
            return None
            
        # Extraction et contrôle d'expiration de la charge utile
        payload_bytes = base64url_decode(encoded_payload)
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        exp = payload.get("exp")
        if exp and datetime.now(timezone.utc).timestamp() > exp:
            return None
            
        return payload
    except Exception:
        return None
