from typing import Optional, List, Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/assistant", tags=["AI Cybersecurity Assistant"])

class ChatRequest(BaseModel):
    message: str
    context_type: Optional[str] = None # SQLi, XSS, Phishing, BruteForce, Ransomware, General
    context_data: Optional[Dict[str, Any]] = None
    lang: Optional[str] = "en"  # "en" or "fr" — controls reply language
    prompt: Optional[str] = None  # alias accepted from frontend

SECURITY_KNOWLEDGE_BASE = {
    "sqli": {
        "en": {
            "title": "Defensive Guide: Preventing SQL Injection (SQLi)",
            "explanation": "SQL Injection occurs when untrusted user input is directly concatenated into SQL queries without proper sanitization or parameterization, allowing attackers to read, modify, or delete backend database tables.",
            "recommendations": [
                "Use Prepared Statements / Parameterized Queries (ORMs like SQLAlchemy, Hibernate, or PDO).",
                "Enforce Input Validation & Sanitization using strict allow-lists.",
                "Apply Least Privilege Principles to database user accounts (disable DROP/ALTER rights for web users).",
                "Deploy a Web Application Firewall (WAF) to filter malicious query payloads (UNION, SELECT, OR 1=1)."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Prévenir l'Injection SQL (SQLi)",
            "explanation": "L'injection SQL se produit lorsque des entrées utilisateur non fiables sont directement concaténées dans des requêtes SQL sans sanitization ni paramétrage, permettant à des attaquants de lire, modifier ou supprimer des tables de la base de données.",
            "recommendations": [
                "Utiliser des requêtes préparées / paramétrées (ORM comme SQLAlchemy, Hibernate ou PDO).",
                "Appliquer la validation et la sanitization des entrées avec des listes d'autorisation strictes.",
                "Appliquer le principe du moindre privilège aux comptes de base de données (désactiver DROP/ALTER).",
                "Déployer un pare-feu applicatif web (WAF) pour filtrer les charges utiles malveillantes (UNION, SELECT, OR 1=1)."
            ]
        }
    },
    "xss": {
        "en": {
            "title": "Defensive Guide: Mitigating Cross-Site Scripting (XSS)",
            "explanation": "XSS occurs when malicious JavaScript scripts are injected into trusted web applications and executed inside victims' browsers, potentially hijacking session tokens and cookies.",
            "recommendations": [
                "Context-Aware Output Encoding (HTML entity encoding, JS escaping).",
                "Set Content-Security-Policy (CSP) headers to restrict script execution sources.",
                "Use HttpOnly and Secure flags on all session cookies to prevent cookie theft.",
                "Use modern frameworks (React/Vue) that sanitize outputs automatically by default."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Atténuer le Cross-Site Scripting (XSS)",
            "explanation": "Le XSS se produit lorsque des scripts JavaScript malveillants sont injectés dans des applications web de confiance et exécutés dans le navigateur des victimes, pouvant voler des jetons de session et des cookies.",
            "recommendations": [
                "Encodage de sortie contextuel (encodage des entités HTML, échappement JS).",
                "Définir des en-têtes Content-Security-Policy (CSP) pour restreindre les sources d'exécution des scripts.",
                "Utiliser les drapeaux HttpOnly et Secure sur tous les cookies de session.",
                "Utiliser des frameworks modernes (React/Vue) qui nettoient automatiquement les sorties."
            ]
        }
    },
    "brute_force": {
        "en": {
            "title": "Defensive Guide: Mitigating Brute Force Authentication",
            "explanation": "Brute force attacks involve automated bots systematically testing thousands of password combinations against login endpoints to compromise user accounts.",
            "recommendations": [
                "Implement Account Lockout & Rate Limiting (e.g., max 5 attempts per 15 min per IP).",
                "Enforce Multi-Factor Authentication (MFA / 2FA / TOTP) across all login portals.",
                "Require Strong Password Policies and check against breached credential lists.",
                "Deploy Cloudflare / CAPTCHA challenges after consecutive failed login attempts."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Atténuer les Attaques par Force Brute",
            "explanation": "Les attaques par force brute consistent en des robots automatisés testant systématiquement des milliers de combinaisons de mots de passe contre des points de terminaison de connexion.",
            "recommendations": [
                "Implémenter le verrouillage de compte et la limitation du débit (ex. : max 5 tentatives par 15 min par IP).",
                "Imposer l'authentification multi-facteur (MFA / 2FA / TOTP) sur tous les portails de connexion.",
                "Exiger des politiques de mots de passe forts et vérifier les listes de mots de passe compromis.",
                "Déployer des défis Cloudflare / CAPTCHA après des tentatives de connexion échouées consécutives."
            ]
        }
    },
    "phishing": {
        "en": {
            "title": "Defensive Guide: Countering Email & URL Phishing Campaigns",
            "explanation": "Phishing deceives targets into disclosing sensitive credentials or clicking malicious download links by spoofing authentic brands, urgent bank alerts, or package delivery notices.",
            "recommendations": [
                "Always inspect the domain name in URLs for typosquatting (e.g., paypa1.com vs paypal.com).",
                "Configure Email Authentication Protocols: SPF, DKIM, and DMARC (p=reject).",
                "Never submit passwords or MFA codes via links sent in unsolicited emails or SMS messages.",
                "Use CyberGuard's URL Scanner to verify suspicious links with Random Forest ML before opening."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Contrer les Campagnes de Phishing par Email et URL",
            "explanation": "Le phishing trompe les cibles pour qu'elles divulguent des identifiants sensibles ou cliquent sur des liens malveillants en se faisant passer pour des marques authentiques, des alertes bancaires urgentes ou des avis de livraison.",
            "recommendations": [
                "Inspectez toujours le nom de domaine dans les URL pour détecter le typosquatting (ex. : paypa1.com vs paypal.com).",
                "Configurez les protocoles d'authentification e-mail : SPF, DKIM et DMARC (p=reject).",
                "Ne soumettez jamais de mots de passe ou de codes MFA via des liens envoyés dans des e-mails ou SMS non sollicités.",
                "Utilisez le scanner URL de CyberGuard pour vérifier les liens suspects avec le ML Random Forest avant de les ouvrir."
            ]
        }
    },
    "ransomware": {
        "en": {
            "title": "Defensive Guide: Ransomware Detection & Prevention",
            "explanation": "Ransomware encrypts target systems and critical documents (.crypto, .enc, .locked) and demands payment in cryptocurrency. It often enters through phishing email attachments or unpatched remote vulnerabilities.",
            "recommendations": [
                "Maintain immutable offline backups (3-2-1 backup strategy) tested regularly.",
                "Block suspicious email attachments with executable or script extensions (.exe, .vbs, .js, .bat, .zip).",
                "Keep operating systems and software patched against known CVEs and Zero-Day exploits.",
                "Isolate compromised systems immediately from the network if ransomware encryption is suspected."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Détection et Prévention des Ransomwares",
            "explanation": "Les ransomwares chiffrent les systèmes cibles et les documents critiques (.crypto, .enc, .locked) et exigent un paiement en cryptomonnaie. Ils pénètrent souvent via des pièces jointes d'e-mails de phishing ou des vulnérabilités non corrigées.",
            "recommendations": [
                "Maintenez des sauvegardes hors ligne immuables (stratégie de sauvegarde 3-2-1) testées régulièrement.",
                "Bloquez les pièces jointes suspectes avec des extensions exécutables ou de script (.exe, .vbs, .js, .bat, .zip).",
                "Maintenez les systèmes d'exploitation et les logiciels corrigés contre les CVE connus et les exploits Zero-Day.",
                "Isolez immédiatement les systèmes compromis du réseau si un chiffrement par ransomware est suspecté."
            ]
        }
    },
    "report": {
        "en": {
            "title": "Defensive Guide: Generating Cryptographic Incident Reports",
            "explanation": "CyberGuard generates SHA-256 cryptographically signed forensic reports for every detected threat. This provides proof of integrity for law enforcement and security audits.",
            "recommendations": [
                "Run an analysis on the URL or message in the portal.",
                "Click 'Generate Incident Report' on the analysis result card.",
                "Copy your unique Report Code (e.g., RPT-2026-XXXXX) to verify on the Investigator Portal."
            ]
        },
        "fr": {
            "title": "Guide Défensif : Génération de Rapports d'Incidents Cryptographiques",
            "explanation": "CyberGuard génère des rapports forensiques signés cryptographiquement par SHA-256 pour chaque menace détectée. Cela fournit une preuve d'intégrité pour les forces de l'ordre et les audits de sécurité.",
            "recommendations": [
                "Lancez une analyse sur l'URL ou le message dans le portail.",
                "Cliquez sur 'Générer un rapport d'incident' sur la fiche de résultat d'analyse.",
                "Copiez votre code de rapport unique (ex. : RPT-2026-XXXXX) pour vérifier sur le portail investigateur."
            ]
        }
    }
}

import uuid
from datetime import datetime, timezone
import requests
import urllib3
from fastapi import Header, Depends
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import AuditLog, UtilisateurStandard, Enqueteur
from app.core.config import settings
from app.core.security import decode_access_token
from app.db.mongodb import mongo_collections

# Disable insecure request warnings when ssl verification is bypassed locally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_user_email_from_header(authorization: Any = None) -> str:
    if isinstance(authorization, str) and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        payload = decode_access_token(token)
        if payload:
            if "email" in payload and payload["email"]:
                return payload["email"]
            if "sub" in payload and payload["sub"]:
                return str(payload["sub"])
    return "alice.martin@example.com"


@router.post("/chat")
def security_assistant_chat(
    req: ChatRequest, 
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
):
    user_email = get_user_email_from_header(authorization)
    lang = (req.lang or "en").lower()
    if lang not in ("en", "fr"):
        lang = "en"

    ai_text = None
    recommendations = []

    # Use the actual message (support both `message` and `prompt` fields)
    user_message = req.message or req.prompt or ""

    # 1. Try Live OpenAI API if key provided
    if settings.OPENAI_API_KEY:
        try:
            system_prompt = (
                "You are CyberGuard AI, an expert cybersecurity defense assistant. "
                "Answer clearly and concisely for security analysts. "
                + ("Respond entirely in French." if lang == "fr" else "Respond in English.")
            )
            res = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_message}
                    ],
                    "max_tokens": 500
                },
                timeout=8,
                verify=False
            )
            if res.status_code == 200:
                data = res.json()
                ai_text = data["choices"][0]["message"]["content"]
                recommendations = (
                    ["Consultez les journaux de scans CyberGuard", "Vérifiez les empreintes SHA-256", "Exportez le rapport d'incident"]
                    if lang == "fr" else
                    ["Review CyberGuard threat scan logs", "Verify SHA-256 evidence digests", "Export incident investigation report"]
                )
        except Exception as e:
            print(f"[Warning] OpenAI API call failed: {e}. Using fallback knowledge base.")

    # 2. Try Live Gemini API if key provided
    if not ai_text and settings.GEMINI_API_KEY:
        try:
            lang_instruction = "Réponds entièrement en français." if lang == "fr" else "Respond in English."
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={settings.GEMINI_API_KEY}"
            res = requests.post(
                url,
                json={
                    "contents": [{
                        "parts": [{"text": f"You are CyberGuard AI Cybersecurity Assistant. {lang_instruction} Answer concisely for a security analyst:\n\nUser: {user_message}"}]
                    }]
                },
                timeout=8,
                verify=False
            )
            if res.status_code == 200:
                data = res.json()
                ai_text = data["candidates"][0]["content"]["parts"][0]["text"]
                recommendations = (
                    ["Consultez le registre de preuves d'incidents", "Vérifiez la somme de contrôle SHA-256", "Configurez les règles de pare-feu & WAF"]
                    if lang == "fr" else
                    ["Check incident evidence ledger", "Verify SHA-256 report checksum", "Configure firewall & WAF rules"]
                )
            else:
                print(f"[Warning] Gemini API status code {res.status_code}: {res.text}")
        except Exception as e:
            print(f"[Warning] Gemini API call failed: {e}. Using fallback knowledge base.")

    # 3. Intelligent Security Knowledge Base (Offline Fallback — bilingual)
    if not ai_text:
        query = user_message.lower()
        kb_key = None

        if "sql" in query or "sqli" in query or req.context_type == "SQLi":
            kb_key = "sqli"
        elif "xss" in query or "script" in query or req.context_type == "XSS":
            kb_key = "xss"
        elif "brute" in query or "login" in query or "password" in query or "mot de passe" in query or req.context_type == "BruteForce":
            kb_key = "brute_force"
        elif "ransom" in query or "encrypt" in query or "locked" in query or "chiffr" in query:
            kb_key = "ransomware"
        elif "report" in query or "evidence" in query or "sha" in query or "rapport" in query or "preuve" in query:
            kb_key = "report"
        elif "phish" in query or "email" in query or "url" in query or "sms" in query or "link" in query or "lien" in query or "hameçon" in query:
            kb_key = "phishing"

        if kb_key:
            kb = SECURITY_KNOWLEDGE_BASE[kb_key][lang]
            recs_bullets = "\n".join([f"- {r}" for r in kb["recommendations"]])
            context_label = "Contexte d'analyse" if lang == "fr" else "Analysis Context"
            actions_label = "Actions de durcissement défensif recommandées" if lang == "fr" else "Recommended Defensive Hardening Actions"
            ai_text = f"### {kb['title']}\n\n**{context_label}:** {kb['explanation']}\n\n**{actions_label}:**\n{recs_bullets}"
            recommendations = kb.get("recommendations", [])
        else:
            if lang == "fr":
                ai_text = (
                    "Bonjour ! Je suis votre **Assistant IA CyberGuard** 🛡️.\n\n"
                    "Je peux vous aider à :\n"
                    "- Analyser si un lien ou un e-mail est malveillant\n"
                    "- Expliquer comment se défendre contre l'Injection SQL, le XSS et les attaques par force brute\n"
                    "- Vous guider sur la protection contre les ransomwares et la mitigation des incidents\n"
                    "- Vous expliquer comment générer et vérifier des rapports forensiques cryptographiques."
                )
                recommendations = [
                    "Comment vérifier si un lien est une attaque de phishing ?",
                    "Que faire si j'ai reçu un SMS suspect ?",
                    "Comment prévenir les ransomwares et l'injection SQL ?",
                    "Comment CyberGuard génère-t-il des rapports de preuves SHA-256 ?"
                ]
            else:
                ai_text = (
                    "Hello! I am your **CyberGuard AI Cybersecurity Assistant** 🛡️.\n\n"
                    "I can help you:\n"
                    "- Analyze whether a specific link or email is malicious\n"
                    "- Explain how to defend against SQL Injection, XSS, and Brute Force attacks\n"
                    "- Guide you on Ransomware protection and incident mitigation\n"
                    "- Walk you through generating and verifying cryptographic forensic reports."
                )
                recommendations = [
                    "How do I check if a link is a phishing attack?",
                    "What should I do if I received a suspicious SMS?",
                    "How do I prevent Ransomware and SQL Injection?",
                    "How does CyberGuard generate SHA-256 evidence reports?"
                ]

    # 4. Save Conversation in MongoDB
    try:
        chat_doc = {
            "id": str(uuid.uuid4()),
            "user_email": user_email,
            "user_message": user_message,
            "ai_reply": ai_text,
            "recommendations": recommendations,
            "context_type": req.context_type or "General",
            "lang": lang,
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        mongo_collections.chat_messages.insert_one(chat_doc)
    except Exception as e:
        print(f"[MongoDB Chat Warning] Could not persist message: {e}")

    # 5. Log AI Consultation in AuditLog
    try:
        actor_name = "Alice Martin"
        if user_email:
            u_std = db.query(UtilisateurStandard).filter(UtilisateurStandard.email == user_email).first()
            if u_std:
                actor_name = f"{u_std.prenom} {u_std.nom}"
            else:
                u_enq = db.query(Enqueteur).filter(Enqueteur.email == user_email).first()
                if u_enq:
                    actor_name = f"{u_enq.prenom} {u_enq.nom}"

        clean_question = user_message.strip()
        if len(clean_question) > 60:
            clean_question = clean_question[:60] + "..."

        audit = AuditLog(
            actor=actor_name,
            action="CHAT_IA",
            target=f"Thème: {req.context_type or 'Conseils Défensifs'}",
            details=f"Question posée : \"{clean_question}\""
        )
        db.add(audit)
        db.commit()
    except Exception as e:
        print(f"[AuditLog Chat Error] {e}")

    return {
        "reply": ai_text,
        "recommendations": recommendations
    }

@router.get("/history")
def get_chat_history(authorization: Optional[str] = Header(None)):
    """Retrieve full AI conversation history for the authenticated user from MongoDB."""
    user_email = get_user_email_from_header(authorization)
    try:
        docs = list(mongo_collections.chat_messages.find({"user_email": user_email}).sort("created_at", 1).limit(100))
        formatted = []
        for d in docs:
            if "_id" in d:
                d["_id"] = str(d["_id"])
            formatted.append(d)
        return {
            "status": "success",
            "user_email": user_email,
            "total_messages": len(formatted),
            "history": formatted
        }
    except Exception as e:
        print(f"[MongoDB Chat History Error] {e}")
        return {
            "status": "error",
            "user_email": user_email,
            "total_messages": 0,
            "history": []
        }

@router.delete("/history")
def clear_chat_history(authorization: Optional[str] = Header(None)):
    """Clear all chat history for the authenticated user from MongoDB."""
    user_email = get_user_email_from_header(authorization)
    try:
        res = mongo_collections.chat_messages.delete_many({"user_email": user_email})
        return {
            "status": "success",
            "message": f"Historique de chat effacé ({res.deleted_count} messages supprimés)",
            "deleted_count": res.deleted_count
        }
    except Exception as e:
        return {"status": "error", "detail": str(e)}
