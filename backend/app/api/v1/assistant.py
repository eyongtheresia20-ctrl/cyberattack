from typing import Optional, List, Dict, Any
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/assistant", tags=["AI Cybersecurity Assistant"])

class ChatRequest(BaseModel):
    message: str
    context_type: Optional[str] = None # SQLi, XSS, Phishing, BruteForce, Ransomware, General
    context_data: Optional[Dict[str, Any]] = None

SECURITY_KNOWLEDGE_BASE = {
    "sqli": {
        "title": "Defensive Guide: Preventing SQL Injection (SQLi)",
        "explanation": "SQL Injection occurs when untrusted user input is directly concatenated into SQL queries without proper sanitization or parameterization, allowing attackers to read, modify, or delete backend database tables.",
        "recommendations": [
            "Use Prepared Statements / Parameterized Queries (ORMs like SQLAlchemy, Hibernate, or PDO).",
            "Enforce Input Validation & Sanitization using strict allow-lists.",
            "Apply Least Privilege Principles to database user accounts (disable DROP/ALTER rights for web users).",
            "Deploy a Web Application Firewall (WAF) to filter malicious query payloads (UNION, SELECT, OR 1=1)."
        ]
    },
    "xss": {
        "title": "Defensive Guide: Mitigating Cross-Site Scripting (XSS)",
        "explanation": "XSS occurs when malicious JavaScript scripts are injected into trusted web applications and executed inside victims' browsers, potentially hijacking session tokens and cookies.",
        "recommendations": [
            "Context-Aware Output Encoding (HTML entity encoding, JS escaping).",
            "Set Content-Security-Policy (CSP) headers to restrict script execution sources.",
            "Use HttpOnly and Secure flags on all session cookies to prevent cookie theft.",
            "Use modern frameworks (React/Vue) that sanitize outputs automatically by default."
        ]
    },
    "brute_force": {
        "title": "Defensive Guide: Mitigating Brute Force Authentication",
        "explanation": "Brute force attacks involve automated bots systematically testing thousands of password combinations against login endpoints to compromise user accounts.",
        "recommendations": [
            "Implement Account Lockout & Rate Limiting (e.g., max 5 attempts per 15 min per IP).",
            "Enforce Multi-Factor Authentication (MFA / 2FA / TOTP) across all login portals.",
            "Require Strong Password Policies and check against breached credential lists.",
            "Deploy Cloudflare / CAPTCHA challenges after consecutive failed login attempts."
        ]
    },
    "phishing": {
        "title": "Defensive Guide: Countering Email & URL Phishing Campaigns",
        "explanation": "Phishing deceives targets into disclosing sensitive credentials or clicking malicious download links by spoofing authentic brands, urgent bank alerts, or package delivery notices.",
        "recommendations": [
            "Always inspect the domain name in URLs for typosquatting (e.g., paypa1.com vs paypal.com).",
            "Configure Email Authentication Protocols: SPF, DKIM, and DMARC (p=reject).",
            "Never submit passwords or MFA codes via links sent in unsolicited emails or SMS messages.",
            "Use PhishGuard's URL Scanner to verify suspicious links with Random Forest ML before opening."
        ]
    },
    "ransomware": {
        "title": "Defensive Guide: Ransomware Detection & Prevention",
        "explanation": "Ransomware encrypts target systems and critical documents (.crypto, .enc, .locked) and demands payment in cryptocurrency. It often enters through phishing email attachments or unpatched remote vulnerabilities.",
        "recommendations": [
            "Maintain immutable offline backups (3-2-1 backup strategy) tested regularly.",
            "Block suspicious email attachments with executable or script extensions (.exe, .vbs, .js, .bat, .zip).",
            "Keep operating systems and software patched against known CVEs and Zero-Day exploits.",
            "Isolate compromised systems immediately from the network if ransomware encryption is suspected."
        ]
    },
    "report": {
        "title": "Defensive Guide: Generating Cryptographic Incident Reports",
        "explanation": "PhishGuard generates SHA-256 cryptographically signed forensic reports for every detected threat. This provides proof of integrity for law enforcement and security audits.",
        "recommendations": [
            "Run an analysis on the URL or message in the portal.",
            "Click 'Generate Incident Report' on the analysis result card.",
            "Copy your unique Report Code (e.g., RPT-2026-XXXXX) to verify on the Investigator Portal."
        ]
    }
}

import uuid
from datetime import datetime, timezone
import requests
import urllib3
from fastapi import Header
from app.core.config import settings
from app.core.security import decode_access_token
from app.db.mongodb import mongo_collections

# Disable insecure request warnings when ssl verification is bypassed locally
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def get_user_email_from_header(authorization: Any = None) -> str:
    if isinstance(authorization, str) and authorization.startswith("Bearer "):
        token = authorization.split(" ")[1]
        payload = decode_access_token(token)
        if payload and "sub" in payload:
            return payload["sub"]
    return "alice.martin@example.com"


@router.post("/chat")
def security_assistant_chat(req: ChatRequest, authorization: Optional[str] = Header(None)):
    user_email = get_user_email_from_header(authorization)
    ai_text = None
    recommendations = []

    # 1. Try Live OpenAI API if key provided
    if settings.OPENAI_API_KEY:
        try:
            res = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "gpt-3.5-turbo",
                    "messages": [
                        {"role": "system", "content": "You are PhishGuard AI, an expert cybersecurity defense assistant specializing in phishing, threat intelligence, vulnerability mitigation, and incident analysis."},
                        {"role": "user", "content": req.message}
                    ],
                    "max_tokens": 500
                },
                timeout=8,
                verify=False
            )
            if res.status_code == 200:
                data = res.json()
                ai_text = data["choices"][0]["message"]["content"]
                recommendations = [
                    "Review PhishGuard threat scan logs",
                    "Verify SHA-256 evidence digests",
                    "Export incident investigation report"
                ]
        except Exception as e:
            print(f"[Warning] OpenAI API call failed: {e}. Using fallback knowledge base.")

    # 2. Try Live Gemini API if key provided
    if not ai_text and settings.GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent?key={settings.GEMINI_API_KEY}"
            res = requests.post(
                url,
                json={
                    "contents": [{
                        "parts": [{"text": f"You are PhishGuard AI Cybersecurity Assistant. Answer concisely for a security analyst:\n\nUser: {req.message}"}]
                    }]
                },
                timeout=8,
                verify=False
            )
            if res.status_code == 200:
                data = res.json()
                ai_text = data["candidates"][0]["content"]["parts"][0]["text"]
                recommendations = [
                    "Check incident evidence ledger",
                    "Verify SHA-256 report checksum",
                    "Configure firewall & WAF rules"
                ]
            else:
                print(f"[Warning] Gemini API status code {res.status_code}: {res.text}")
        except Exception as e:
            print(f"[Warning] Gemini API call failed: {e}. Using fallback knowledge base.")

    # 3. Intelligent Security Knowledge Base (Offline Fallback)
    if not ai_text:
        query = req.message.lower()
        
        if "sql" in query or "sqli" in query or req.context_type == "SQLi":
            kb = SECURITY_KNOWLEDGE_BASE["sqli"]
        elif "xss" in query or "script" in query or req.context_type == "XSS":
            kb = SECURITY_KNOWLEDGE_BASE["xss"]
        elif "brute" in query or "login" in query or "password" in query or req.context_type == "BruteForce":
            kb = SECURITY_KNOWLEDGE_BASE["brute_force"]
        elif "ransom" in query or "encrypt" in query or "locked" in query:
            kb = SECURITY_KNOWLEDGE_BASE["ransomware"]
        elif "report" in query or "evidence" in query or "sha" in query:
            kb = SECURITY_KNOWLEDGE_BASE["report"]
        elif "phish" in query or "email" in query or "url" in query or "sms" in query or "link" in query:
            kb = SECURITY_KNOWLEDGE_BASE["phishing"]
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
                "How does PhishGuard generate SHA-256 evidence reports?"
            ]

        if not ai_text and kb:
            recs_bullets = "\n".join([f"- {r}" for r in kb["recommendations"]])
            ai_text = f"### {kb['title']}\n\n**Analysis Context:** {kb['explanation']}\n\n**Recommended Defensive Hardening Actions:**\n{recs_bullets}"
            recommendations = kb.get("recommendations", [
                "How do I verify a suspicious domain using PhishGuard?",
                "What evidence is included in an Incident Report?",
                "How does PhishGuard verify SHA-256 report integrity?"
            ])

    # 4. Save Conversation in MongoDB
    try:
        chat_doc = {
            "id": str(uuid.uuid4()),
            "user_email": user_email,
            "user_message": req.message,
            "ai_reply": ai_text,
            "recommendations": recommendations,
            "context_type": req.context_type or "General",
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        mongo_collections.chat_messages.insert_one(chat_doc)
    except Exception as e:
        print(f"[MongoDB Chat Warning] Could not persist message: {e}")

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



