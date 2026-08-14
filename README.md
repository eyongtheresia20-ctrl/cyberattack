# PhishGuard — Intelligent Cyber Threat & Phishing Intelligence Platform

PhishGuard is an academic web platform for detecting phishing (URL, Email, SMS), monitoring web security events (SQLi, XSS, Brute force, Path traversal), managing incident evidence, verifying report SHA-256 integrity, and offering AI security defense guidance.

## Technology Stack

- **Frontend**: React + Tailwind CSS + Lucide Icons (Vite)
- **Backend**: Python 3.10+ FastAPI
- **Machine Learning**: `scikit-learn` (Random Forest URL Classifier & TF-IDF NLP Text Classifier), `pandas`, `NumPy`
- **Database**: PostgreSQL (via SQLAlchemy) with automatic out-of-the-box SQLite fallback
- **Integrations**: VirusTotal API, Google Safe Browsing API, GeoIP & ASN Lookup

---

## Quick Start Instructions

### 1. Launch FastAPI Backend

```bash
cd backend
python -m uvicorn app.main:app --reload --port 8000
```

The API interactive docs will be live at: `http://localhost:8000/docs`

### 2. Launch React Frontend

```bash
cd frontend
npm run dev
```

Open `http://localhost:3000` in your browser.

---

## Features Showcase

1. **URL Phishing Threat Scanner**: Extracts 17 lexical/structural features (entropy, IP host presence, HTTPS, subdomain depth, suspicious keywords), executes Random Forest prediction, and checks VirusTotal & Google Safe Browsing APIs.
2. **SMS & Email NLP Analyzer**: TF-IDF vectorization and classification for credential harvesting, urgency pressure, and financial scam language.
3. **Web Security Log Collector & Cyber Attack Classifier**: Ingests HTTP server/WAF logs to classify SQL Injection (`UNION`, `DROP`), XSS (`<script>`), Path Traversal (`../../etc/passwd`), and Brute Force authentication spikes, enriched with GeoIP & ASN source metadata.
4. **Incidents & Evidence Ledger**: Cryptographically binds evidence items and generates formal investigator reports signed with SHA-256 checksums.
5. **Investigator Verification Portal**: Verifies report integrity by recomputing SHA-256 digests against immutable database records to prove untampered evidence.
6. **AI Defensive Assistant**: Contextual chatbot offering step-by-step remediation advice for detected vulnerabilities.
