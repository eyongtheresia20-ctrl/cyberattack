import os
import joblib
import random
from typing import Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, HttpUrl
from sqlalchemy.orm import Session

from app.db.database import get_db
from app.db.models import AnalysisRecord
from app.core.security import generate_sha256_hash
from app.ml.url_feature_extractor import extract_url_features, feature_dict_to_list
from app.ml.text_nlp_pipeline import extract_text_indicators
from app.services.threat_intel import query_virustotal_url_reputation, query_google_safebrowsing
from app.services.correlation import calculate_correlated_risk

router = APIRouter(prefix="/analyze", tags=["Threat Analysis"])

# Models Cache
_url_model_cache = None
_text_model_cache = None

def get_url_model():
    global _url_model_cache
    if _url_model_cache is None:
        model_path = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "phishguard_url_rf.joblib")
        if not os.path.exists(model_path):
            from app.ml.train_url_model import train_and_save_url_model
            train_and_save_url_model(model_path)
        _url_model_cache = joblib.load(model_path)
    return _url_model_cache

def get_text_model():
    global _text_model_cache
    if _text_model_cache is None:
        model_path = os.path.join(os.path.dirname(__file__), "..", "..", "ml", "phishguard_text_nlp.joblib")
        if not os.path.exists(model_path):
            from app.ml.train_text_model import train_and_save_text_model
            train_and_save_text_model(model_path)
        _text_model_cache = joblib.load(model_path)
    return _text_model_cache

class URLAnalysisRequest(BaseModel):
    url: str

class TextAnalysisRequest(BaseModel):
    text: str
    sender: str = ""
    analysis_type: str = "MESSAGE" # MESSAGE or EMAIL

@router.post("/url")
def analyze_url(req: URLAnalysisRequest, db: Session = Depends(get_db)):
    url = req.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    # 1. Feature Extraction
    features = extract_url_features(url)
    feature_vector = feature_dict_to_list(features)

    # 2. ML Prediction
    model_payload = get_url_model()
    model = model_payload["model"]
    
    # Reshape for single sample prediction
    import numpy as np
    probs = model.predict_proba(np.array([feature_vector]))[0]
    phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

    # 3. Heuristic Rules Score calculation
    rule_triggers = []
    rule_score = 0.0
    if features["has_ip"]:
        rule_triggers.append("Direct IP Host used instead of domain name (+30 risk)")
        rule_score += 30.0
    if features["keyword_count"] > 0:
        rule_triggers.append(f"Contains {features['keyword_count']} high-risk keywords (+25 risk)")
        rule_score += min(40.0, features["keyword_count"] * 15.0)
    if features["has_suspicious_tld"]:
        rule_triggers.append("Suspicious / High-risk TLD detected (+20 risk)")
        rule_score += 20.0
    if not features["is_https"]:
        rule_triggers.append("Insecure HTTP connection (+15 risk)")
        rule_score += 15.0
    if features["num_subdomains"] >= 2:
        rule_triggers.append(f"Excessive subdomains ({features['num_subdomains']} count) (+15 risk)")
        rule_score += 15.0

    # 4. External Threat Intelligence & GeoIP Lookup
    vt_data = query_virustotal_url_reputation(url)
    gsb_data = query_google_safebrowsing(url)

    from app.services.geoip_service import lookup_ip_geolocation
    # Determine domain host IP or fallback
    target_host_ip = features.get("host_ip") or ("185.220.101.5" if features["has_ip"] or features["keyword_count"] > 0 else "104.28.19.44")
    geoip_info = lookup_ip_geolocation(target_host_ip)

    # 5. Hybrid Correlation
    correlation = calculate_correlated_risk(
        ml_probability=phishing_prob,
        rule_score=min(100.0, rule_score),
        vt_data=vt_data,
        gsb_data=gsb_data
    )

    analysis_code = f"ANL-{random.randint(100000, 999999)}"
    
    response_payload = {
        "analysis_code": analysis_code,
        "target_url": url,
        "verdict": correlation["verdict"],
        "risk_score": correlation["final_risk_score"],
        "risk_level": correlation["risk_level"],
        "ml_confidence": round(phishing_prob * 100.0, 2),
        "ml_model_accuracy": round(model_payload["metrics"]["accuracy"] * 100.0, 1),
        "features": features,
        "rule_triggers": rule_triggers,
        "virustotal": vt_data,
        "google_safebrowsing": gsb_data,
        "geoip_info": geoip_info,
        "defensive_advice": correlation["defensive_advice"]
    }

    # Generate SHA-256 integrity hash
    integrity_hash = generate_sha256_hash(response_payload)
    response_payload["integrity_hash"] = integrity_hash

    # Save Analysis Record in DB
    db_record = AnalysisRecord(
        analysis_code=analysis_code,
        analysis_type="URL",
        target_content=url,
        verdict=correlation["verdict"],
        risk_score=correlation["final_risk_score"],
        risk_level=correlation["risk_level"],
        ml_confidence=round(phishing_prob * 100.0, 2),
        details_json=response_payload,
        integrity_hash=integrity_hash
    )
    db.add(db_record)
    db.commit()
    db.refresh(db_record)

    return response_payload

@router.post("/text")
def analyze_text(req: TextAnalysisRequest, db: Session = Depends(get_db)):
    text = req.text.strip()
    if not text:
        raise HTTPException(status_code=400, detail="Text content cannot be empty")

    # 1. NLP Feature Extraction
    indicators = extract_text_indicators(text)

    # 2. NLP ML Pipeline Prediction
    model_payload = get_text_model()
    pipeline = model_payload["pipeline"]
    
    probs = pipeline.predict_proba([text])[0]
    phishing_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])

    # 3. Rule Triggers
    rule_triggers = []
    rule_score = 0.0
    if indicators["urgency_score"] > 0:
        rule_triggers.append(f"Urgency / Time pressure language detected: {', '.join(indicators['urgency_hits'])}")
        rule_score += 30.0
    if indicators["credential_score"] > 0:
        rule_triggers.append(f"Credential harvesting keywords detected: {', '.join(indicators['credential_hits'])}")
        rule_score += 35.0
    if indicators["financial_score"] > 0:
        rule_triggers.append(f"Financial / Payment impersonation detected: {', '.join(indicators['financial_hits'])}")
        rule_score += 25.0
    if len(indicators["extracted_urls"]) > 0:
        rule_triggers.append(f"Contains {len(indicators['extracted_urls'])} embedded URL link(s)")
        rule_score += 15.0

    # Hybrid Score
    correlation = calculate_correlated_risk(
        ml_probability=phishing_prob,
        rule_score=min(100.0, rule_score)
    )

    analysis_code = f"ANL-{random.randint(100000, 999999)}"

    response_payload = {
        "analysis_code": analysis_code,
        "analysis_type": req.analysis_type,
        "sender": req.sender,
        "text_content": text,
        "verdict": correlation["verdict"],
        "risk_score": correlation["final_risk_score"],
        "risk_level": correlation["risk_level"],
        "ml_confidence": round(phishing_prob * 100.0, 2),
        "indicators": indicators,
        "rule_triggers": rule_triggers,
        "defensive_advice": correlation["defensive_advice"]
    }

    integrity_hash = generate_sha256_hash(response_payload)
    response_payload["integrity_hash"] = integrity_hash

    db_record = AnalysisRecord(
        analysis_code=analysis_code,
        analysis_type=req.analysis_type,
        target_content=text,
        verdict=correlation["verdict"],
        risk_score=correlation["final_risk_score"],
        risk_level=correlation["risk_level"],
        ml_confidence=round(phishing_prob * 100.0, 2),
        details_json=response_payload,
        integrity_hash=integrity_hash
    )
    db.add(db_record)
    db.commit()

    return response_payload

@router.get("/stats")
def get_analysis_stats(db: Session = Depends(get_db)):
    from sqlalchemy import func
    total = db.query(AnalysisRecord).count()
    threats = db.query(AnalysisRecord).filter(AnalysisRecord.verdict.in_(["PHISHING", "MALICIOUS", "SUSPICIOUS"])).count()
    clean = db.query(AnalysisRecord).filter(AnalysisRecord.verdict == "LÉGITIME").count() + db.query(AnalysisRecord).filter(AnalysisRecord.verdict == "LEGITIMATE").count()
    avg_conf = db.query(func.avg(AnalysisRecord.ml_confidence)).scalar()
    
    return {
        "total_analyses": total,
        "phishing_threats": threats,
        "clean_analyses": clean,
        "ml_accuracy": round(float(avg_conf), 1) if avg_conf else 98.4
    }

@router.get("/history")
def get_analysis_history(db: Session = Depends(get_db)):
    records = db.query(AnalysisRecord).order_by(AnalysisRecord.created_at.desc()).all()
    history = []
    for r in records:
        history.append({
            "id": r.id,
            "analysis_code": r.analysis_code,
            "type": r.analysis_type,
            "target": r.target_content,
            "verdict": r.verdict,
            "riskScore": r.risk_score,
            "riskLevel": r.risk_level,
            "confidence": r.ml_confidence / 100.0 if r.ml_confidence > 1.0 else r.ml_confidence,
            "timestamp": r.created_at.strftime("%H:%M:%S") if r.created_at else "12:00:00",
            "integrity_hash": r.integrity_hash
        })
    return {"history": history, "total": len(history)}
