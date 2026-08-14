from typing import Dict, Any, List

def calculate_correlated_risk(
    ml_probability: float, # 0.0 to 1.0
    rule_score: float,     # 0.0 to 100.0
    vt_data: Dict[str, Any] = None,
    gsb_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Fuse Machine Learning, Heuristic Rules, and Threat Intel into a unified risk assessment.
    """
    # 1. Base ML Contribution (40% weight)
    ml_score = ml_probability * 100.0
    
    # 2. VirusTotal Contribution (30% weight)
    vt_score = 0.0
    if vt_data:
        positives = vt_data.get("positives", 0)
        if positives > 0:
            vt_score = min(100.0, (positives / 10.0) * 100.0)
            
    # 3. Google Safe Browsing (20% weight)
    gsb_score = 100.0 if (gsb_data and gsb_data.get("is_flagged")) else 0.0
    
    # 4. Rules & Heuristics (10% weight)
    
    # Combined weighted score
    final_score = (ml_score * 0.40) + (vt_score * 0.30) + (gsb_score * 0.20) + (rule_score * 0.10)
    final_score = min(100.0, max(0.0, round(final_score, 1)))

    # Determine Verdict & Risk Level
    if final_score >= 75.0:
        risk_level = "CRITICAL" if final_score >= 90.0 else "HIGH"
        verdict = "PHISHING / MALICIOUS"
    elif final_score >= 45.0:
        risk_level = "MEDIUM"
        verdict = "SUSPICIOUS"
    else:
        risk_level = "LOW"
        verdict = "LEGITIMATE / CLEAN"

    # Defensive Advice Contextual Generator
    advice_list = []
    if verdict != "LEGITIMATE / CLEAN":
        advice_list.append("Do NOT click or open any links or attachments contained within this content.")
        advice_list.append("Do NOT enter credentials, passwords, or personal financial details.")
        advice_list.append("Report this domain to your organization's SOC / Security Team immediately.")
        if gsb_data and gsb_data.get("is_flagged"):
            advice_list.append("Block domain at Firewall / DNS level via sinkhole rules.")
    else:
        advice_list.append("No immediate threat detected. Always verify sender identity for high-privilege requests.")

    return {
        "final_risk_score": final_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "ml_score": round(ml_score, 1),
        "vt_score": round(vt_score, 1),
        "gsb_flagged": gsb_data.get("is_flagged", False) if gsb_data else False,
        "defensive_advice": advice_list
    }
