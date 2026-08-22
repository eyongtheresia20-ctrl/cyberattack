from typing import Dict, Any, List

def calculate_correlated_risk(
    ml_probability: float, # 0.0 to 1.0
    rule_score: float,     # 0.0 to 100.0
    vt_data: Dict[str, Any] = None,
    gsb_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Fuse Machine Learning, Heuristic Rules, and Threat Intel into a unified risk assessment.
    Uses dynamic weight normalization so that zero external threat intel hits do not dilute high ML & heuristic signals.
    """
    ml_score = ml_probability * 100.0
    rule_score = min(100.0, max(0.0, rule_score))
    
    vt_positives = vt_data.get("positives", 0) if vt_data else 0
    gsb_flagged = bool(gsb_data and gsb_data.get("is_flagged"))

    vt_score = min(100.0, (vt_positives / 5.0) * 100.0) if vt_positives > 0 else 0.0
    gsb_score = 100.0 if gsb_flagged else 0.0

    # Dynamic Weight Allocation
    if vt_positives > 0 or gsb_flagged:
        # Threat Intel present & confirmed
        final_score = (ml_score * 0.35) + (vt_score * 0.35) + (gsb_score * 0.15) + (rule_score * 0.15)
    else:
        # Rely on Hybrid ML Engine & Heuristic Rule Signals (60% ML / 40% Rules)
        final_score = (ml_score * 0.60) + (rule_score * 0.40)

    # High Signal Threshold Override: If both ML > 85% and Rule score > 40%, ensure High Risk minimum
    if ml_score >= 85.0 and rule_score >= 40.0:
        final_score = max(final_score, 80.0)

    final_score = min(100.0, max(0.0, round(final_score, 1)))

    # Determine Verdict & Risk Level
    if final_score >= 70.0:
        risk_level = "CRITICAL" if final_score >= 88.0 else "HIGH"
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
        advice_list.append("Report this domain/message to your organization's SOC / Security Team immediately.")
        if gsb_flagged or vt_positives > 0:
            advice_list.append("Block domain at Firewall / DNS level via sinkhole rules.")
    else:
        advice_list.append("No immediate threat detected. Always verify sender identity for high-privilege requests.")

    return {
        "final_risk_score": final_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "ml_score": round(ml_score, 1),
        "vt_score": round(vt_score, 1),
        "gsb_flagged": gsb_flagged,
        "defensive_advice": advice_list
    }

