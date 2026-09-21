from typing import Dict, Any, List


def calculate_correlated_risk(
    ml_probability: float,   # 0.0 to 1.0
    rule_score: float,       # 0.0 to 100.0
    vt_data: Dict[str, Any] = None,
    gsb_data: Dict[str, Any] = None,
    geoip_data: Dict[str, Any] = None,
    ml_features: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """
    Fuse Machine Learning (Primary), Heuristic Rules, and External Threat Intel
    into a unified risk assessment with full source transparency.

    Weighting strategy (adaptive):
      - All APIs live:       ML 60% + Rules 20% + APIs 20%
      - Some APIs ML-mode:   ML 72% + Rules 23% + APIs 5%
      - All APIs ML-mode:    ML 80% + Rules 20% + APIs  0%

    The analysis NEVER fails — ML runs autonomously when all APIs are unavailable.
    """
    ml_score   = ml_probability * 100.0
    rule_score = min(100.0, max(0.0, rule_score))

    # ── Determine API availability ─────────────────────────────────────────
    vt_live   = bool(vt_data  and vt_data.get("api_status")  == "live")
    gsb_live  = bool(gsb_data and gsb_data.get("api_status") == "live")
    geo_live  = bool(geoip_data and geoip_data.get("api_status") == "live")

    vt_ml     = bool(vt_data  and "ml" in (vt_data.get("api_status") or ""))
    gsb_ml    = bool(gsb_data and "ml" in (gsb_data.get("api_status") or ""))
    geo_ml    = bool(geoip_data and "ml" in (geoip_data.get("api_status") or ""))

    live_count = sum([vt_live, gsb_live, geo_live])
    ml_count   = sum([vt_ml, gsb_ml, geo_ml])
    api_failures = []

    # ── Extract scores from each intel source ─────────────────────────────
    vt_positives = vt_data.get("positives", 0) if vt_data else 0
    gsb_flagged  = bool(gsb_data and gsb_data.get("is_flagged"))
    geo_risk     = float(geoip_data.get("asn_risk_ml", 0.0)) if geoip_data else 0.0

    vt_score  = min(100.0, (vt_positives / 5.0) * 100.0) if vt_positives > 0 else 0.0
    gsb_score = 100.0 if gsb_flagged else 0.0
    geo_score = geo_risk * 60.0  # ASN risk contributes up to 60 risk points

    # ── ML-equivalent features supplement ─────────────────────────────────
    consensus_score = 0.0
    if ml_features:
        consensus_score = float(ml_features.get("multi_engine_consensus", 0.0)) * 100.0

    # ── Adaptive Weighting ─────────────────────────────────────────────────
    if live_count >= 2:
        # Multiple live APIs — high external corroboration
        api_composite = (vt_score * 0.40 + gsb_score * 0.40 + geo_score * 0.20)
        final_score = (ml_score * 0.60) + (rule_score * 0.20) + (api_composite * 0.20)
        mode = "FULL_INTEL"
    elif live_count == 1:
        # One live API — partial corroboration
        api_composite = max(vt_score if vt_live else 0.0,
                             gsb_score if gsb_live else 0.0,
                             geo_score if geo_live else 0.0)
        final_score = (ml_score * 0.68) + (rule_score * 0.22) + (api_composite * 0.10)
        mode = "PARTIAL_INTEL"
    else:
        # All APIs in ML autonomous mode — pure ML engine
        # Use multi_engine_consensus from ML features as tertiary signal
        final_score = (ml_score * 0.78) + (rule_score * 0.20) + (consensus_score * 0.02)
        mode = "AUTONOMOUS_ML"

    # ── Track API failures for transparency ───────────────────────────────
    if vt_ml:
        api_failures.append("VT_ML_FALLBACK")
    elif not vt_live and vt_data:
        api_failures.append("VT_UNAVAILABLE")

    if gsb_ml:
        api_failures.append("GSB_ML_FALLBACK")
    elif not gsb_live and gsb_data:
        api_failures.append("GSB_UNAVAILABLE")

    if geo_ml:
        api_failures.append("GEOIP_ML_FALLBACK")
    elif not geo_live and geoip_data:
        api_failures.append("GEOIP_UNAVAILABLE")

    # ── High-signal threshold overrides ───────────────────────────────────
    if ml_score >= 80.0 or (ml_score >= 60.0 and rule_score >= 35.0):
        final_score = max(final_score, 82.0)
    elif (ml_score < 25.0 and rule_score < 20.0
          and not gsb_flagged and vt_positives == 0 and geo_risk < 0.3):
        final_score = min(final_score, 18.0)

    # Consensus boost: if ML features and all signals agree on threat
    if (consensus_score > 70.0 and ml_score > 55.0):
        final_score = max(final_score, ml_score * 0.95)

    final_score = min(100.0, max(0.0, round(final_score, 1)))

    # ── Verdict & Risk Level ──────────────────────────────────────────────
    if final_score >= 65.0:
        risk_level = "CRITICAL" if final_score >= 85.0 else "HIGH"
        verdict    = "PHISHING / MALICIOUS"
    elif final_score >= 40.0:
        risk_level = "MEDIUM"
        verdict    = "SUSPICIOUS"
    else:
        risk_level = "LOW"
        verdict    = "LEGITIMATE / CLEAN"

    # ── Adaptive Defensive Advice ─────────────────────────────────────────
    advice_list: List[str] = []
    if verdict != "LEGITIMATE / CLEAN":
        advice_list.append("Ne cliquez sur aucun lien et n'ouvrez aucune pièce jointe associée.")
        advice_list.append("Ne saisissez jamais vos identifiants, mots de passe ou coordonnées bancaires.")
        advice_list.append("Signalez cette cible suspecte à l'équipe SOC de sécurité.")
        if gsb_flagged or vt_positives > 0:
            advice_list.append("Bloquez immédiatement le nom de domaine au niveau du pare-feu / DNS.")
        if geo_risk >= 0.5:
            advice_list.append("L'infrastructure d'hébergement provient d'un ASN à haut risque — bloquer l'IP au niveau réseau.")
        if mode == "AUTONOMOUS_ML":
            advice_list.append(
                "⚙️ Mode Autonome ML actif : Analyse complète effectuée par le moteur IA interne "
                "(services externes temporairement indisponibles)."
            )
    else:
        advice_list.append("Contenu vérifié et conforme. Aucune anomalie structurelle détectée.")
        if mode == "AUTONOMOUS_ML":
            advice_list.append("⚙️ Mode Autonome ML actif — les APIs externes étaient indisponibles, analyse ML seule.")

    # ── Intel sources used ────────────────────────────────────────────────
    intel_sources = []
    if ml_score > 0:
        intel_sources.append("ML_PRIMARY")
    if rule_score > 0:
        intel_sources.append("HEURISTIC_RULES")
    if vt_live:
        intel_sources.append("VIRUSTOTAL_LIVE")
    elif vt_ml:
        intel_sources.append("VIRUSTOTAL_ML_SIMULATION")
    if gsb_live:
        intel_sources.append("GSB_LIVE")
    elif gsb_ml:
        intel_sources.append("GSB_ML_SIMULATION")
    if geo_live:
        intel_sources.append("GEOIP_LIVE")
    elif geo_ml:
        intel_sources.append("GEOIP_ML_SIMULATION")

    return {
        "final_risk_score":    final_score,
        "risk_level":          risk_level,
        "verdict":             verdict,
        "ml_score":            round(ml_score, 1),
        "vt_score":            round(vt_score, 1),
        "gsb_flagged":         gsb_flagged,
        "geo_risk_score":      round(geo_score, 1),
        "consensus_score":     round(consensus_score, 1),
        "correlation_mode":    mode,
        "intel_sources_used":  intel_sources,
        "api_failures":        api_failures,
        "autonomous_mode":     mode == "AUTONOMOUS_ML",
        "defensive_advice":    advice_list,
    }
