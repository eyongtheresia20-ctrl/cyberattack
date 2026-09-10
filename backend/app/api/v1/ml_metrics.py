"""
PhishGuard ML Metrics API
=========================
Endpoint: GET /api/v1/ml/metrics
Returns real performance metrics for all trained ML models:
  - Random Forest, Gradient Boosting, MLP (URL analysis)
  - TF-IDF + Random Forest (Text/NLP analysis)
Includes: Accuracy, Precision, Recall, F1, 5-Fold CV scores, Confusion Matrix
"""

import os
import joblib
from fastapi import APIRouter
from typing import Dict, Any

router = APIRouter(prefix="/ml", tags=["ML Model Metrics"])

ML_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "ml")

URL_MODELS = {
    "rf":  ("phishguard_url_rf.joblib",  "Random Forest Classifier"),
    "gbm": ("phishguard_url_gbm.joblib", "Gradient Boosting Machine"),
    "mlp": ("phishguard_url_mlp.joblib", "Multi-Layer Perceptron (Neural Network)"),
}
TEXT_MODEL_FILE = "phishguard_text_nlp.joblib"

# Algorithm justification — stored here so the frontend can display it
ALGORITHM_RATIONALE = {
    "rf": {
        "name": "Random Forest Classifier",
        "why_chosen": "Robuste aux valeurs aberrantes, insensible à la normalisation, fournit l'importance des features (explicabilité). Très efficace sur des features numériques hétérogènes comme les 17 features URL.",
        "why_not_svm": "SVM nécessite une normalisation stricte et est coûteux en temps d'entraînement sur des datasets larges. RF est plus rapide et interprétable.",
        "complexity": "O(n × m × log n) entraînement | O(m × log n) prédiction",
        "color": "#3b82f6"
    },
    "gbm": {
        "name": "Gradient Boosting Machine (GBM)",
        "why_chosen": "Boosting séquentiel : chaque arbre corrige les erreurs du précédent. Généralement plus précis que RF sur des données structurées. Contrôle fin via learning_rate.",
        "why_not_logistic": "La Régression Logistique suppose une relation linéaire entre features et label — invalide pour la détection de phishing qui est hautement non-linéaire.",
        "complexity": "O(n × d × n_estimators) entraînement | O(n_estimators × d) prédiction",
        "color": "#8b5cf6"
    },
    "mlp": {
        "name": "Multi-Layer Perceptron (Réseau de Neurones)",
        "why_chosen": "Capture des relations non-linéaires complexes entre features. Architecture 64→32→16 neurones. Bénéficie du StandardScaler pour une convergence rapide.",
        "why_not_naive_bayes": "Naïve Bayes suppose l'indépendance conditionnelle des features — fausse pour les URLs (longueur et entropie sont corrélées). MLP n'a pas cette contrainte.",
        "complexity": "O(epochs × n × layers) entraînement | O(layers) prédiction",
        "color": "#ec4899"
    },
    "nlp": {
        "name": "TF-IDF + Random Forest (NLP Pipeline)",
        "why_chosen": "TF-IDF convertit le texte en vecteurs numériques pondérés par fréquence inverse. Les bigrammes capturent des patterns comme 'verify account', 'click here'. RF classifie ensuite ces vecteurs.",
        "why_not_bert": "BERT requiert des GPU et plusieurs heures d'entraînement pour fine-tuning. TF-IDF+RF atteint >90% d'accuracy en quelques secondes sur ce dataset.",
        "complexity": "TF-IDF : O(n × vocab) | RF : O(n × log n × features)",
        "color": "#f59e0b"
    }
}


def _load_model_payload(filepath: str) -> Dict[str, Any]:
    """Load a joblib model payload safely."""
    try:
        return joblib.load(filepath)
    except Exception as e:
        return {"error": str(e)}


def _extract_metrics(payload: Dict[str, Any], model_key: str) -> Dict[str, Any]:
    """Extract a clean metrics dict from a model payload."""
    if "error" in payload:
        return {"status": "error", "detail": payload["error"]}

    base_metrics = payload.get("metrics", {})
    cv = payload.get("cross_validation", {})
    cm = payload.get("confusion_matrix", {})
    rationale = ALGORITHM_RATIONALE.get(model_key, {})

    return {
        "status": "loaded",
        "model_name": payload.get("model_name", "Unknown"),
        "dataset_size": payload.get("dataset_size", "N/A"),
        "feature_names": payload.get("feature_names", []),

        # Hold-out Test Metrics
        "metrics": {
            "accuracy":  base_metrics.get("accuracy", 0),
            "precision": base_metrics.get("precision", 0),
            "recall":    base_metrics.get("recall", 0),
            "f1_score":  base_metrics.get("f1_score", 0),
        },

        # 5-Fold Cross-Validation Metrics
        "cross_validation": {
            "n_folds":           cv.get("n_folds", 5),
            "cv_accuracy_mean":  cv.get("cv_accuracy_mean", 0),
            "cv_accuracy_std":   cv.get("cv_accuracy_std", 0),
            "cv_accuracy_scores": cv.get("cv_accuracy_scores", []),
            "cv_f1_mean":        cv.get("cv_f1_mean", 0),
            "cv_f1_std":         cv.get("cv_f1_std", 0),
            "cv_precision_mean": cv.get("cv_precision_mean", 0),
            "cv_recall_mean":    cv.get("cv_recall_mean", 0),
        },

        # Confusion Matrix
        "confusion_matrix": {
            "true_positive":  cm.get("true_positive", 0),
            "true_negative":  cm.get("true_negative", 0),
            "false_positive": cm.get("false_positive", 0),
            "false_negative": cm.get("false_negative", 0),
        },

        # Algorithm Justification (for academic report)
        "rationale": {
            "why_chosen":    rationale.get("why_chosen", ""),
            "comparison":    rationale.get("why_not_svm", rationale.get("why_not_logistic",
                             rationale.get("why_not_naive_bayes", rationale.get("why_not_bert", "")))),
            "complexity":    rationale.get("complexity", ""),
            "color":         rationale.get("color", "#6b7280"),
        }
    }


@router.get("/metrics")
def get_all_model_metrics() -> Dict[str, Any]:
    """
    Return performance metrics for all PhishGuard ML/NLP models.
    Includes hold-out test scores, 5-fold cross-validation, and confusion matrices.
    """
    result = {
        "url_models": {},
        "text_model": {},
        "ensemble_summary": {},
        "models_trained": False,
    }

    # ── URL Models (RF, GBM, MLP) ─────────────────────────────────
    accuracies = []
    f1_scores = []
    for key, (filename, _) in URL_MODELS.items():
        filepath = os.path.join(ML_DIR, filename)
        payload = _load_model_payload(filepath)
        metrics = _extract_metrics(payload, key)
        result["url_models"][key] = metrics
        if metrics.get("status") == "loaded":
            accuracies.append(metrics["metrics"]["accuracy"])
            f1_scores.append(metrics["metrics"]["f1_score"])

    # ── Text NLP Model ────────────────────────────────────────────
    text_filepath = os.path.join(ML_DIR, TEXT_MODEL_FILE)
    text_payload = _load_model_payload(text_filepath)
    result["text_model"] = _extract_metrics(text_payload, "nlp")

    # ── Ensemble Summary ──────────────────────────────────────────
    if accuracies:
        result["models_trained"] = True
        result["ensemble_summary"] = {
            "total_url_models": len(accuracies),
            "avg_accuracy":  round(sum(accuracies) / len(accuracies), 4),
            "avg_f1_score":  round(sum(f1_scores)  / len(f1_scores),  4),
            "best_model_accuracy": round(max(accuracies), 4),
            "model_names": [URL_MODELS[k][1] for k in URL_MODELS],
        }

    return result


@router.get("/metrics/{model_key}")
def get_single_model_metrics(model_key: str) -> Dict[str, Any]:
    """
    Return metrics for a single model.
    model_key: 'rf' | 'gbm' | 'mlp' | 'nlp'
    """
    if model_key == "nlp":
        filepath = os.path.join(ML_DIR, TEXT_MODEL_FILE)
        payload = _load_model_payload(filepath)
        return _extract_metrics(payload, "nlp")

    if model_key not in URL_MODELS:
        return {"error": f"Unknown model key '{model_key}'. Valid: rf, gbm, mlp, nlp"}

    filename, _ = URL_MODELS[model_key]
    filepath = os.path.join(ML_DIR, filename)
    payload = _load_model_payload(filepath)
    return _extract_metrics(payload, model_key)
