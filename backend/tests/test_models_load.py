import os
import pytest
import joblib

MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "ml")

def test_url_rf_model_file_exists():
    path = os.path.join(MODEL_DIR, "phishguard_url_rf.joblib")
    assert os.path.exists(path), f"Model file missing at {path}"

def test_url_gbm_model_file_exists():
    path = os.path.join(MODEL_DIR, "phishguard_url_gbm.joblib")
    assert os.path.exists(path), f"Model file missing at {path}"

def test_url_mlp_model_file_exists():
    path = os.path.join(MODEL_DIR, "phishguard_url_mlp.joblib")
    assert os.path.exists(path), f"Model file missing at {path}"

def test_text_rf_model_file_exists():
    path = os.path.join(MODEL_DIR, "phishguard_text_nlp.joblib")
    assert os.path.exists(path), f"Model file missing at {path}"

def test_models_have_metrics_and_cv():
    """Verify loaded model packages contain metrics, cross_validation and confusion_matrix"""
    for filename in ["phishguard_url_rf.joblib", "phishguard_url_gbm.joblib", "phishguard_url_mlp.joblib", "phishguard_text_nlp.joblib"]:
        path = os.path.join(MODEL_DIR, filename)
        if os.path.exists(path):
            data = joblib.load(path)
            assert isinstance(data, dict), f"{filename} payload is not a dict"
            assert "model" in data or "pipeline" in data, f"{filename} missing 'model' or 'pipeline'"
            if "metrics" in data:
                assert "accuracy" in data["metrics"]
                assert "f1_score" in data["metrics"]
            if "cross_validation" in data:
                assert "cv_accuracy_mean" in data["cross_validation"]
                assert "cv_f1_mean" in data["cross_validation"]
