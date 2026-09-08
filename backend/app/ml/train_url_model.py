import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from app.ml.url_feature_extractor import extract_url_features, feature_dict_to_list

def generate_synthetic_url_dataset():
    """Generate representative dataset of legitimate and phishing URLs for model training."""
    legitimate_urls = [
        "https://www.google.com/search?q=cybersecurity",
        "https://github.com/torvalds/linux",
        "https://wikipedia.org/wiki/Machine_learning",
        "https://aws.amazon.com/console/",
        "https://www.microsoft.com/en-us/store",
        "https://stackoverflow.com/questions/123456",
        "https://news.ycombinator.com/item?id=3000",
        "https://www.nytimes.com/section/technology",
        "https://pypi.org/project/scikit-learn/",
        "https://fastapi.tiangolo.com/tutorial/",
        "https://docs.python.org/3/library/index.html",
        "https://developer.mozilla.org/en-US/docs/Web",
        "https://www.medium.com/@author/article-name",
        "https://cloud.google.com/vertex-ai",
        "https://gitlab.com/group/project/-/pipelines",
        "https://bitbucket.org/workspace/repository",
        "https://www.oracle.com/database/technologies/",
        "https://www.cisco.com/c/en/us/products/security",
        "https://www.cloudflare.com/learning/ddos/what-is-ddos/",
        "https://www.eff.org/privacy/tor"
    ]

    phishing_urls = [
        "http://192.168.1.100/paypal.com/login-verify-account.php?id=99283",
        "http://secure-update-appleid-billing.xyz/login.html?token=x938",
        "http://microsoft-online-account-recovery.top/auth/signin",
        "http://verify-bank-account-security-alert.club/update-pin.asp",
        "http://google-drive-shared-doc-claim.site/login@verify",
        "http://account-paypal-resolution-center.work/cgi-bin/webscr",
        "http://10.0.0.15/online-banking-confirm-identity.html",
        "http://amazon-prime-giftcard-claim.info/claim?code=88392",
        "http://wallet-connect-crypto-airdrop.online/claim-tokens",
        "http://secure-billing-netflix-update.gq/login",
        "http://facebook-security-checkpoint-verify.tk/checkpoint",
        "http://chase-bank-verify-ssn-urgent.ml/login.php",
        "http://wellsfargo-online-service-update.biz/secure/auth",
        "http://binance-account-unlock-verification.xyz/kyc",
        "http://instagram-copyright-infringement-appeal.site/appeal.php",
        "http://dhl-package-delivery-tracking-update.club/track",
        "http://usps-address-redelivery-confirm.top/redelivery",
        "http://outlook-webmail-upgrade-required.online/login",
        "http://coinbase-security-vault-verification.work/login",
        "http://metamask-seed-phrase-verify-wallet.xyz/connect"
    ]

    data = []
    # Add legit URLs with label 0
    for url in legitimate_urls:
        feats = extract_url_features(url)
        feats['label'] = 0
        data.append(feats)
        
    # Add phishing URLs with label 1
    for url in phishing_urls:
        feats = extract_url_features(url)
        feats['label'] = 1
        data.append(feats)

    # Augment data with slight feature noise to create a robust dataset
    augmented_data = []
    for item in data:
        augmented_data.append(item)
        # Duplicate with minor variation
        v1 = item.copy()
        v1['url_length'] += np.random.randint(1, 5)
        v1['entropy'] = round(v1['entropy'] + np.random.uniform(-0.1, 0.1), 4)
        augmented_data.append(v1)

    df = pd.DataFrame(augmented_data)
    return df

def train_and_save_url_model(output_dir: str = None):
    """Train Random Forest, Gradient Boosting, and MLP models and save to disk."""
    if output_dir is None:
        output_dir = os.path.dirname(__file__)

    df = generate_synthetic_url_dataset()
    X = df.drop(columns=['label'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.neural_network import MLPClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import make_pipeline

    models_config = {
        "rf": (RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42), "phishguard_url_rf.joblib", "Random Forest Classifier"),
        "gbm": (GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42), "phishguard_url_gbm.joblib", "Gradient Boosting Classifier"),
        "mlp": (make_pipeline(StandardScaler(), MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=500, random_state=42)), "phishguard_url_mlp.joblib", "Multi-Layer Perceptron (MLP)")
    }

    trained_payloads = {}

    for key, (clf, filename, name) in models_config.items():
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, zero_division=0)
        rec = recall_score(y_test, y_pred, zero_division=0)
        f1 = f1_score(y_test, y_pred, zero_division=0)

        print(f"=== {name} Training Metrics ===")
        print(f"Accuracy : {acc * 100:.2f}% | Precision: {prec * 100:.2f}% | Recall: {rec * 100:.2f}% | F1: {f1 * 100:.2f}%")

        payload = {
            "model": clf,
            "model_name": name,
            "feature_names": list(X.columns),
            "metrics": {"accuracy": float(acc), "precision": float(prec), "recall": float(rec), "f1_score": float(f1)}
        }
        
        file_path = os.path.join(output_dir, filename)
        joblib.dump(payload, file_path)
        trained_payloads[key] = payload

    print("Top 3 ML Models saved successfully!")
    return trained_payloads

if __name__ == "__main__":
    train_and_save_url_model()

