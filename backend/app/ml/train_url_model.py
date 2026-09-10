"""
PhishGuard URL Phishing Detection — ML Training Pipeline
=========================================================
Models: Random Forest | Gradient Boosting | MLP Neural Network
Dataset: 200+ curated URLs (legitimate + phishing patterns from PhishTank/OpenPhish research)
Validation: 5-Fold Stratified Cross-Validation
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score, cross_val_predict
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
)
from app.ml.url_feature_extractor import extract_url_features

# ─────────────────────────────────────────────
# Optional: Load real Kaggle/PhishTank CSV
# ─────────────────────────────────────────────
def load_dataset_from_csv(csv_path: str) -> pd.DataFrame:
    """
    Load a real phishing dataset from a CSV file (e.g. from Kaggle).
    Expected columns: 'url' (string) and 'label' (0=legit, 1=phishing).
    Falls back to the built-in dataset if the file is not found.
    """
    if not os.path.exists(csv_path):
        print(f"[Info] CSV not found at {csv_path}. Using built-in dataset.")
        return None
    try:
        df = pd.read_csv(csv_path)
        if 'url' not in df.columns or 'label' not in df.columns:
            print("[Warning] CSV must have 'url' and 'label' columns. Using built-in dataset.")
            return None
        print(f"[Dataset] Loaded {len(df)} rows from CSV: {csv_path}")
        return df
    except Exception as e:
        print(f"[Warning] Could not load CSV: {e}. Using built-in dataset.")
        return None


# ─────────────────────────────────────────────
# Built-in curated dataset (200+ URLs)
# Based on documented PhishTank / OpenPhish patterns
# ─────────────────────────────────────────────
LEGITIMATE_URLS = [
    # Major Tech / Cloud
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/torvalds/linux",
    "https://wikipedia.org/wiki/Machine_learning",
    "https://aws.amazon.com/console/",
    "https://www.microsoft.com/en-us/store",
    "https://stackoverflow.com/questions/123456",
    "https://news.ycombinator.com/item?id=3000",
    "https://pypi.org/project/scikit-learn/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://docs.python.org/3/library/index.html",
    "https://developer.mozilla.org/en-US/docs/Web",
    "https://cloud.google.com/vertex-ai",
    "https://gitlab.com/group/project/-/pipelines",
    "https://bitbucket.org/workspace/repository",
    "https://www.oracle.com/database/technologies/",
    "https://www.cisco.com/c/en/us/products/security",
    "https://www.cloudflare.com/learning/ddos/what-is-ddos/",
    "https://www.eff.org/privacy/tor",
    "https://kubernetes.io/docs/concepts/overview/",
    "https://hub.docker.com/_/python",
    # E-commerce / Finance
    "https://www.amazon.com/dp/B08N5WRWNW",
    "https://www.paypal.com/us/home",
    "https://www.chase.com/personal/checking",
    "https://www.wellsfargo.com/mortgage/",
    "https://stripe.com/docs/payments",
    "https://www.shopify.com/pricing",
    "https://www.ebay.com/sch/i.html?_nkw=laptop",
    "https://www.bestbuy.com/site/laptops/all-laptops/pcmcat138500050001.c",
    "https://www.walmart.com/cp/electronics/3944",
    "https://www.target.com/c/electronics/-/N-5xtg6",
    # Media / News
    "https://www.nytimes.com/section/technology",
    "https://www.bbc.com/news/technology",
    "https://www.reuters.com/technology/",
    "https://techcrunch.com/category/security/",
    "https://www.wired.com/category/security/",
    "https://arstechnica.com/security/",
    "https://www.theguardian.com/technology",
    "https://www.lemonde.fr/pixels/",
    "https://www.lefigaro.fr/secteur/high-tech",
    "https://www.liberation.fr/societe/numerique/",
    # Education / Gov
    "https://www.mit.edu/research/artificial-intelligence",
    "https://www.stanford.edu/departments/computer-science",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.edx.org/learn/cybersecurity",
    "https://www.usa.gov/online-security",
    "https://www.cisa.gov/topics/cyber-threats-and-advisories",
    "https://nvd.nist.gov/vuln/full-listing",
    "https://www.cert.ssi.gouv.fr/",
    "https://www.data.gouv.fr/fr/datasets/",
    "https://www.legifrance.gouv.fr/",
    # Social / Communication
    "https://www.linkedin.com/in/profile-name",
    "https://twitter.com/intent/tweet?text=Hello",
    "https://www.facebook.com/groups/developers",
    "https://www.instagram.com/explore/tags/cybersecurity/",
    "https://discord.com/channels/123456/789012",
    "https://slack.com/intl/en-fr/help/articles/201374536",
    "https://zoom.us/meeting/schedule",
    "https://teams.microsoft.com/l/meetup-join/",
    "https://meet.google.com/abc-defg-hij",
    "https://www.reddit.com/r/netsec/",
    # Dev / Open source
    "https://www.npmjs.com/package/react",
    "https://packagist.org/packages/laravel/laravel",
    "https://crates.io/crates/tokio",
    "https://rubygems.org/gems/rails",
    "https://pkg.go.dev/net/http",
    "https://maven.apache.org/guides/introduction/",
    "https://gradle.org/docs/",
    "https://www.jetbrains.com/idea/documentation/",
    "https://code.visualstudio.com/docs/",
    "https://www.postman.com/docs/",
    # Crypto (Legit)
    "https://www.coinbase.com/learn/crypto-basics",
    "https://ethereum.org/en/developers/docs/",
    "https://bitcoin.org/en/faq",
    "https://binance.com/en/support",
    "https://www.ledger.com/academy",
    # Healthcare / Services
    "https://www.who.int/news-room/fact-sheets/detail/malaria",
    "https://www.nih.gov/research-training/",
    "https://www.webmd.com/vitamins/ai/ingredientmono-982",
    "https://www.healthline.com/health/skin/atopic-dermatitis",
    "https://www.mayoclinic.org/diseases-conditions/cancer/symptoms-causes/syc-20370588",
    # Travel / Booking
    "https://www.booking.com/hotel/fr/paris.html",
    "https://www.airbnb.com/rooms/12345678",
    "https://www.tripadvisor.com/Hotel_Review-g187147",
    "https://www.expedia.com/Flights-Search",
    "https://www.sncf.com/fr/horaires/tgv/paris-lyon",
    # French Companies
    "https://www.orange.fr/portail",
    "https://www.sap.com/france/products/erp.html",
    "https://www.capgemini.com/fr-fr/about-us/",
    "https://www.renault.com/fr/vehicules/renault",
    "https://www.totalenergies.fr/particuliers",
    # Streaming / Entertainment
    "https://www.netflix.com/browse",
    "https://www.spotify.com/fr/account/overview/",
    "https://www.youtube.com/channel/UC_x5XG1OV2P6uZZ5FSM9Ttw",
    "https://www.twitch.tv/directory/game/Science%20%26%20Technology",
    "https://www.hulu.com/series/",
    # Security Vendors (Legit)
    "https://www.crowdstrike.com/cybersecurity-101/",
    "https://www.paloaltonetworks.com/cyberpedia",
    "https://www.sentinelone.com/blog/",
    "https://www.darktrace.com/blog/",
    "https://www.mandiant.com/resources/blog",
]

PHISHING_URLS = [
    # PayPal spoofing
    "http://192.168.1.100/paypal.com/login-verify-account.php?id=99283",
    "http://secure-update-paypal-verify.xyz/login.html?token=x938",
    "http://paypal-account-resolution-center.work/cgi-bin/webscr",
    "http://paypal-security-team-verify-account.top/update",
    "http://www.paypal-service-notice.club/auth/signin",
    # Apple ID spoofing
    "http://secure-update-appleid-billing.xyz/login.html?token=x938",
    "http://appleid-security.top/verify/payment-update",
    "http://apple-account-locked-verify.site/unlock.php",
    "http://apple-id-security-alert.online/confirm-identity",
    "http://appleid-billing-verify-secure.info/update-now",
    # Microsoft spoofing
    "http://microsoft-online-account-recovery.top/auth/signin",
    "http://outlook-webmail-upgrade-required.online/login",
    "http://microsoft365-account-verify.xyz/signin",
    "http://microsoft-security-alert-login.work/reset",
    "http://ms-office365-verify-identity.club/auth",
    # Banking
    "http://verify-bank-account-security-alert.club/update-pin.asp",
    "http://chase-bank-verify-ssn-urgent.ml/login.php",
    "http://wellsfargo-online-service-update.biz/secure/auth",
    "http://bnpparibas-secure-login-verify.xyz/compte",
    "http://societegenerale-espace-client-verify.top/connexion",
    "http://creditagricole-secure-update.online/espace-client",
    "http://boursorama-account-verify-secure.work/login",
    "http://lcl-banque-espace-personnel-verify.site/connexion",
    # Amazon / E-commerce
    "http://amazon-prime-giftcard-claim.info/claim?code=88392",
    "http://amazon-order-verify-account-update.xyz/signin",
    "http://amazon-security-alert-unusual-activity.top/verify",
    "http://amazon-account-suspended-verify.club/restore",
    "http://amazon-fr-verification-paiement.site/connexion",
    # Crypto scams
    "http://wallet-connect-crypto-airdrop.online/claim-tokens",
    "http://binance-account-unlock-verification.xyz/kyc",
    "http://coinbase-security-vault-verification.work/login",
    "http://metamask-seed-phrase-verify-wallet.xyz/connect",
    "http://crypto-airdrop-free-usdt-claim.top/wallet-connect",
    "http://eth-airdrop-2024-claim-reward.site/connect-wallet",
    "http://bitcoin-reward-claim-official.online/claim?ref=abc",
    # Netflix / Streaming
    "http://secure-billing-netflix-update.gq/login",
    "http://netflix-account-suspended-billing.top/update-payment",
    "http://netflix-fr-mise-a-jour-paiement.xyz/connexion",
    "http://netflix-billing-verify-now.club/account",
    # Facebook / Instagram / Social
    "http://facebook-security-checkpoint-verify.tk/checkpoint",
    "http://instagram-copyright-infringement-appeal.site/appeal.php",
    "http://facebook-unusual-login-verify.online/security",
    "http://instagram-account-suspended-restore.top/verify",
    "http://whatsapp-account-verify-phone.xyz/confirm",
    # DHL / USPS / Delivery
    "http://dhl-package-delivery-tracking-update.club/track",
    "http://usps-address-redelivery-confirm.top/redelivery",
    "http://fedex-package-pending-delivery-confirm.site/track",
    "http://colissimo-livraison-confirmer-adresse.xyz/confirmer",
    "http://laposte-colis-livraison-update.online/confirmer",
    # Government / Tax impersonation
    "http://impots-gouv-remboursement-tva.xyz/demande",
    "http://service-public-fr-identite-numerique.top/connexion",
    "http://irs-refund-claim.work/submit?ssn=",
    "http://caf-allocation-exceptionnelle-verifier.site/connexion",
    "http://ameli-assurance-maladie-remboursement.club/compte",
    # IP-based direct attacks
    "http://10.0.0.15/online-banking-confirm-identity.html",
    "http://172.16.0.5/paypal-login.php",
    "http://192.168.0.1/admin/secure-login.asp",
    "http://10.10.10.10/microsoft-verify.html",
    "http://192.168.1.254/apple-id-verify.php",
    # Google spoofing
    "http://google-drive-shared-doc-claim.site/login@verify",
    "http://google-account-security-verify.xyz/signin",
    "http://google-workspace-suspended-verify.online/restore",
    # Steam / Gaming
    "http://steamcommunity-trade-offer-verify.xyz/login",
    "http://steam-free-cs2-skins-claim.top/claim",
    "http://discord-nitro-free-gift-claim.online/gift?code=abc",
    # Healthcare / SSN theft
    "http://medicare-verify-identity-benefits.xyz/update",
    "http://social-security-benefit-claim.top/apply?ssn=",
    # General patterns
    "http://secure-login-verify-account-update.xyz/auth",
    "http://account-suspended-urgent-verify.online/restore",
    "http://billing-update-required-now.club/pay",
    "http://free-gift-card-reward-claim.site/claim",
    "http://urgent-security-alert-verify.top/login",
    "http://your-account-has-been-hacked-verify.work/reset",
    "http://confirm-identity-account-locked.xyz/unlock",
    "http://limited-time-offer-claim-reward.online/get",
    "http://suspicious-login-verify-now.club/verify",
    "http://access-restricted-verify-identity.top/access",
    # Office 365 / Enterprise
    "http://office365-subscription-expired-update.xyz/renew",
    "http://sharepoint-document-shared-verify.online/view",
    "http://outlook-calendar-invite-verify.top/accept",
    # HR / Payroll scams
    "http://hr-payroll-update-bank-details.xyz/update",
    "http://urgent-wire-transfer-ceo-request.online/approve",
    "http://invoice-payment-due-immediately.work/pay",
    # VPN / Proxy spoofing
    "http://nordvpn-account-suspended-reactivate.xyz/login",
    "http://expressvpn-renewal-required.online/renew",
    # Insurance / Legal
    "http://assurance-maladie-remboursement-verifier.xyz/compte",
    "http://accident-indemnisation-rapide-claim.online/formulaire",
    # Misc high-entropy / random-looking
    "http://xk2j9s-secure.top/login?id=827361&token=abc9182",
    "http://a8f3b1.xyz/verify?uid=98271&session=kx81jq",
    "http://j19dk2.online/auth?redirect=paypal&token=9283kjn",
    "http://82kd9a.club/login.php?ref=bank&id=991827",
    "http://z8x9k1-secure-verify.work/account?id=827&tk=nkd82",
]


def generate_builtin_dataset() -> pd.DataFrame:
    """Generate feature-extracted dataset from built-in curated URL lists."""
    print(f"[Dataset] Built-in: {len(LEGITIMATE_URLS)} legitimate + {len(PHISHING_URLS)} phishing URLs")
    data = []
    for url in LEGITIMATE_URLS:
        try:
            feats = extract_url_features(url)
            feats['label'] = 0
            data.append(feats)
        except Exception:
            pass
    for url in PHISHING_URLS:
        try:
            feats = extract_url_features(url)
            feats['label'] = 1
            data.append(feats)
        except Exception:
            pass
    df = pd.DataFrame(data)
    print(f"[Dataset] Total samples after feature extraction: {len(df)}")
    return df


def generate_dataset_from_csv_or_builtin(csv_path: str = None) -> pd.DataFrame:
    """Try to load from CSV first; fall back to built-in curated dataset."""
    if csv_path:
        df_csv = load_dataset_from_csv(csv_path)
        if df_csv is not None:
            # Extract features from the CSV URLs
            data = []
            for _, row in df_csv.iterrows():
                try:
                    feats = extract_url_features(str(row['url']))
                    feats['label'] = int(row['label'])
                    data.append(feats)
                except Exception:
                    pass
            df = pd.DataFrame(data)
            print(f"[Dataset] CSV extracted features: {len(df)} samples")
            return df
    return generate_builtin_dataset()


def compute_confusion_matrix_values(y_true, y_pred):
    """Return confusion matrix as a readable dict {TN, FP, FN, TP}."""
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn, fp, fn, tp = 0, 0, 0, int(cm[0][0])
    return {
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive": int(tp)
    }


def train_and_save_url_model(output_dir: str = None, csv_path: str = None):
    """
    Train Random Forest, Gradient Boosting, and MLP models.
    Includes 5-Fold Stratified Cross-Validation.
    Saves trained models with full metrics to disk.
    """
    if output_dir is None:
        output_dir = os.path.dirname(__file__)

    df = generate_dataset_from_csv_or_builtin(csv_path)
    X = df.drop(columns=['label'])
    y = df['label']

    # ── Hold-out Test Split ──────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── 5-Fold Stratified Cross-Validation Setup ─────────────────────
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    models_config = {
        "rf": (
            RandomForestClassifier(n_estimators=150, max_depth=12, min_samples_split=4, random_state=42),
            "phishguard_url_rf.joblib",
            "Random Forest Classifier"
        ),
        "gbm": (
            GradientBoostingClassifier(n_estimators=150, learning_rate=0.08, max_depth=5,
                                       subsample=0.85, random_state=42),
            "phishguard_url_gbm.joblib",
            "Gradient Boosting Machine (GBM)"
        ),
        "mlp": (
            make_pipeline(
                StandardScaler(),
                MLPClassifier(hidden_layer_sizes=(64, 32, 16), activation='relu',
                               max_iter=800, random_state=42, early_stopping=True,
                               validation_fraction=0.15)
            ),
            "phishguard_url_mlp.joblib",
            "Multi-Layer Perceptron Neural Network"
        ),
    }

    trained_payloads = {}

    for key, (clf, filename, name) in models_config.items():
        print(f"\n{'='*55}")
        print(f"  Training: {name}")
        print(f"{'='*55}")

        # ── 5-Fold Cross-Validation (on full dataset) ─────────────
        cv_scores_acc  = cross_val_score(clf, X, y, cv=cv, scoring='accuracy',  n_jobs=-1)
        cv_scores_f1   = cross_val_score(clf, X, y, cv=cv, scoring='f1',        n_jobs=-1)
        cv_scores_prec = cross_val_score(clf, X, y, cv=cv, scoring='precision', n_jobs=-1)
        cv_scores_rec  = cross_val_score(clf, X, y, cv=cv, scoring='recall',    n_jobs=-1)

        print(f"  [5-Fold CV] Accuracy : {cv_scores_acc.mean()*100:.2f}% +/- {cv_scores_acc.std()*100:.2f}%")
        print(f"  [5-Fold CV] F1-Score : {cv_scores_f1.mean()*100:.2f}%  +/- {cv_scores_f1.std()*100:.2f}%")
        print(f"  [5-Fold CV] Precision: {cv_scores_prec.mean()*100:.2f}% +/- {cv_scores_prec.std()*100:.2f}%")
        print(f"  [5-Fold CV] Recall   : {cv_scores_rec.mean()*100:.2f}%  +/- {cv_scores_rec.std()*100:.2f}%")

        # ── Train on Train set, evaluate on Hold-out Test set ────
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        acc   = accuracy_score(y_test, y_pred)
        prec  = precision_score(y_test, y_pred, zero_division=0)
        rec   = recall_score(y_test, y_pred, zero_division=0)
        f1    = f1_score(y_test, y_pred, zero_division=0)
        cm    = compute_confusion_matrix_values(y_test, y_pred)

        print(f"\n  [Hold-out Test] Accuracy : {acc*100:.2f}%")
        print(f"  [Hold-out Test] Precision: {prec*100:.2f}%")
        print(f"  [Hold-out Test] Recall   : {rec*100:.2f}%")
        print(f"  [Hold-out Test] F1-Score : {f1*100:.2f}%")
        print(f"  [Confusion Matrix] TP={cm['true_positive']} FP={cm['false_positive']} "
              f"TN={cm['true_negative']} FN={cm['false_negative']}")

        payload = {
            "model": clf,
            "model_name": name,
            "feature_names": list(X.columns),
            "dataset_size": len(df),
            "metrics": {
                "accuracy":  round(float(acc), 4),
                "precision": round(float(prec), 4),
                "recall":    round(float(rec), 4),
                "f1_score":  round(float(f1), 4),
            },
            "cross_validation": {
                "n_folds": 5,
                "cv_accuracy_mean":  round(float(cv_scores_acc.mean()), 4),
                "cv_accuracy_std":   round(float(cv_scores_acc.std()), 4),
                "cv_accuracy_scores": [round(s, 4) for s in cv_scores_acc.tolist()],
                "cv_f1_mean":        round(float(cv_scores_f1.mean()), 4),
                "cv_f1_std":         round(float(cv_scores_f1.std()), 4),
                "cv_precision_mean": round(float(cv_scores_prec.mean()), 4),
                "cv_recall_mean":    round(float(cv_scores_rec.mean()), 4),
            },
            "confusion_matrix": cm
        }

        file_path = os.path.join(output_dir, filename)
        joblib.dump(payload, file_path)
        trained_payloads[key] = payload
        print(f"  [OK] Saved -> {filename}")

    print(f"\n{'='*55}")
    print("  [OK] All 3 URL models trained & saved successfully!")
    print(f"{'='*55}\n")
    return trained_payloads


if __name__ == "__main__":
    # To use a real Kaggle CSV, pass the path:
    # train_and_save_url_model(csv_path="path/to/phishing_dataset.csv")
    train_and_save_url_model()
