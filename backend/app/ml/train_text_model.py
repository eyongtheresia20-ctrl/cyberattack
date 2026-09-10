"""
PhishGuard Text / Email / SMS NLP Pipeline — Training Script
=============================================================
Model : TF-IDF Vectorizer (unigrams + bigrams) + Random Forest Classifier
Dataset : 80 curated messages (40 legitimate + 40 phishing)
Validation : 5-Fold Stratified Cross-Validation
"""

import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix


LEGITIMATE_MESSAGES = [
    # Workplace / Team
    "Hey, are we still meeting for lunch tomorrow at 12:30 PM?",
    "Hi Team, please review the attached project schedule for Q3.",
    "Can you send me the latest slides for the client presentation?",
    "The software update has completed successfully on your device.",
    "Reminder: Your doctor appointment is scheduled for Thursday at 10 AM.",
    "Your monthly bank statement is now available in your online dashboard. Thank you.",
    "Your order #49204 has shipped and is estimated to arrive on Friday.",
    "Verification code for your account is 482019. Do not share this code.",
    "Happy Birthday! Wishing you a fantastic day filled with joy.",
    "Security Notice: Successful login to your account from Chrome on Windows.",
    # Official Notifications
    "Your password was changed successfully. If this wasn't you, contact support.",
    "Your subscription has been renewed. Thank you for staying with us.",
    "Your invoice for this month is now available to download in your account.",
    "We have received your support request and will respond within 24 hours.",
    "Your package is out for delivery today between 10 AM and 2 PM.",
    "Thank you for your purchase. Your order will be ready in 3-5 business days.",
    "Your reservation has been confirmed for Saturday at 7:00 PM.",
    "This is a reminder that your library books are due back on September 15.",
    "Your direct deposit of $2,450.00 has been credited to your account.",
    "Your flight check-in is now open. Check in online to save time at the airport.",
    # Educational / Informational
    "The meeting notes from yesterday's session have been shared on Drive.",
    "Please review the updated data privacy policy attached to this email.",
    "Your 2-step verification was successfully set up on your account.",
    "New comment on your post: 'Great insights! Really valuable analysis.'",
    "Your weekly activity summary is ready to view in the app.",
    "You have 3 unread messages in your inbox.",
    "Your gym membership will renew automatically on the 1st of next month.",
    "This month's newsletter is now available. Read about our latest features.",
    "Your annual performance review is scheduled for next Tuesday at 2 PM.",
    "The quarterly financial report has been posted on the intranet portal.",
    # French legitimate messages
    "Bonjour, votre rendez-vous du mardi 10 septembre est confirmé à 14h30.",
    "Votre commande a bien été expédiée et arrivera sous 3 à 5 jours ouvrés.",
    "Votre relevé de compte du mois d'août est disponible dans votre espace client.",
    "Rappel: votre abonnement mensuel sera renouvelé automatiquement le 1er octobre.",
    "Votre code de vérification est : 847392. Ne le partagez avec personne.",
    "Votre mot de passe a été modifié avec succès. Contactez le support si nécessaire.",
    "Bonne nouvelle! Votre demande de remboursement a été traitée.",
    "L'assemblée générale annuelle aura lieu le 15 octobre à 10h en salle de conférence.",
    "Votre colis est en cours d'acheminement et devrait arriver vendredi.",
    "Merci de votre confiance. Votre satisfaction est notre priorité.",
]

PHISHING_MESSAGES = [
    # PayPal phishing
    "URGENT: Your PayPal account has been suspended! Click http://secure-paypal-verify.xyz to restore access within 24h.",
    "Action Required: Verify your PayPal information immediately at http://paypal-account-resolution.top",
    "Your PayPal account will be permanently closed unless you update your details: http://paypal-verify.club",
    # Bank phishing
    "ALERT: Unusual login attempt detected on your bank account. Verify identity immediately at http://192.168.1.100/login",
    "FINAL NOTICE: Your tax refund of $480 is ready. Submit SSN and card details at http://irs-refund-claim.work",
    "Urgent: Your bank account has been flagged for suspicious activity. Verify now: http://bank-verify-secure.xyz",
    "Your account is at risk! Update your banking credentials immediately at http://secure-bank-login.top",
    # Amazon phishing
    "CONGRATULATIONS! You won a $1000 Amazon Gift Card. Claim your reward now at http://giftcard-claim.info",
    "Amazon: Your account has been temporarily suspended. Verify your identity: http://amazon-verify-account.xyz",
    "Your Amazon order has a problem. Confirm your payment method: http://amazon-payment-update.top",
    # Apple phishing
    "SECURITY NOTICE: Your Apple ID is locked due to multiple failed attempts. Update payment info http://appleid-security.top",
    "Apple: Your iCloud storage is full and your account is at risk. Verify now: http://icloud-verify-secure.online",
    # Microsoft phishing
    "WARNING: Credential compromise detected! Please reset your Microsoft password immediately: http://outlook-verify.online",
    "Microsoft: Unusual sign-in activity detected. Secure your account: http://microsoft-security-login.xyz",
    "Your Office 365 subscription has expired. Renew now to avoid data loss: http://office365-renew.top",
    # Netflix phishing
    "Your Netflix subscription payment failed. Account will be terminated today unless updated at http://netflix-billing.site",
    "Netflix: Update your payment information to continue your subscription: http://netflix-payment-verify.club",
    # Delivery / Shipping
    "USPS: Package delivery pending due to invalid address. Confirm address immediately http://usps-redelivery.club",
    "DHL: Your package is being held. Pay customs fee to release: http://dhl-customs-fee.xyz",
    "FedEx: Delivery failed. Schedule redelivery at: http://fedex-redeliver.online",
    # Crypto scams
    "Crypto Airdrop: Claim your 500 FREE USDT tokens now by connecting wallet at http://wallet-connect-airdrop.xyz",
    "SPECIAL OFFER: Double your Bitcoin investment in 24 hours! Visit http://bitcoin-double.top",
    "MetaMask: Your wallet requires urgent security verification. Connect at http://metamask-verify.xyz",
    # CEO Fraud / Wire Transfer
    "Urgent wire transfer request: Please process payment of $12,500 to vendor immediately.",
    "This is urgent. I need you to purchase iTunes gift cards worth $500 and send codes. CEO",
    "Process this invoice ASAP before end of day. Vendor account: http://invoice-pay-now.xyz",
    # Credential Harvesting
    "Your email password will expire in 24 hours. Update it now: http://webmail-update.online",
    "IT Department: Reset your credentials immediately to avoid account lockout: http://it-reset.xyz",
    "Security Alert: Your login credentials were exposed in a breach. Reset now: http://reset-verify.top",
    # Government / Tax impersonation
    "IRS: You owe back taxes. Pay immediately to avoid arrest: http://irs-payment-urgent.work",
    "Social Security Administration: Your SSN has been suspended. Call immediately or pay fine.",
    "COVID relief payment of $1,400 is available. Claim at http://covid-relief-claim.xyz",
    # French phishing
    "URGENT: Votre compte PayPal a été suspendu! Vérifiez immédiatement: http://paypal-verif.xyz",
    "Impôts: Vous avez un remboursement en attente. Cliquez ici: http://impots-remboursement.top",
    "Votre colis est bloqué en douane. Payez 2,99€ pour le libérer: http://colissimo-douane.xyz",
    "ALERTE SÉCURITÉ: Votre compte bancaire a été compromis. Vérifiez: http://bnp-securite.club",
    "CAF: Vous avez droit à une aide exceptionnelle. Réclamez maintenant: http://caf-aide.online",
    "Ameli: Votre carte vitale expire bientôt. Mettez à jour vos informations: http://ameli-renouvellement.xyz",
    # Generic psychological manipulation
    "CONGRATULATIONS! You are today's lucky winner. Claim your prize: http://prize-claim.top",
    "FINAL WARNING: Your account will be deleted in 24 hours unless you act now: http://account-restore.work",
]


def generate_text_dataset() -> pd.DataFrame:
    """Build the labeled text dataset from curated message lists."""
    print(f"[Dataset] Text: {len(LEGITIMATE_MESSAGES)} legitimate + {len(PHISHING_MESSAGES)} phishing messages")
    data = [(msg, 0) for msg in LEGITIMATE_MESSAGES] + [(msg, 1) for msg in PHISHING_MESSAGES]
    df = pd.DataFrame(data, columns=['text', 'label'])
    print(f"[Dataset] Total text samples: {len(df)}")
    return df


def compute_confusion_matrix_values(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    if cm.shape == (2, 2):
        tn, fp, fn, tp = cm.ravel()
    else:
        tn, fp, fn, tp = 0, 0, 0, int(cm[0][0])
    return {
        "true_negative":  int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn),
        "true_positive":  int(tp)
    }


def train_and_save_text_model(output_path: str = None):
    """
    Train TF-IDF + Random Forest NLP pipeline with 5-fold cross-validation.
    Saves model + full metrics payload to disk.
    """
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "phishguard_text_nlp.joblib")

    df = generate_text_dataset()
    X = df['text']
    y = df['label']

    # ── Hold-out Split ───────────────────────────────────────────────
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # ── Pipeline: TF-IDF + Random Forest ────────────────────────────
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),   # Unigrams + Bigrams
            min_df=1,
            sublinear_tf=True,    # Log normalization
            analyzer='word',
            strip_accents='unicode'
        )),
        ('clf', RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_split=2,
            random_state=42
        ))
    ])

    # ── 5-Fold Stratified Cross-Validation ──────────────────────────
    print(f"\n{'='*55}")
    print("  Training: Text NLP Pipeline (TF-IDF + Random Forest)")
    print(f"{'='*55}")

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_acc  = cross_val_score(pipeline, X, y, cv=cv, scoring='accuracy',  n_jobs=-1)
    cv_f1   = cross_val_score(pipeline, X, y, cv=cv, scoring='f1',        n_jobs=-1)
    cv_prec = cross_val_score(pipeline, X, y, cv=cv, scoring='precision', n_jobs=-1)
    cv_rec  = cross_val_score(pipeline, X, y, cv=cv, scoring='recall',    n_jobs=-1)

    print(f"  [5-Fold CV] Accuracy : {cv_acc.mean()*100:.2f}% +/- {cv_acc.std()*100:.2f}%")
    print(f"  [5-Fold CV] F1-Score : {cv_f1.mean()*100:.2f}%  +/- {cv_f1.std()*100:.2f}%")
    print(f"  [5-Fold CV] Precision: {cv_prec.mean()*100:.2f}% +/- {cv_prec.std()*100:.2f}%")
    print(f"  [5-Fold CV] Recall   : {cv_rec.mean()*100:.2f}%  +/- {cv_rec.std()*100:.2f}%")

    # ── Train on train set, evaluate on hold-out ─────────────────────
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)
    acc   = accuracy_score(y_test, y_pred)
    prec  = precision_score(y_test, y_pred, zero_division=0)
    rec   = recall_score(y_test, y_pred, zero_division=0)
    f1    = f1_score(y_test, y_pred, zero_division=0)
    cm    = compute_confusion_matrix_values(y_test, y_pred)

    print(f"\n  [Hold-out Test] Accuracy : {acc*100:.2f}%")
    print(f"  [Hold-out Test] F1-Score : {f1*100:.2f}%")
    print(f"  [Hold-out Test] Precision: {prec*100:.2f}%")
    print(f"  [Hold-out Test] Recall   : {rec*100:.2f}%")
    print(f"  [Confusion Matrix] TP={cm['true_positive']} FP={cm['false_positive']} "
          f"TN={cm['true_negative']} FN={cm['false_negative']}")

    model_payload = {
        "pipeline": pipeline,
        "model_name": "Text NLP Pipeline (TF-IDF + Random Forest)",
        "dataset_size": len(df),
        "metrics": {
            "accuracy":  round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall":    round(float(rec), 4),
            "f1_score":  round(float(f1), 4),
        },
        "cross_validation": {
            "n_folds": 5,
            "cv_accuracy_mean":  round(float(cv_acc.mean()), 4),
            "cv_accuracy_std":   round(float(cv_acc.std()), 4),
            "cv_accuracy_scores": [round(s, 4) for s in cv_acc.tolist()],
            "cv_f1_mean":        round(float(cv_f1.mean()), 4),
            "cv_f1_std":         round(float(cv_f1.std()), 4),
            "cv_precision_mean": round(float(cv_prec.mean()), 4),
            "cv_recall_mean":    round(float(cv_rec.mean()), 4),
        },
        "confusion_matrix": cm,
    }

    joblib.dump(model_payload, output_path)
    print(f"\n  [OK] Text NLP model saved -> {output_path}")
    print(f"{'='*55}\n")
    return model_payload


if __name__ == "__main__":
    train_and_save_text_model()
