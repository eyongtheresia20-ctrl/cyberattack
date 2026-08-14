import os
import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score

def generate_text_dataset():
    data = [
        # Legitimate messages/emails (Label 0)
        ("Hey, are we still meeting for lunch tomorrow at 12:30 PM?", 0),
        ("Your monthly bank statement is now available in your online dashboard. Thank you for choosing Us.", 0),
        ("Hi Team, please review the attached project schedule for Q3.", 0),
        ("Reminder: Your doctor appointment is scheduled for Thursday at 10 AM.", 0),
        ("Security Notice: Successful login to your account from Chrome on Windows.", 0),
        ("Your order #49204 has shipped and is estimated to arrive on Friday.", 0),
        ("Can you send me the latest slides for the client presentation?", 0),
        ("Verification code for your account is 482019. Do not share this code.", 0),
        ("Happy Birthday! Wishing you a fantastic day filled with joy.", 0),
        ("The software update has completed successfully on your device.", 0),

        # Phishing / Scam messages/emails (Label 1)
        ("URGENT: Your PayPal account has been suspended! Click http://secure-paypal-verify.xyz to restore access within 24h.", 1),
        ("ALERT: Unusual login attempt detected on your bank account. Verify identity immediately at http://192.168.1.100/login", 1),
        ("CONGRATULATIONS! You won a $1000 Amazon Gift Card. Claim your reward now at http://giftcard-claim.info", 1),
        ("SECURITY NOTICE: Your Apple ID is locked due to multiple failed attempts. Update payment info http://appleid-security.top", 1),
        ("FINAL NOTICE: Your tax refund of $480 is ready. Submit SSN and card details at http://irs-refund-claim.work", 1),
        ("Your Netflix subscription payment failed. Account will be terminated today unless updated at http://netflix-billing.site", 1),
        ("USPS: Package delivery pending due to invalid address. Confirm address immediately http://usps-redelivery.club", 1),
        ("WARNING: Credential compromise detected! Please reset your Microsoft password immediately: http://outlook-verify.online", 1),
        ("Urgent wire transfer request: Please process payment of $12,500 to vendor immediately.", 1),
        ("Crypto Airdrop: Claim your 500 FREE USDT tokens now by connecting wallet at http://wallet-connect-airdrop.xyz", 1)
    ]
    
    df = pd.DataFrame(data, columns=['text', 'label'])
    return df

def train_and_save_text_model(output_path: str = None):
    if output_path is None:
        output_path = os.path.join(os.path.dirname(__file__), "phishguard_text_nlp.joblib")

    df = generate_text_dataset()
    X = df['text']
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), min_df=1)),
        ('clf', RandomForestClassifier(n_estimators=100, random_state=42))
    ])

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred, zero_division=0)

    print(f"=== Text NLP Pipeline Model Training Metrics ===")
    print(f"Accuracy: {acc * 100:.2f}%")
    print(f"F1-Score: {f1 * 100:.2f}%")

    model_payload = {
        "pipeline": pipeline,
        "metrics": {"accuracy": acc, "f1_score": f1}
    }

    joblib.dump(model_payload, output_path)
    print(f"Text Model saved successfully to: {output_path}")
    return model_payload

if __name__ == "__main__":
    train_and_save_text_model()
