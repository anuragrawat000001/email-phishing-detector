from detector import PhishingDetector
import pandas as pd


# 🔥 Rule-based phishing detection
def check_phishing_indicators(email):
    suspicious_keywords = [
        "urgent", "verify", "suspend", "click here", "login",
        "password", "bank", "account locked", "confirm",
        "update", "security alert", "limited time", "act now",
        "winner", "prize", "claim", "free", "lottery"
    ]

    suspicious_domains = [
        "paypa1", "gmai1", "amaz0n", "secure-login", "verify-now"
    ]

    text = (email['subject'] + " " + email['body'] + " " + email['sender']).lower()

    keyword_hits = [word for word in suspicious_keywords if word in text]
    domain_hits = [domain for domain in suspicious_domains if domain in text]

    score = len(keyword_hits) + len(domain_hits)

    return {
        "score": score,
        "keywords": keyword_hits,
        "domains": domain_hits
    }


def main():
    print("="*70)
    print("EMAIL PHISHING DETECTOR - HYBRID MODEL (ML + RULE)")
    print("="*70)

    detector = PhishingDetector()

    # 🔥 TRAIN MODEL
    print("\n📚 Training model using dataset...")

    df = pd.read_csv("CEAS_08.csv")

    emails = []
    labels = []

    for _, row in df.iterrows():
        if 'subject' in df.columns and 'body' in df.columns:
            subject = str(row['subject'])
            body = str(row['body'])
        else:
            subject = str(row.get('text', ''))
            body = ""

        label = int(row['label'])

        emails.append({
            'subject': subject,
            'body': body,
            'sender': 'unknown'
        })

        labels.append(label)

    detector.train(emails, labels)
    detector.save_model()

    print(f"✅ Model trained on {len(emails)} emails!")

    # 🔥 MENU
    while True:
        print("\n" + "="*50)
        print("1. Enter email manually")
        print("2. Load email from file")
        print("Type 'exit' to quit")
        print("="*50)

        choice = input("Choose option: ")

        if choice.lower() == "exit":
            break

        if choice == "1":
            subject = input("Subject: ")
            body = input("Body: ")
            sender = input("Sender: ")

            email = {
                'subject': subject,
                'body': body,
                'sender': sender
            }

        elif choice == "2":
            file_path = input("Enter file path: ")

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                email = {
                    'subject': content,
                    'body': content,
                    'sender': "unknown"
                }

            except Exception as e:
                print(f"❌ Error: {e}")
                continue

        else:
            print("❌ Invalid choice")
            continue

        # 🔍 ML RESULT
        result = detector.predict(email)

        # 🔍 RULE RESULT
        rules = check_phishing_indicators(email)

        print("\n🔍 ML Prediction:", result['prediction'])
        print(f"Confidence: {result['confidence']*100:.2f}%")

        # 🔥 SHOW RULE FLAGS
        if rules['score'] > 0:
            print("\n⚠️ Rule-Based Indicators:")
            if rules['keywords']:
                print("   Keywords:", ", ".join(rules['keywords']))
            if rules['domains']:
                print("   Domains:", ", ".join(rules['domains']))

        # 🔥 HYBRID DECISION (IMPORTANT CHANGE)
        if result['is_phishing'] or rules['score'] >= 2:
            print("\n🚨 FINAL RESULT: PHISHING EMAIL")
        else:
            print("\n✅ FINAL RESULT: SAFE EMAIL")

        again = input("\nTest another email? (y/n): ")
        if again.lower() != 'y':
            print("Exiting... 👋")
            break


if __name__ == "__main__":
    main()
