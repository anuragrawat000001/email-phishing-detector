from detector import PhishingDetector
import pandas as pd

# 🔥 Rule-based phishing detection (optional but useful)
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
    print("EMAIL PHISHING DETECTOR - LIVE DEMO")
    print("="*70)
    
    detector = PhishingDetector()
    
    # 🔥 TRAIN USING KAGGLE DATASET
    print("\n📚 Training model using dataset...")

    df = pd.read_csv("emails.csv")   # make sure this file is in same folder

    emails = []
    labels = []

    # 🔥 HANDLE DIFFERENT DATASET FORMATS
    for _, row in df.iterrows():
        if 'subject' in df.columns and 'body' in df.columns:
            subject = str(row['subject'])
            body = str(row['body'])
        else:
            # if dataset has only 'text'
            subject = str(row.get('text', ''))
            body = ""

        label = int(row['label'])  # must be 0 or 1

        emails.append({
            'subject': subject,
            'body': body,
            'sender': 'unknown'
        })

        labels.append(label)

    detector.train(emails, labels)
    detector.save_model()

    print(f"✅ Model trained on {len(emails)} emails!")

    # INTERACTIVE MENU
    print("\n" + "="*70)
    print("INTERACTIVE TEST")
    print("1. Enter email manually")
    print("2. Load email from file (.txt/.eml)")
    print("Type 'exit' anytime to quit")
    print("="*70)

    while True:
        choice = input("\nChoose option (1/2): ")

        if choice.lower() == "exit":
            break

        # 🔹 Manual input
        if choice == "1":
            subject = input("Subject: ")
            if subject.lower() == "exit": break

            body = input("Body: ")
            if body.lower() == "exit": break

            sender = input("Sender: ")
            if sender.lower() == "exit": break

            email = {
                'subject': subject,
                'body': body,
                'sender': sender
            }

        # 🔹 File input
        elif choice == "2":
            file_path = input("Enter full file path: ")
            if file_path.lower() == "exit": break

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                email = {
                    'subject': content,
                    'body': content,
                    'sender': "unknown"
                }

            except Exception as e:
                print(f"❌ Error reading file: {e}")
                continue

        else:
            print("❌ Invalid option. Choose 1 or 2.")
            continue

        # 🔍 ML Prediction
        result = detector.predict(email)

        # 🔍 Rule-based detection (optional)
        rules = check_phishing_indicators(email)

        print("\n🔍 Result:", result['prediction'])
        print(f"Confidence: {result['confidence']*100:.2f}%")

        if rules['score'] > 0:
            print("\n⚠️ Indicators:")
            if rules['keywords']:
                print("   Keywords:", ", ".join(rules['keywords']))
            if rules['domains']:
                print("   Domains:", ", ".join(rules['domains']))

        # 🔥 FINAL DECISION (use ML mainly)
        if result['is_phishing']:
            print("\n🚨 PHISHING EMAIL DETECTED")
        else:
            print("\n✅ LEGITIMATE EMAIL")

        again = input("\nTest another email? (y/n): ")
        if again.lower() != 'y':
            print("Exiting... 👋")
            break


if __name__ == "__main__":
    main()
