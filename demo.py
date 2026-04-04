from detector import PhishingDetector

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
    print("EMAIL PHISHING DETECTOR - LIVE DEMO")
    print("="*70)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Sample training data
    legitimate_emails = [
        {
            'subject': 'Your order has been confirmed',
            'body': 'Thank you for your purchase. Your order #12345 has been confirmed.',
            'sender': 'orders@amazon.com'
        },
        {
            'subject': 'Meeting scheduled for tomorrow',
            'body': 'Meeting tomorrow at 2 PM.',
            'sender': 'boss@company.com'
        }
    ]
    
    phishing_emails = [
        {
            'subject': 'URGENT: Verify your account',
            'body': 'Click here to verify your account immediately',
            'sender': 'security@paypa1.com'
        },
        {
            'subject': 'You have won a prize!',
            'body': 'Claim your reward now',
            'sender': 'lottery@fake.com'
        }
    ]
    
    # Train model
    print("\n📚 Training the model...")
    all_emails = legitimate_emails + phishing_emails
    labels = [0]*len(legitimate_emails) + [1]*len(phishing_emails)
    
    detector.train(all_emails, labels)
    detector.save_model()
    
    print("\n✅ Model ready!")

    # Interactive menu
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

        # 🔍 Rule-based detection
        rules = check_phishing_indicators(email)

        print("\n🔍 Result:", result['prediction'])
        print(f"Confidence: {result['confidence']*100:.2f}%")
        print(f"Phishing Score: {result['phishing_score']:.4f}")
        print(f"Legitimate Score: {result['legitimate_score']:.4f}")

        # Show indicators
        if rules['score'] > 0:
            print("\n⚠️ Suspicious Indicators Found:")
            if rules['keywords']:
                print("   Keywords:", ", ".join(rules['keywords']))
            if rules['domains']:
                print("   Suspicious Domains:", ", ".join(rules['domains']))

        # Final decision
        if result['is_phishing'] or rules['score'] > 2:
            print("\n🚨 HIGH RISK: This email is likely phishing!")
        else:
            print("\n✅ This email appears legitimate")

        again = input("\nTest another email? (y/n): ")
        if again.lower() != 'y':
            print("Exiting... 👋")
            break


if __name__ == "__main__":
    main()
