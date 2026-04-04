from detector import PhishingDetector

def main():
    print("="*70)
    print("EMAIL PHISHING DETECTOR - LIVE DEMO")
    print("="*70)
    
    # Initialize detector
    detector = PhishingDetector()
    
    # Sample legitimate emails
    legitimate_emails = [
        {
            'subject': 'Your order has been confirmed',
            'body': 'Thank you for your purchase. Your order #12345 has been confirmed and will be shipped soon.',
            'sender': 'orders@amazon.com'
        },
        {
            'subject': 'Meeting scheduled for tomorrow',
            'body': 'Hi, this is to confirm our meeting tomorrow at 2 PM.',
            'sender': 'boss@company.com'
        }
    ]
    
    # Sample phishing emails
    phishing_emails = [
        {
            'subject': 'URGENT: Verify your account immediately',
            'body': 'Click here to verify your account or it will be closed.',
            'sender': 'security@paypa1.com'
        },
        {
            'subject': 'You have won a prize!',
            'body': 'Congratulations! Click here to claim your prize.',
            'sender': 'lottery@winner.com'
        }
    ]
    
    # Train model
    print("\n📚 Training the model...")
    all_emails = legitimate_emails + phishing_emails
    labels = [0]*len(legitimate_emails) + [1]*len(phishing_emails)
    
    detector.train(all_emails, labels)
    detector.save_model()
    
    print("\n✅ Model ready!")

    # 🔥 INTERACTIVE LOOP STARTS HERE
    print("\n" + "="*70)
    print("INTERACTIVE TEST - Enter your own emails")
    print("Type 'exit' anytime to quit")
    print("="*70)

    while True:
        print("\n--- Enter Email Details ---")
        
        subject = input("Subject: ")
        if subject.lower() == "exit":
            break
            
        body = input("Body: ")
        if body.lower() == "exit":
            break
            
        sender = input("Sender: ")
        if sender.lower() == "exit":
            break

        email = {
            'subject': subject,
            'body': body,
            'sender': sender
        }

        result = detector.predict(email)

        print("\n🔍 Result:", result['prediction'])
        print(f"Confidence: {result['confidence']*100:.2f}%")
        print(f"Phishing Score: {result['phishing_score']:.4f}")
        print(f"Legitimate Score: {result['legitimate_score']:.4f}")

        if result['is_phishing']:
            print("\n⚠️ This email shows phishing characteristics!")
        else:
            print("\n✅ This email appears legitimate")

        choice = input("\nTest another email? (y/n): ")
        if choice.lower() != 'y':
            print("Exiting... 👋")
            break


if __name__ == "__main__":
    main()
