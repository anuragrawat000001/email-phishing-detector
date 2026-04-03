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
            'body': 'Hi, this is to confirm our meeting tomorrow at 2 PM. Please find the agenda attached.',
            'sender': 'boss@company.com'
        },
        {
            'subject': 'Welcome to our service',
            'body': 'Welcome! Your account has been created successfully. You can now log in with your credentials.',
            'sender': 'support@gmail.com'
        },
        {
            'subject': 'Invoice for January 2026',
            'body': 'Please find the attached invoice for your January subscription. Thank you for your business.',
            'sender': 'billing@service.com'
        }
    ]
    
    # Sample phishing emails
    phishing_emails = [
        {
            'subject': 'URGENT: Verify your account immediately',
            'body': 'Click here to verify your account or it will be closed. Verify now: click-here-to-verify.com',
            'sender': 'security@paypa1.com'
        },
        {
            'subject': 'Confirm your identity to unlock account',
            'body': 'Your account has been locked. Please confirm your identity by clicking the link and entering your password.',
            'sender': 'noreply@bankk.com'
        },
        {
            'subject': 'You have won a prize!',
            'body': 'Congratulations! You have won $1,000,000. Click here to claim your prize and provide your banking details.',
            'sender': 'lottery@winner.com'
        },
        {
            'subject': 'Suspicious activity detected',
            'body': 'We detected suspicious login attempts. Click here urgently to verify it is you: http://confirm-now.xyz',
            'sender': 'alerts@paypalll.com'
        }
    ]
    
    # Train model
    print("\n📚 Training the model with sample data...")
    all_emails = legitimate_emails + phishing_emails
    labels = [0] * len(legitimate_emails) + [1] * len(phishing_emails)
    
    detector.train(all_emails, labels)
    detector.save_model()
    
    # Test on legitimate emails
    print("\n" + "="*70)
    print("TESTING ON LEGITIMATE EMAILS ✅")
    print("="*70)
    
    for i, email in enumerate(legitimate_emails, 1):
        result = detector.predict(email)
        status = "✅ CORRECT" if not result['is_phishing'] else "❌ WRONG"
        print(f"\n📧 Email {i}: {status}")
        print(f"   Subject: {email['subject']}")
        print(f"   Prediction: {result['prediction']}")
        print(f"   Confidence: {result['confidence']*100:.2f}%")
        print(f"   Scores - Phishing: {result['phishing_score']:.4f} | Legitimate: {result['legitimate_score']:.4f}")
    
    # Test on phishing emails
    print("\n" + "="*70)
    print("TESTING ON PHISHING EMAILS 🚨")
    print("="*70)
    
    for i, email in enumerate(phishing_emails, 1):
        result = detector.predict(email)
        status = "✅ CORRECT" if result['is_phishing'] else "❌ WRONG"
        print(f"\n📧 Email {i}: {status}")
        print(f"   Subject: {email['subject']}")
        print(f"   Prediction: {result['prediction']}")
        print(f"   Confidence: {result['confidence']*100:.2f}%")
        print(f"   Scores - Phishing: {result['phishing_score']:.4f} | Legitimate: {result['legitimate_score']:.4f}")
    
    # Model Evaluation
    print("\n" + "="*70)
    print("MODEL EVALUATION REPORT")
    print("="*70)
    
    metrics = detector.evaluate(all_emails, labels)
    print(f"\n📊 Performance Metrics:")
    print(f"   ✅ Accuracy:  {metrics['accuracy']*100:.2f}%")
    print(f"   ✅ Precision: {metrics['precision']*100:.2f}%")
    print(f"   ✅ Recall:    {metrics['recall']*100:.2f}%")
    print(f"   ✅ F1-Score:  {metrics['f1_score']:.4f}")
    
    print("\n" + "="*70)
    print("🎉 DEMO COMPLETED SUCCESSFULLY!")
    print("="*70)
    
    # Interactive test
    print("\n" + "="*70)
    print("INTERACTIVE TEST - Try your own email!")
    print("="*70)
    
    test_email = {
        'subject': 'Please update your payment information',
        'body': 'Your payment method has expired. Click here to update it immediately before your account is suspended.',
        'sender': 'billing@amazon-secure.com'
    }
    
    print(f"\nTest Email:")
    print(f"   Subject: {test_email['subject']}")
    print(f"   Body: {test_email['body']}")
    print(f"   Sender: {test_email['sender']}")
    
    result = detector.predict(test_email)
    print(f"\n🔍 Result: {result['prediction']}")
    print(f"   Confidence: {result['confidence']*100:.2f}%")
    print(f"   Phishing Score: {result['phishing_score']:.4f}")
    print(f"   Legitimate Score: {result['legitimate_score']:.4f}")
    
    if result['is_phishing']:
        print("\n⚠️  This email shows phishing characteristics!")
        print("   Indicators: Urgent language, payment request, suspicious domain")
    else:
        print("\n✅ This email appears to be legitimate")

if __name__ == "__main__":
    main()
