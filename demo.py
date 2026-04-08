from detector import PhishingDetector
import pandas as pd
import re
from urllib.parse import urlparse


# ----------------------------
# RULE-BASED DETECTION (IMPROVED)
# ----------------------------
def check_phishing_indicators(email):
    suspicious_keywords = [
        "urgent", "verify", "suspend", "click here", "login",
        "password", "bank", "account locked", "confirm",
        "update", "security alert", "limited time", "act now",
        "winner", "prize", "claim", "free", "lottery"
    ]

    suspicious_domains = ["paypa1", "gmai1", "amaz0n"]

    text = (email['subject'] + " " + email['body'] + " " + email['sender']).lower()

    keyword_hits = [word for word in suspicious_keywords if re.search(rf"\b{word}\b", text)]
    domain_hits = [domain for domain in suspicious_domains if domain in text]

    return len(keyword_hits) + len(domain_hits), keyword_hits, domain_hits


# ----------------------------
# URL ANALYSIS (FIXED)
# ----------------------------
def analyze_urls(email):
    text = (email['subject'] + " " + email['body']).lower()
    urls = re.findall(r'https?://\S+|www\.\S+', text)

    score = 0
    flags = []

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            score += 2
            flags.append(f"IP in URL: {domain}")

        if any(s in domain for s in ["bit.ly", "tinyurl", "goo.gl"]):
            score += 2
            flags.append(f"Shortened URL: {domain}")

        if any(x in url for x in ["login", "verify", "bank"]):
            score += 1
            flags.append(f"Suspicious keyword in URL")

    return score, flags, urls


# ----------------------------
# HEADER ANALYSIS
# ----------------------------
def analyze_headers(email):
    headers = email.get("headers", {})

    score = 0
    issues = []

    f = headers.get("from", "").lower()
    r = headers.get("reply_to", "").lower()
    rp = headers.get("return_path", "").lower()
    spf = headers.get("spf", "").lower()
    dkim = headers.get("dkim", "").lower()

    if f and r and f != r:
        score += 2
        issues.append("From != Reply-To")

    if rp and f and rp != f:
        score += 1
        issues.append("Return-Path mismatch")

    if spf == "fail":
        score += 2
        issues.append("SPF failed")

    if dkim == "fail":
        score += 2
        issues.append("DKIM failed")

    return score, issues


# ----------------------------
# TRAIN MODEL
# ----------------------------
def train_model():
    print("\n📚 Training model...")

    df = pd.read_csv("CEAS_08.csv")

    emails, labels = [], []

    for _, row in df.iterrows():
        emails.append({
            "subject": str(row.get("subject", row.get("text", ""))),
            "body": str(row.get("body", "")),
            "sender": "unknown"
        })
        labels.append(int(row["label"]))

    detector = PhishingDetector()
    detector.train(emails, labels)
    detector.save_model()

    print("✅ Training complete\n")


# ----------------------------
# MAIN
# ----------------------------
def main():
    detector = PhishingDetector()
    detector.load_model()

    if not detector.is_trained:
        train_model()
        detector.load_model()

    while True:
        print("\n1. Single email")
        print("2. Batch (5 emails)")
        print("exit to quit")

        choice = input("Choice: ")

        if choice == "exit":
            break

        # ---------------- SINGLE ----------------
        if choice == "1":
            email = {
                "subject": input("Subject: "),
                "body": input("Body: "),
                "sender": input("Sender: "),
                "headers": {
                    "from": input("From: "),
                    "reply_to": input("Reply-To: "),
                    "return_path": input("Return-Path: "),
                    "spf": input("SPF (pass/fail): "),
                    "dkim": input("DKIM (pass/fail): ")
                }
            }

            ml = detector.predict(email)
            rule_score, keywords, domains = check_phishing_indicators(email)
            url_score, url_flags, urls = analyze_urls(email)
            header_score, header_flags = analyze_headers(email)

            total = rule_score + url_score + header_score

            print("\n🔍 ML:", ml["prediction"])
            print("Confidence:", round(ml["confidence"]*100, 2), "%")

            if ml.get("reasons"):
                print("🧠 ML Reasons:", ml["reasons"])

            if keywords:
                print("⚠️ Keywords:", keywords)

            if domains:
                print("⚠️ Domains:", domains)

            if urls:
                print("🔗 URLs:", urls)

            if url_flags:
                print("⚠️ URL Issues:", url_flags)

            if header_flags:
                print("📧 Header Issues:", header_flags)

            # FINAL DECISION (IMPROVED)
            if ml["final_score"] > 0.6 or total >= 4:
                print("\n🚨 FINAL: PHISHING")
            else:
                print("\n✅ FINAL: SAFE")

        # ---------------- BATCH ----------------
        elif choice == "2":
            emails = []

            for i in range(5):
                print(f"\nEmail {i+1}")
                emails.append({
                    "subject": input("Subject: "),
                    "body": input("Body: "),
                    "sender": input("Sender: "),
                    "headers": {
                        "from": "",
                        "reply_to": "",
                        "return_path": "",
                        "spf": "pass",
                        "dkim": "pass"
                    }
                })

            results = detector.predict_batch(emails)

            print("\n=== RESULTS ===")

            for i, res in enumerate(results):
                rule_score, _, _ = check_phishing_indicators(emails[i])
                url_score, _, _ = analyze_urls(emails[i])
                header_score, _ = analyze_headers(emails[i])

                total = rule_score + url_score + header_score

                final = "PHISHING" if res["final_score"] > 0.6 or total >= 4 else "SAFE"

                print(f"Email {i+1}: {final} ({round(res['final_score']*100,2)}%)")

        else:
            print("❌ Invalid choice")


if __name__ == "__main__":
    main()
