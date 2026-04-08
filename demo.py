from detector import PhishingDetector
import pandas as pd
import re
import requests
from urllib.parse import urlparse
import email
from email import policy


# ----------------------------
# RULE-BASED DETECTION
# ----------------------------
def check_phishing_indicators(email_data):
    suspicious_keywords = [
        "urgent", "verify", "login", "password", "bank",
        "confirm", "update", "free", "winner"
    ]

    text = (email_data['subject'] + " " + email_data['body']).lower()
    hits = [w for w in suspicious_keywords if re.search(rf"\b{w}\b", text)]

    return len(hits), hits


# ----------------------------
# URL ANALYSIS
# ----------------------------
def analyze_urls(email_data):
    text = (email_data['subject'] + " " + email_data['body']).lower()
    urls = re.findall(r'https?://\S+|www\.\S+', text)

    score = 0
    flags = []

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            score += 2
            flags.append("IP-based URL")

        if "bit.ly" in domain or "tinyurl" in domain:
            score += 2
            flags.append("Shortened URL")

    return score, flags


# ----------------------------
# HEADER ANALYSIS
# ----------------------------
def analyze_headers(email_data):
    headers = email_data.get("headers", {})
    score = 0
    issues = []

    if headers.get("from") != headers.get("reply_to"):
        score += 2
        issues.append("From != Reply-To")

    if headers.get("spf") == "fail":
        score += 2
        issues.append("SPF failed")

    if headers.get("dkim") == "fail":
        score += 2
        issues.append("DKIM failed")

    return score, issues


# ----------------------------
# LOAD FROM URLS
# ----------------------------
def load_emails_from_urls(urls):
    emails = []

    for url in urls:
        try:
            res = requests.get(url, timeout=5)
            content = res.text

            emails.append({
                "subject": content[:50],
                "body": content,
                "sender": "unknown",
                "headers": {}
            })

        except Exception as e:
            print("Error loading:", url)

    return emails


# ----------------------------
# LOAD FROM .EML FILES
# ----------------------------
def load_emails_from_eml(paths):
    emails = []

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as f:
                msg = email.message_from_file(f, policy=policy.default)

            subject = str(msg["subject"])
            sender = str(msg["from"])

            # Extract body
            if msg.is_multipart():
                body = ""
                for part in msg.walk():
                    if part.get_content_type() == "text/plain":
                        body += part.get_content()
            else:
                body = msg.get_content()

            emails.append({
                "subject": subject,
                "body": body,
                "sender": sender,
                "headers": {
                    "from": sender,
                    "reply_to": str(msg.get("reply-to", "")),
                    "return_path": str(msg.get("return-path", "")),
                    "spf": "pass",
                    "dkim": "pass"
                }
            })

        except Exception as e:
            print("Error reading file:", path)

    return emails


# ----------------------------
# MAIN
# ----------------------------
def main():
    detector = PhishingDetector()
    detector.load_model()

    while True:
        print("\n1. Single Email")
        print("2. Batch Manual")
        print("3. Batch from URLs")
        print("4. Batch from .eml files")
        print("exit")

        choice = input("Choice: ")

        if choice == "exit":
            break

        # ---------------- SINGLE ----------------
        if choice == "1":
            email_data = {
                "subject": input("Subject: "),
                "body": input("Body: "),
                "sender": input("Sender: "),
                "headers": {
                    "from": input("From: "),
                    "reply_to": input("Reply-To: "),
                    "spf": input("SPF (pass/fail): "),
                    "dkim": input("DKIM (pass/fail): ")
                }
            }

            ml = detector.predict(email_data)
            r_score, _ = check_phishing_indicators(email_data)
            u_score, _ = analyze_urls(email_data)
            h_score, _ = analyze_headers(email_data)

            total = r_score + u_score + h_score

            print("\nPrediction:", ml["prediction"])

            if ml["final_score"] > 0.6 or total >= 4:
                print("🚨 PHISHING")
            else:
                print("✅ SAFE")

        # ---------------- MANUAL BATCH ----------------
        elif choice == "2":
            emails = []

            for i in range(5):
                emails.append({
                    "subject": input("Subject: "),
                    "body": input("Body: "),
                    "sender": input("Sender: ")
                })

            results = detector.predict_batch(emails)

            for i, r in enumerate(results):
                print(f"Email {i+1}: {r['prediction']}")

        # ---------------- URL BATCH ----------------
        elif choice == "3":
            urls = [input(f"URL {i+1}: ") for i in range(5)]

            emails = load_emails_from_urls(urls)
            results = detector.predict_batch(emails)

            for i, r in enumerate(results):
                print(f"URL Email {i+1}: {r['prediction']}")

        # ---------------- EML FILE BATCH ----------------
        elif choice == "4":
            paths = [input(f"File path {i+1}: ") for i in range(5)]

            emails = load_emails_from_eml(paths)
            results = detector.predict_batch(emails)

            for i, r in enumerate(results):
                print(f"File Email {i+1}: {r['prediction']}")

        else:
            print("Invalid option")


if __name__ == "__main__":
    main()
