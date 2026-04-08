from detector import PhishingDetector
import re
import requests
from urllib.parse import urlparse
import email
from email import policy


# ----------------------------
# DOMAIN REPUTATION
# ----------------------------
def check_domain_reputation(domain):
    suspicious = ["phish", "scam", "malware"]
    return any(word in domain for word in suspicious)


# ----------------------------
# RULE-BASED DETECTION
# ----------------------------
def check_phishing_indicators(email_data):
    keywords = ["urgent", "verify", "login", "password", "bank", "free"]

    text = (email_data['subject'] + " " + email_data['body']).lower()
    hits = [w for w in keywords if re.search(rf"\b{w}\b", text)]

    return len(hits), hits


# ----------------------------
# URL ANALYSIS
# ----------------------------
def analyze_urls(email_data):
    text = (email_data['subject'] + " " + email_data['body']).lower()
    urls = re.findall(r'https?://\S+|www\.\S+', text)

    score = 0
    flags = []

    sender_domain = email_data['sender'].split("@")[-1] if "@" in email_data['sender'] else ""

    for url in urls:
        parsed = urlparse(url if url.startswith("http") else "http://" + url)
        domain = parsed.netloc

        if re.match(r"\d+\.\d+\.\d+\.\d+", domain):
            score += 2
            flags.append("IP-based URL")

        if any(x in domain for x in ["bit.ly", "tinyurl"]):
            score += 2
            flags.append("Shortened URL")

        if url.startswith("http://"):
            score += 1
            flags.append("Not secure (HTTP)")

        if len(url) > 75:
            score += 1
            flags.append("Long URL")

        if sender_domain and sender_domain not in domain:
            score += 2
            flags.append("Sender mismatch")

        if check_domain_reputation(domain):
            score += 3
            flags.append("Bad domain reputation")

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
# FINAL DECISION
# ----------------------------
def final_decision(ml, r, u, h):
    total = r + u + h
    combined = (0.6 * ml["final_score"]) + (0.4 * (total / 10))

    if combined > 0.75:
        level = "HIGH RISK"
    elif combined > 0.5:
        level = "MEDIUM RISK"
    else:
        level = "LOW RISK"

    label = "PHISHING" if combined > 0.5 else "SAFE"

    return label, level, combined


# ----------------------------
# PROCESS FUNCTION (FIXED)
# ----------------------------
def process_emails(detector, emails):
    print("\n=== RESULTS ===\n")

    for i, email_data in enumerate(emails):
        ml = detector.predict(email_data)

        r, keywords = check_phishing_indicators(email_data)
        u, url_flags = analyze_urls(email_data)
        h, header_flags = analyze_headers(email_data)

        label, level, score = final_decision(ml, r, u, h)

        print(f"\n📧 Email {i+1}")
        print("ML:", ml["prediction"])
        print("Confidence:", round(ml["confidence"] * 100, 2), "%")
        print("Risk Level:", level)

        if keywords:
            print("⚠️ Keywords:", keywords)
        if url_flags:
            print("⚠️ URL Issues:", url_flags)
        if header_flags:
            print("📧 Header Issues:", header_flags)

        print("🚨 FINAL:", label)
        print("-" * 40)


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
        except:
            print("❌ Failed:", url)

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

            body = ""
            if msg.is_multipart():
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
                    "spf": "pass",
                    "dkim": "pass"
                }
            })
        except:
            print("❌ Error reading:", path)

    return emails


# ----------------------------
# MAIN MENU
# ----------------------------
def main():
    detector = PhishingDetector()
    detector.load_model()

    while True:
        print("\n1. Single Email")
        print("2. Batch Manual (5)")
        print("3. 5 Emails from URLs")
        print("4. 5 Emails from .eml files")
        print("exit")

        choice = input("Choice: ")

        if choice == "exit":
            break

        elif choice == "1":
            email_data = {
                "subject": input("Subject: "),
                "body": input("Body: "),
                "sender": input("Sender: "),
                "headers": {
                    "from": input("From: "),
                    "reply_to": input("Reply-To: "),
                    "spf": input("SPF: "),
                    "dkim": input("DKIM: ")
                }
            }

            process_emails(detector, [email_data])

        elif choice == "2":
            emails = []
            for i in range(5):
                print(f"\nEmail {i+1}")
                emails.append({
                    "subject": input("Subject: "),
                    "body": input("Body: "),
                    "sender": input("Sender: ")
                })

            process_emails(detector, emails)

        elif choice == "3":
            print("\nEnter 5 URLs:\n")
            urls = [input(f"URL {i+1}: ") for i in range(5)]
            emails = load_emails_from_urls(urls)
            process_emails(detector, emails)

        elif choice == "4":
            print("\nEnter 5 .eml file paths:\n")
            paths = [input(f"File {i+1}: ") for i in range(5)]
            emails = load_emails_from_eml(paths)
            process_emails(detector, emails)

        else:
            print("❌ Invalid choice")


if __name__ == "__main__":
    main()
