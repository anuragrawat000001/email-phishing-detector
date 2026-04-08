from detector import PhishingDetector
import pandas as pd
import os
from sklearn.utils import shuffle


# ----------------------------
# NORMALIZE LABEL
# ----------------------------
def normalize_label(value):
    v = str(value).strip().lower()

    if v in ["1", "spam", "phishing", "true", "yes"]:
        return 1
    if v in ["0", "ham", "legit", "legitimate", "false", "no"]:
        return 0

    # fallback (numeric)
    try:
        return 1 if int(v) == 1 else 0
    except:
        return 0


# ----------------------------
# LOAD CEAS DATASET
# ----------------------------
def load_ceas(path="CEAS_08.csv"):
    df = pd.read_csv(path)
    df.dropna(inplace=True)

    emails, labels = [], []

    for _, row in df.iterrows():
        subject = str(row.get("subject", row.get("text", "")))
        body = str(row.get("body", ""))

        label = normalize_label(row.get("label", 0))

        emails.append({
            "subject": subject,
            "body": body,
            "sender": "unknown"
        })
        labels.append(label)

    print(f"CEAS loaded: {len(emails)}")
    return emails, labels


# ----------------------------
# LOAD KAGGLE DATASET (AUTO DETECT)
# ----------------------------
def load_kaggle(path):
    df = pd.read_csv(path)
    df.dropna(inplace=True)

    emails, labels = [], []

    for _, row in df.iterrows():
        # Detect text column
        if "text" in df.columns:
            text = str(row["text"])
        elif "message" in df.columns:
            text = str(row["message"])
        elif "email" in df.columns:
            text = str(row["email"])
        else:
            continue

        # Detect label column
        if "label" in df.columns:
            label = row["label"]
        elif "spam" in df.columns:
            label = row["spam"]
        elif "target" in df.columns:
            label = row["target"]
        else:
            continue

        label = normalize_label(label)

        emails.append({
            "subject": "",
            "body": text,
            "sender": "unknown"
        })
        labels.append(label)

    print(f"Loaded {len(emails)} from {path}")
    return emails, labels


# ----------------------------
# MAIN TRAIN FUNCTION
# ----------------------------
def main():
    print("📚 Loading datasets...")

    emails_all = []
    labels_all = []

    # Load CEAS
    if os.path.exists("CEAS_08.csv"):
        e, l = load_ceas()
        emails_all += e
        labels_all += l
    else:
        print("⚠️ CEAS_08.csv not found")

    # Load Kaggle datasets
    if os.path.exists("data"):
        for file in os.listdir("data"):
            if file.endswith(".csv"):
                path = os.path.join("data", file)
                e, l = load_kaggle(path)
                emails_all += e
                labels_all += l
    else:
        print("⚠️ data/ folder not found")

    print(f"\nTotal dataset size: {len(emails_all)}")

    # Safety check
    if len(emails_all) == 0:
        print("❌ No dataset loaded. Add CSV files.")
        return

    # Shuffle dataset
    emails_all, labels_all = shuffle(emails_all, labels_all, random_state=42)

    # Train model
    detector = PhishingDetector()
    detector.train(emails_all, labels_all)

    # Save model
    detector.save_model()

    print("\n✅ Training complete! Model ready.")


if __name__ == "__main__":
    main()
