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

    try:
        return 1 if int(v) == 1 else 0
    except:
        return 0


# ----------------------------
# LOAD ANY DATASET (FIXED)
# ----------------------------
def load_dataset(path):
    df = pd.read_csv(path)
    df.dropna(inplace=True)

    emails = []
    labels = []

    for _, row in df.iterrows():

        # ----------------------------
        # CASE 1: subject + body
        # ----------------------------
        if "subject" in df.columns and "body" in df.columns:
            subject = str(row["subject"]).strip()
            body = str(row["body"]).strip()

        # ----------------------------
        # CASE 2: combined text
        # ----------------------------
        elif "text_combined" in df.columns:
            subject = ""
            body = str(row["text_combined"]).strip()

        # ----------------------------
        # CASE 3: fallback
        # ----------------------------
        else:
            continue

        if not body:
            continue

        # ----------------------------
        # LABEL
        # ----------------------------
        if "label" in df.columns:
            label = row["label"]
        else:
            continue

        label = normalize_label(label)

        emails.append({
            "subject": subject,
            "body": body,
            "sender": "unknown"
        })

        labels.append(label)

    print(f"Loaded {len(emails)} from {path}")
    return emails, labels


# ----------------------------
# MAIN
# ----------------------------
def main():
    print("📚 Loading datasets...")

    emails_all = []
    labels_all = []

    # Load CEAS if exists
    if os.path.exists("CEAS_08.csv"):
        e, l = load_dataset("CEAS_08.csv")
        emails_all += e
        labels_all += l
    else:
        print("⚠️ CEAS_08.csv not found")

    # Load all CSVs inside /data folder
    if os.path.exists("data"):
        for file in os.listdir("data"):
            if file.endswith(".csv"):
                path = os.path.join("data", file)
                e, l = load_dataset(path)
                emails_all += e
                labels_all += l
    else:
        print("⚠️ data folder not found")

    print(f"\n📊 Total dataset size: {len(emails_all)}")

    # Safety check
    if len(emails_all) == 0:
        print("❌ No data loaded. Check dataset files.")
        return

    # Shuffle data
    emails_all, labels_all = shuffle(emails_all, labels_all, random_state=42)

    # Dataset stats (for viva)
    print("\n📈 Dataset stats:")
    print(f"Total: {len(labels_all)}")
    print(f"Phishing: {sum(labels_all)}")
    print(f"Safe: {len(labels_all) - sum(labels_all)}")

    # Train
    detector = PhishingDetector()
    detector.train(emails_all, labels_all)

    # Save model
    detector.save_model()

    print("\n✅ Training complete! Model ready.")


if __name__ == "__main__":
    main()
