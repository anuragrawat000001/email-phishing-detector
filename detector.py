import pickle
import re
import numpy as np

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class PhishingDetector:
    def __init__(self):
        # ----------------------------
        # TF-IDF (IMPROVED)
        # ----------------------------
        self.vectorizer = TfidfVectorizer(
            max_features=4000,
            ngram_range=(1, 2),
            stop_words='english'
        )

        # ----------------------------
        # MODELS (OPTIMIZED)
        # ----------------------------
        self.nb = MultinomialNB()

        self.lr = LogisticRegression(
            max_iter=1000,
            class_weight='balanced'
        )

        self.rf = RandomForestClassifier(
            n_estimators=50,   # reduced for speed
            max_depth=12,
            class_weight='balanced',
            random_state=42
        )

        # ----------------------------
        # ENSEMBLE (FAST + STRONG)
        # ----------------------------
        self.model = VotingClassifier(
            estimators=[
                ('nb', self.nb),
                ('lr', self.lr),
                ('rf', self.rf)
            ],
            voting='soft'
        )

        self.is_trained = False

    # ----------------------------
    # FEATURE EXTRACTION
    # ----------------------------
    def extract_features(self, email):
        subject = email.get('subject', '').lower()
        body = email.get('body', '').lower()
        sender = email.get('sender', '').lower()

        text = f"{subject} {body} {sender}"

        # Clean text
        text = re.sub(r"http\S+", " URL ", text)
        text = re.sub(r"[^a-zA-Z]", " ", text)

        # Add simple features
        features = []

        if "http" in body:
            features.append("HAS_URL")

        if body.count("!") > 2:
            features.append("EXCESSIVE_EXCLAMATION")

        if any(word in body for word in ["urgent", "verify", "login"]):
            features.append("SUSPICIOUS_WORD")

        return text + " " + " ".join(features)

    # ----------------------------
    # RULE SCORE
    # ----------------------------
    def rule_score(self, email):
        text = self.extract_features(email)

        keywords = [
            "urgent", "verify", "login", "password",
            "bank", "account", "click", "suspend"
        ]

        score = sum(bool(re.search(rf"\b{w}\b", text)) for w in keywords)
        return score / len(keywords)

    # ----------------------------
    # TRAIN
    # ----------------------------
    def train(self, emails, labels):
        features = [self.extract_features(e) for e in emails]

        X = self.vectorizer.fit_transform(features)
        self.model.fit(X, labels)

        self.is_trained = True
        print(f"Model trained on {len(emails)} emails")

    # ----------------------------
    # PREDICT SINGLE
    # ----------------------------
    def predict(self, email):
        if not self.is_trained:
            self.load_model()
            if not self.is_trained:
                raise Exception("Model not trained")

        features = self.extract_features(email)
        X = self.vectorizer.transform([features])

        pred = self.model.predict(X)[0]
        probs = self.model.predict_proba(X)[0]

        rule = self.rule_score(email)

        # Hybrid scoring
        combined = (0.6 * probs[1]) + (0.4 * rule)

        result = "PHISHING" if combined > 0.5 else "LEGITIMATE"

        return {
            "prediction": result,
            "ml_score": float(probs[1]),
            "rule_score": float(rule),
            "final_score": float(combined),
            "confidence": float(max(probs))
        }

    # ----------------------------
    # BATCH PREDICT
    # ----------------------------
    def predict_batch(self, emails):
        if not self.is_trained:
            self.load_model()
            if not self.is_trained:
                raise Exception("Model not trained")

        features = [self.extract_features(e) for e in emails]
        X = self.vectorizer.transform(features)

        probs = self.model.predict_proba(X)

        results = []

        for i, email in enumerate(emails):
            rule = self.rule_score(email)
            combined = (0.6 * probs[i][1]) + (0.4 * rule)

            result = "PHISHING" if combined > 0.5 else "LEGITIMATE"

            results.append({
                "email_index": i + 1,
                "prediction": result,
                "score": float(combined)
            })

        return results

    # ----------------------------
    # SAVE
    # ----------------------------
    def save_model(self):
        pickle.dump(self.model, open("model.pkl", "wb"))
        pickle.dump(self.vectorizer, open("vectorizer.pkl", "wb"))
        print("Model saved")

    # ----------------------------
    # LOAD
    # ----------------------------
    def load_model(self):
        try:
            self.model = pickle.load(open("model.pkl", "rb"))
            self.vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
            self.is_trained = True
            print("Model loaded")
        except:
            print("Train model first")
            self.is_trained = False
