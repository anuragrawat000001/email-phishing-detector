import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class PhishingDetector:
    def __init__(self):
        # Text vectorizer
        self.vectorizer = TfidfVectorizer(max_features=2000, stop_words='english')

        # Models
        self.nb = MultinomialNB()
        self.lr = LogisticRegression(max_iter=1000)
        self.rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)

        # Ensemble model
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
        text = re.sub(r"http\S+", "", text)
        text = re.sub(r"[^a-zA-Z]", " ", text)

        return text

    # ----------------------------
    # RULE-BASED SCORE
    # ----------------------------
    def rule_score(self, email):
        text = self.extract_features(email)

        keywords = [
            "urgent", "verify", "login", "password",
            "bank", "account", "click", "suspend"
        ]

        score = sum(re.search(rf"\b{word}\b", text) is not None for word in keywords)
        return score / len(keywords)

    # ----------------------------
    # TRAIN MODEL
    # ----------------------------
    def train(self, emails, labels):
        features = [self.extract_features(e) for e in emails]

        X = self.vectorizer.fit_transform(features)
        self.model.fit(X, labels)

        self.is_trained = True
        print(f"Model trained on {len(emails)} emails")

    # ----------------------------
    # SINGLE PREDICTION
    # ----------------------------
    def predict(self, email):
        if not self.is_trained:
            self.load_model()
            if not self.is_trained:
                raise Exception("Model not trained. Train or load model first.")

        features = self.extract_features(email)
        X = self.vectorizer.transform([features])

        pred = self.model.predict(X)[0]

        # Safe probability handling
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)[0]
        else:
            probs = [1 - pred, pred]

        rule = self.rule_score(email)

        # Hybrid scoring
        final_score = 0.7 * probs[1] + 0.3 * rule
        result = "PHISHING" if final_score > 0.5 else "LEGITIMATE"

        # Explainability (reasons)
        keywords = ["urgent", "verify", "login", "password", "bank", "click"]
        reasons = [word for word in keywords if word in features]

        return {
            "prediction": result,
            "ml_score": float(probs[1]),
            "rule_score": float(rule),
            "final_score": float(final_score),
            "confidence": float(max(probs)),
            "reasons": reasons
        }

    # ----------------------------
    # BATCH PREDICTION
    # ----------------------------
    def predict_batch(self, emails):
        if not self.is_trained:
            self.load_model()
            if not self.is_trained:
                raise Exception("Model not trained.")

        features = [self.extract_features(e) for e in emails]
        X = self.vectorizer.transform(features)

        preds = self.model.predict(X)

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X)
        else:
            probs = [[1 - p, p] for p in preds]

        results = []

        for i, email in enumerate(emails):
            rule = self.rule_score(email)
            final_score = 0.7 * probs[i][1] + 0.3 * rule

            result = "PHISHING" if final_score > 0.5 else "LEGITIMATE"

            keywords = ["urgent", "verify", "login", "password", "bank", "click"]
            reasons = [word for word in keywords if word in features[i]]

            results.append({
                "email_index": i + 1,
                "prediction": result,
                "ml_score": float(probs[i][1]),
                "rule_score": float(rule),
                "final_score": float(final_score),
                "reasons": reasons
            })

        return results

    # ----------------------------
    # EVALUATION
    # ----------------------------
    def evaluate(self, emails, labels):
        features = [self.extract_features(e) for e in emails]
        X = self.vectorizer.transform(features)
        preds = self.model.predict(X)

        return {
            "accuracy": accuracy_score(labels, preds),
            "precision": precision_score(labels, preds, zero_division=0),
            "recall": recall_score(labels, preds, zero_division=0),
            "f1_score": f1_score(labels, preds, zero_division=0)
        }

    # ----------------------------
    # SAVE MODEL
    # ----------------------------
    def save_model(self):
        pickle.dump(self.model, open("model.pkl", "wb"))
        pickle.dump(self.vectorizer, open("vectorizer.pkl", "wb"))
        print("Model saved successfully")

    # ----------------------------
    # LOAD MODEL
    # ----------------------------
    def load_model(self):
        try:
            self.model = pickle.load(open("model.pkl", "rb"))
            self.vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
            self.is_trained = True
            print("Model loaded successfully")
        except FileNotFoundError:
            print("Model files not found. Please train first.")
            self.is_trained = False
