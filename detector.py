import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score


class PhishingDetector:
    def __init__(self):
        # Vectorizer
        self.vectorizer = TfidfVectorizer(max_features=2000, stop_words='english')

        # Models
        self.nb = MultinomialNB()
        self.lr = LogisticRegression(max_iter=1000)
        self.rf = RandomForestClassifier(n_estimators=100)

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

        # Clean text
        text = f"{subject} {body} {sender}"
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

        score = sum(word in text for word in keywords)
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
    # SINGLE PREDICTION
    # ----------------------------
    def predict(self, email):
        if not self.is_trained:
            self.load_model()

        features = self.extract_features(email)
        X = self.vectorizer.transform([features])

        pred = self.model.predict(X)[0]
        probs = self.model.predict_proba(X)[0]

        rule = self.rule_score(email)

        # Hybrid score
        final_score = 0.7 * probs[1] + 0.3 * rule

        result = "PHISHING" if final_score > 0.5 else "LEGITIMATE"

        return {
            "prediction": result,
            "ml_score": float(probs[1]),
            "rule_score": float(rule),
            "final_score": float(final_score),
            "confidence": float(max(probs))
        }

    # ----------------------------
    # BATCH PREDICTION (MULTIPLE INPUTS)
    # ----------------------------
    def predict_batch(self, emails):
        if not self.is_trained:
            self.load_model()

        features = [self.extract_features(e) for e in emails]
        X = self.vectorizer.transform(features)

        preds = self.model.predict(X)
        probs = self.model.predict_proba(X)

        results = []

        for i, email in enumerate(emails):
            rule = self.rule_score(email)
            final_score = 0.7 * probs[i][1] + 0.3 * rule

            result = "PHISHING" if final_score > 0.5 else "LEGITIMATE"

            results.append({
                "email_index": i + 1,
                "prediction": result,
                "ml_score": float(probs[i][1]),
                "rule_score": float(rule),
                "final_score": float(final_score)
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
    # SAVE / LOAD
    # ----------------------------
    def save_model(self):
        pickle.dump(self.model, open("model.pkl", "wb"))
        pickle.dump(self.vectorizer, open("vectorizer.pkl", "wb"))
        print("Model saved")

    def load_model(self):
        try:
            self.model = pickle.load(open("model.pkl", "rb"))
            self.vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
            self.is_trained = True
            print("Model loaded")
        except:
            print("Model not found")
            self.is_trained = False
