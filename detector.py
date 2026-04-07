import pickle
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

class PhishingDetector:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.model = MultinomialNB()
        self.is_trained = False
    
    def extract_features(self, email):
        """Extract and preprocess email text features"""
        subject = email.get('subject', '').lower()
        body = email.get('body', '').lower()
        sender = email.get('sender', '').lower()
        combined_text = f"{subject} {body} {sender}"
        return combined_text
    
    def train(self, emails, labels):
        """Train the phishing detector model"""
        features = [self.extract_features(email) for email in emails]
        X = self.vectorizer.fit_transform(features)
        self.model.fit(X, labels)
        self.is_trained = True
        print(f"Model trained on {len(emails)} emails")
    
    def predict(self, email):
        """Predict if an email is phishing or legitimate"""
        if not self.is_trained:
            self.load_model()
        
        features = self.extract_features(email)
        X = self.vectorizer.transform([features])
        prediction = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]
        
        confidence = max(probabilities)
        phishing_score = probabilities[1]
        legitimate_score = probabilities[0]
        
        return {
            'is_phishing': bool(prediction),
            'prediction': 'PHISHING' if prediction else 'LEGITIMATE',
            'confidence': confidence,
            'phishing_score': phishing_score,
            'legitimate_score': legitimate_score
        }
    
    def evaluate(self, emails, labels):
        """Evaluate model performance"""
        features = [self.extract_features(email) for email in emails]
        X = self.vectorizer.transform(features)
        predictions = self.model.predict(X)
        
        return {
            'accuracy': accuracy_score(labels, predictions),
            'precision': precision_score(labels, predictions, zero_division=0),
            'recall': recall_score(labels, predictions, zero_division=0),
            'f1_score': f1_score(labels, predictions, zero_division=0)
        }
    
    def save_model(self, model_path='trained_model.pkl', vectorizer_path='vectorizer.pkl'):
        """Save the trained model and vectorizer"""
        with open(model_path, 'wb') as f:
            pickle.dump(self.model, f)
        with open(vectorizer_path, 'wb') as f:
            pickle.dump(self.vectorizer, f)
        print(f"Model saved to {model_path} and {vectorizer_path}")
    
    def load_model(self, model_path='trained_model.pkl', vectorizer_path='vectorizer.pkl'):
        """Load a trained model and vectorizer"""
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)
            self.is_trained = True
            print(f"Model loaded")
        except FileNotFoundError:
            print(f"Model files not found.")
            self.is_trained = False
