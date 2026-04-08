import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle

# Load dataset
df = pd.read_csv("data/emails.csv")

X = df["text"]
y = df["label"]

# Convert text → numbers
vectorizer = TfidfVectorizer()
X_tfidf = vectorizer.fit_transform(X)

# Train model
model = MultinomialNB()
model.fit(X_tfidf, y)

# Save model
pickle.dump(model, open("model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("Model trained successfully")
