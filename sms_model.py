# SMS PHISHING MODEL (TF-IDF + Naive Bayes)

import pandas as pd
import pickle
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# Sample dataset (replace with Kaggle dataset later)
data = [
    ("Win ₹5000 now click here http://fake.com", 1),
    ("Your OTP is 123456", 0),
    ("Verify your bank account immediately", 1),
    ("Meeting at 5pm", 0)
]

df = pd.DataFrame(data, columns=["text", "label"])

vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(df["text"])
y = df["label"]

model = MultinomialNB()
model.fit(X, y)

pickle.dump(model, open("sms_model.pkl", "wb"))
pickle.dump(vectorizer, open("vectorizer.pkl", "wb"))

print("✅ SMS model trained")
