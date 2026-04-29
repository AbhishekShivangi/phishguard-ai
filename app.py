from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
import re

app = Flask(__name__)
CORS(app)

# Load models
url_model = pickle.load(open("../ml_model/url_model.pkl", "rb"))
sms_model = pickle.load(open("../ml_model/sms_model.pkl", "rb"))
vectorizer = pickle.load(open("../ml_model/vectorizer.pkl", "rb"))

FEATURE_NAMES = ["length", "keyword_hits"]

def extract_features(url):
    keywords = ["login", "verify", "bank"]
    return [
        len(url),
        sum(k in url.lower() for k in keywords)
    ]

# ---------------- URL PREDICT ----------------
@app.route("/predict/url", methods=["POST"])
def predict_url():
    data = request.json
    url = data["url"]

    features = extract_features(url)
    pred = url_model.predict([features])[0]
    prob = url_model.predict_proba([features])[0]

    confidence = round(max(prob)*100, 2)

    label = "Safe" if pred == 0 else "Dangerous"

    reasons = []
    if len(url) > 75:
        reasons.append("Long URL")
    if "login" in url:
        reasons.append("Contains login keyword")

    return jsonify({
        "prediction": label,
        "confidence": confidence,
        "reasons": reasons
    })

# ---------------- SMS PREDICT ----------------
@app.route("/predict/text", methods=["POST"])
def predict_text():
    data = request.json
    text = data["text"]

    X = vectorizer.transform([text])
    pred = sms_model.predict(X)[0]
    prob = sms_model.predict_proba(X)[0]

    confidence = round(max(prob)*100, 2)

    label = "Safe" if pred == 0 else "Dangerous"

    return jsonify({
        "prediction": label,
        "confidence": confidence
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
