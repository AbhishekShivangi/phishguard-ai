"""
api.py — Flask REST API for phishing detection.
Start with:  python api.py
Endpoint:    POST /predict   { "url": "https://example.com" }
"""

import os
import re
import time
import pickle
import socket
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# Import shared feature extractor from model.py
from model import extract_features, FEATURE_NAMES

# ─── Config ──────────────────────────────────
MODEL_PATH = "model.pkl"

TOP_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "twitter.com", "instagram.com",
    "linkedin.com", "apple.com", "microsoft.com", "amazon.com", "github.com",
    "netflix.com", "paypal.com", "yahoo.com", "bing.com", "reddit.com", "ebay.com",
    "wikipedia.org", "chatgpt.com", "openai.com", "whatsapp.com", "tiktok.com",
    "stackoverflow.com", "aws.amazon.com"
}
MODEL_PATH = "model.pkl"

app = Flask(__name__)
CORS(app)  # Allow Streamlit to call this API

# ─── Load model ──────────────────────────────
try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    print(f"[SUCCESS] Model loaded from {MODEL_PATH}")
except FileNotFoundError:
    model = None
    print("[WARNING] model.pkl not found — run python model.py first.")


# ─── External API (URLhaus) ─────────────────────

def check_urlhaus(url: str) -> dict:
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url}, timeout=5)
        data = r.json()
        if data.get("query_status") == "ok":
            threat = data.get("threat", "malware")
            return {"status": f"Threat detected: {threat}", "is_malicious": True, "source": "URLhaus"}
        return {"status": "No threats found", "is_malicious": False, "source": "URLhaus"}
    except Exception as e:
        return {"status": f"API error: {str(e)}", "is_malicious": False, "source": "URLhaus"}


# ─── Network info ─────────────────────────────

def get_network_info(url: str) -> dict:
    try:
        hostname = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        ip = socket.gethostbyname(hostname)
    except Exception:
        ip = "Unresolvable"

    start = time.time()
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True,
                            headers={"User-Agent": "Mozilla/5.0"})
        response_time  = round((time.time() - start) * 1000, 1)
        status_code    = resp.status_code
        final_url      = resp.url
        redirected     = (final_url.rstrip("/") != url.rstrip("/"))
        content_length = len(resp.content)
    except Exception as e:
        response_time  = -1
        status_code    = 0
        final_url      = url
        redirected     = False
        content_length = 0

    return {
        "ip":             ip,
        "response_time":  response_time,
        "status_code":    status_code,
        "final_url":      final_url,
        "redirected":     redirected,
        "content_length": content_length,
    }


# ─── Explainability ───────────────────────────

RISK_EXPLANATIONS = {
    "length":             ("Long URL",              "URLs longer than 75 chars are suspicious"),
    "has_https":          ("No HTTPS",              "Site does not use encrypted HTTPS"),
    "has_ip":             ("IP-based URL",          "URL uses a raw IP address instead of a domain"),
    "at_count":           ("@ symbol",              "@ in URL can redirect to a different host"),
    "double_slash":       ("Double slash",          "Unusual double-slash pattern detected"),
    "hyphen_count":       ("Excessive hyphens",     "Many hyphens often indicate spoofed domains"),
    "keyword_hits":       ("Suspicious keywords",   "Contains phishing keywords (login, bank, etc.)"),
    "has_suspicious_tld": ("Suspicious TLD",        "Domain uses a TLD commonly abused by attackers"),
    "digits_in_domain":   ("Digits in domain",      "Legitimate sites rarely have numbers in domain"),
    "subdomain_count":    ("Deep subdomains",       "Excessive subdomains can mask the real domain"),
    "percent_count":      ("URL encoding",          "Percent-encoding may be used to obfuscate the URL"),
}

def build_reasons(features: dict, prediction: int) -> list:
    reasons = []
    if features["length"] > 75:
        reasons.append(RISK_EXPLANATIONS["length"])
    if features["has_https"] == 0:
        reasons.append(RISK_EXPLANATIONS["has_https"])
    if features["has_ip"] == 1:
        reasons.append(RISK_EXPLANATIONS["has_ip"])
    if features["at_count"] > 0:
        reasons.append(RISK_EXPLANATIONS["at_count"])
    if features["double_slash"] and not features["has_https"] and not features["has_http"]:
        reasons.append(RISK_EXPLANATIONS["double_slash"])
    if features["hyphen_count"] > 3:
        reasons.append(RISK_EXPLANATIONS["hyphen_count"])
    if features["keyword_hits"] > 0:
        reasons.append(RISK_EXPLANATIONS["keyword_hits"])
    if features["has_suspicious_tld"]:
        reasons.append(RISK_EXPLANATIONS["has_suspicious_tld"])
    if features["digits_in_domain"] > 2:
        reasons.append(RISK_EXPLANATIONS["digits_in_domain"])
    if features["subdomain_count"] > 3:
        reasons.append(RISK_EXPLANATIONS["subdomain_count"])
    if features["percent_count"] > 2:
        reasons.append(RISK_EXPLANATIONS["percent_count"])

    if prediction == 0 and not reasons:
        reasons = [("All checks passed", "No suspicious patterns detected in this URL")]
    return [{"flag": r[0], "detail": r[1]} for r in reasons]


# ─── /predict endpoint ────────────────────────

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json(force=True)
    url  = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not re.match(r"https?://", url):
        url = "http://" + url

    if model is None:
        return jsonify({"error": "Model not loaded. Run python model.py first."}), 503

    # Extract base domain
    try:
        domain_part = re.sub(r"https?://", "", url).split("/")[0].split(":")[0]
        parts = domain_part.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain_part
    except:
        base_domain = ""

    # External API (URLhaus)
    api_result = check_urlhaus(url)

    if api_result["is_malicious"]:
        # Definitively malicious according to URLhaus
        prediction = 1
        confidence = 99.0
        label = "Phishing"
        features = extract_features(url)
        reasons = [{"flag": "External API", "detail": api_result["status"]}]
    elif base_domain in TOP_DOMAINS:
        # Whitelisted genuine site
        prediction = 0
        confidence = 99.0
        label = "Safe"
        features = extract_features(url)
        reasons = [{"flag": "Whitelisted Domain", "detail": f"{base_domain} is a known genuine website"}]
    else:
        # ML prediction
        features     = extract_features(url)
        feature_vec  = [[features[k] for k in FEATURE_NAMES]]
        prediction   = int(model.predict(feature_vec)[0])
        proba        = model.predict_proba(feature_vec)[0]
        confidence   = min(round(float(max(proba)) * 100, 2), 99.0)
        label        = "Phishing" if prediction == 1 else "Safe"
        reasons = build_reasons(features, prediction)

    # Network info (async-ish; may slow response)
    network = get_network_info(url)

    return jsonify({
        "url":        url,
        "prediction": label,
        "confidence": confidence,
        "features":   features,
        "reasons":    reasons,
        "api":        api_result,
        "network":    network,
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)