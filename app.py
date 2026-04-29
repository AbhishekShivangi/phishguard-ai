from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle, re, socket, time, requests
from datetime import datetime
import whois, ssl

from model import extract_features, FEATURE_NAMES

app = Flask(__name__)
CORS(app)

model = pickle.load(open("model.pkl", "rb"))

# ---------------- DOMAIN INFO ----------------
def get_domain_info(url):
    try:
        domain = re.sub(r"https?://", "", url).split("/")[0]
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        age_days = (datetime.now() - creation_date).days if creation_date else -1
        return {"domain": domain, "age_days": age_days, "registrar": str(w.registrar)}
    except:
        return {"domain": "unknown", "age_days": -1, "registrar": "unknown"}

# ---------------- SSL CHECK ----------------
def check_ssl(url):
    try:
        hostname = re.sub(r"https?://", "", url).split("/")[0]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(3)
            s.connect((hostname, 443))
            return {"ssl_valid": True}
    except:
        return {"ssl_valid": False}

# ---------------- NETWORK ----------------
def get_network_info(url):
    try:
        host = re.sub(r"https?://", "", url).split("/")[0]
        ip = socket.gethostbyname(host)
    except:
        ip = "Unknown"

    try:
        start = time.time()
        r = requests.get(url, timeout=5)
        rt = round((time.time() - start) * 1000, 1)
        return {"ip": ip, "response_time": rt, "status": r.status_code}
    except:
        return {"ip": ip, "response_time": -1, "status": 0}

# ---------------- GEO ----------------
def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {"country": res.get("country"), "city": res.get("city")}
    except:
        return {}

# ---------------- RISK ----------------
def risk_score(conf, reasons, domain):
    score = conf * 0.5 + len(reasons)*5
    if domain["age_days"] != -1 and domain["age_days"] < 30:
        score += 20
    return min(100, int(score))

# ---------------- API ----------------
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    url = data.get("url")

    if not url.startswith("http"):
        url = "http://" + url

    features = extract_features(url)
    vec = [[features[k] for k in FEATURE_NAMES]]

    pred = model.predict(vec)[0]
    prob = model.predict_proba(vec)[0]

    label = "Phishing" if pred == 1 else "Safe"
    conf = round(max(prob)*100, 2)

    reasons = []
    if features["length"] > 75:
        reasons.append("Long URL")
    if features["keyword_hits"] > 0:
        reasons.append("Suspicious keywords")

    network = get_network_info(url)
    domain = get_domain_info(url)
    ssl_info = check_ssl(url)
    geo = get_geo(network["ip"])

    risk = risk_score(conf, reasons, domain)

    return jsonify({
        "url": url,
        "prediction": label,
        "confidence": conf,
        "risk_score": risk,
        "reasons": reasons,
        "network": network,
        "domain": domain,
        "ssl": ssl_info,
        "geo": geo
    })

app.run(port=5000)
