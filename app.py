import streamlit as st
import pickle
import re
import requests
import socket
import time
import numpy as np
from datetime import datetime

# ---------------- LOAD MODELS ----------------
model = pickle.load(open("model.pkl", "rb"))
sms_model = pickle.load(open("sms_model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

# ---------------- FEATURE EXTRACTION ----------------
def extract_features(url):
    url = url.lower()
    return {
        "length": len(url),
        "keyword_hits": sum(k in url for k in ["login","bank","verify","secure"]),
    }

FEATURE_NAMES = ["length","keyword_hits"]

# ---------------- NETWORK INFO ----------------
def get_network_info(url):
    try:
        host = url.split("//")[-1].split("/")[0]
        ip = socket.gethostbyname(host)
    except:
        ip = "Unknown"

    try:
        start = time.time()
        r = requests.get(url, timeout=3)
        rt = round((time.time()-start)*1000,2)
        return {"ip": ip, "response": rt, "status": r.status_code}
    except:
        return {"ip": ip, "response": -1, "status": 0}

# ---------------- GEO ----------------
def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("country","Unknown")
    except:
        return "Unknown"

# ---------------- UI ----------------
st.set_page_config(page_title="PhishGuard AI Pro", layout="wide")
st.title("🛡️ PhishGuard AI Pro")

tab1, tab2 = st.tabs(["🌐 URL Detection", "📱 SMS Detection"])

# =====================================================
# 🌐 URL DETECTION
# =====================================================
with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url.startswith("http"):
            url = "http://" + url

        features = extract_features(url)
        vec = [[features[k] for k in FEATURE_NAMES]]

        pred = model.predict(vec)[0]
        prob = model.predict_proba(vec)[0]

        label = "Phishing" if pred == 1 else "Safe"
        confidence = round(max(prob)*100,2)

        # Network
        net = get_network_info(url)
        geo = get_geo(net["ip"])

        # Risk score
        risk = min(100, int(confidence + features["keyword_hits"]*10))

        st.subheader(f"🔍 Result: {label}")
        st.write("Confidence:", confidence)
        st.write("Risk Score:", risk)

        st.progress(risk/100)

        st.write("🌐 IP:", net["ip"])
        st.write("⏱ Response Time:", net["response"])
        st.write("🌍 Location:", geo)

        st.write("⚠️ Features:", features)

# =====================================================
# 📱 SMS DETECTION
# =====================================================
with tab2:
    sms = st.text_area("Enter SMS or message")

    if st.button("Analyze SMS"):
        X = vectorizer.transform([sms])
        pred = sms_model.predict(X)[0]
        prob = sms_model.predict_proba(X)[0]

        label = "Phishing" if pred == 1 else "Safe"
        confidence = round(max(prob)*100,2)

        # Pattern detection
        words = ["urgent","verify","bank","free","win","otp","click"]
        found = [w for w in words if w in sms.lower()]

        risk = min(100, int(confidence + len(found)*5))

        st.subheader(f"📱 Result: {label}")
        st.write("Confidence:", confidence)
        st.write("Risk Score:", risk)

        st.progress(risk/100)

        st.write("⚠️ Suspicious Words:", found)

        # Highlight
        highlighted = sms
        for w in found:
            highlighted = highlighted.replace(w, f"🔴{w}🔴")

        st.markdown(highlighted)

        # Simulation
        if st.toggle("⚠️ Simulate Attack"):
            st.error("User clicked malicious link")
            st.warning("Fake login page opened")
            st.error("Credentials stolen!")
            st.success("PhishGuard blocked attack")
