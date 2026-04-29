import streamlit as st
import requests
import socket
import time
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import RandomForestClassifier

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="PhishGuard AI Pro", layout="wide")

# ---------------- LOAD MODELS (NO FILES) ----------------
@st.cache_resource
def load_models():
    # URL model
    url_data = [
        ("https://google.com",0),
        ("https://github.com",0),
        ("http://secure-login-bank.xyz",1),
        ("http://verify-paypal-account.tk",1)
    ]

    def extract(url):
        return [len(url), sum(k in url for k in ["login","bank","verify","secure"])]

    X = [extract(u) for u,_ in url_data]
    y = [l for _,l in url_data]

    url_model = RandomForestClassifier()
    url_model.fit(X,y)

    # SMS model
    sms_data = [
        ("Win money now click here",1),
        ("Your OTP is 1234",0),
        ("Verify your bank account immediately",1),
        ("Free prize claim now",1),
        ("Meeting at 5pm",0),
        ("Your parcel delivered",0)
    ]

    texts = [d[0] for d in sms_data]
    labels = [d[1] for d in sms_data]

    vectorizer = TfidfVectorizer(stop_words="english")
    X_sms = vectorizer.fit_transform(texts)

    sms_model = MultinomialNB()
    sms_model.fit(X_sms, labels)

    return url_model, sms_model, vectorizer

url_model, sms_model, vectorizer = load_models()

# ---------------- FUNCTIONS ----------------
def extract_features(url):
    return [len(url), sum(k in url for k in ["login","bank","verify","secure"])]

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

def get_geo(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return res.get("country","Unknown")
    except:
        return "Unknown"

# ---------------- UI ----------------
st.title("🛡️ PhishGuard AI Pro")
st.markdown("AI-powered phishing detection for URLs and SMS")

tab1, tab2 = st.tabs(["🌐 URL Detection", "📱 SMS Detection"])

# =====================================================
# 🌐 URL DETECTION
# =====================================================
with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url:
            st.warning("Enter URL first")
        else:
            if not url.startswith("http"):
                url = "http://" + url

            features = extract_features(url)
            pred = url_model.predict([features])[0]
            prob = url_model.predict_proba([features])[0]

            label = "🚨 Phishing" if pred == 1 else "✅ Safe"
            confidence = round(max(prob)*100,2)

            net = get_network_info(url)
            geo = get_geo(net["ip"])

            risk = min(100, int(confidence + features[1]*10))

            st.subheader(label)
            st.write("Confidence:", confidence)
            st.write("Risk Score:", risk)
            st.progress(risk/100)

            st.markdown("### 🌐 Network Info")
            st.write("IP:", net["ip"])
            st.write("Response Time:", net["response"])
            st.write("Location:", geo)

            st.markdown("### ⚠️ Feature Analysis")
            st.write({
                "URL Length": features[0],
                "Suspicious Keywords": features[1]
            })

# =====================================================
# 📱 SMS DETECTION
# =====================================================
with tab2:
    sms = st.text_area("Enter SMS / Message")

    if st.button("Analyze SMS"):
        if not sms:
            st.warning("Enter message first")
        else:
            X = vectorizer.transform([sms])
            pred = sms_model.predict(X)[0]
            prob = sms_model.predict_proba(X)[0]

            label = "🚨 Phishing" if pred == 1 else "✅ Safe"
            confidence = round(max(prob)*100,2)

            suspicious_words = ["urgent","verify","bank","free","win","otp","click"]
            found = [w for w in suspicious_words if w in sms.lower()]

            risk = min(100, int(confidence + len(found)*5))

            st.subheader(label)
            st.write("Confidence:", confidence)
            st.write("Risk Score:", risk)
            st.progress(risk/100)

            st.markdown("### ⚠️ Suspicious Words")
            st.write(found if found else "None")

            # Highlight words
            highlighted = sms
            for w in found:
                highlighted = highlighted.replace(w, f"🔴{w}🔴")

            st.markdown(highlighted)

            # Attack simulation
            if st.toggle("⚠️ Simulate Phishing Attack"):
                st.error("User clicked malicious link")
                st.warning("Fake login page opened")
                st.error("Credentials stolen!")
                st.success("PhishGuard blocked attack!")

# ---------------- FOOTER ----------------
st.markdown("---")
st.markdown("PhishGuard AI Pro • Hackathon Project")
