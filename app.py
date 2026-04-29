import streamlit as st
import pandas as pd
import requests
import socket
import time
import re
import kagglehub
from kagglehub import KaggleDatasetAdapter

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- PAGE CONFIG ----------------
st.set_page_config(page_title="PhishGuard AI Pro", layout="wide")
st.title("🛡️ PhishGuard AI Pro (Real Dataset Version)")

# ---------------- LOAD DATASET ----------------
@st.cache_data
df = kagglehub.load_dataset(
    KaggleDatasetAdapter.PANDAS,
    "taruntiwarihp/phishing-site-urls",
    "phishing_site_urls.csv"
)
    df = df.rename(columns={"url": "url", "label": "label"})
    df["label"] = df["label"].map({"bad":1, "good":0})
    return df

df = load_dataset()

st.success(f"Dataset Loaded: {len(df)} URLs")

# ---------------- TRAIN MODELS ----------------
@st.cache_resource
def train_models(df):
    # URL MODEL
    def extract(url):
        return [len(url), sum(k in url for k in ["login","bank","verify","secure"])]

    X = [extract(u) for u in df["url"][:5000]]
    y = df["label"][:5000]

    url_model = RandomForestClassifier(n_estimators=100)
    url_model.fit(X, y)

    # SMS MODEL
    sms_data = [
        ("Win money now click here",1),
        ("Your OTP is 1234",0),
        ("Verify your bank account immediately",1),
        ("Free prize claim now",1),
        ("Meeting at 5pm",0),
    ]

    texts = [d[0] for d in sms_data]
    labels = [d[1] for d in sms_data]

    vectorizer = TfidfVectorizer(stop_words="english")
    X_sms = vectorizer.fit_transform(texts)

    sms_model = MultinomialNB()
    sms_model.fit(X_sms, labels)

    return url_model, sms_model, vectorizer

url_model, sms_model, vectorizer = train_models(df)

# ---------------- NETWORK ----------------
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

# ---------------- DASHBOARD DATA ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs(["🌐 URL Detection", "📱 SMS Detection", "📊 Dashboard"])

# =====================================================
# 🌐 URL DETECTION
# =====================================================
with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url.startswith("http"):
            url = "http://" + url

        features = [len(url), sum(k in url for k in ["login","bank","verify","secure"])]

        pred = url_model.predict([features])[0]
        prob = url_model.predict_proba([features])[0]

        label = "Phishing" if pred == 1 else "Safe"
        confidence = round(max(prob)*100,2)

        net = get_network_info(url)
        geo = get_geo(net["ip"])

        risk = min(100, int(confidence + features[1]*10))

        # Save history
        st.session_state.history.append({
            "url": url,
            "result": label,
            "risk": risk
        })

        st.subheader(f"🔍 {label}")
        st.write("Confidence:", confidence)
        st.write("Risk Score:", risk)
        st.progress(risk/100)

        st.write("IP:", net["ip"])
        st.write("Response:", net["response"])
        st.write("Location:", geo)

# =====================================================
# 📱 SMS DETECTION
# =====================================================
with tab2:
    sms = st.text_area("Enter SMS")

    if st.button("Analyze SMS"):
        X = vectorizer.transform([sms])
        pred = sms_model.predict(X)[0]
        prob = sms_model.predict_proba(X)[0]

        label = "Phishing" if pred == 1 else "Safe"
        confidence = round(max(prob)*100,2)

        words = ["urgent","verify","bank","free","win","otp","click"]
        found = [w for w in words if w in sms.lower()]

        risk = min(100, int(confidence + len(found)*5))

        st.subheader(label)
        st.write("Confidence:", confidence)
        st.write("Risk:", risk)
        st.progress(risk/100)

        st.write("Suspicious Words:", found)

# =====================================================
# 📊 DASHBOARD
# =====================================================
with tab3:
    st.subheader("📊 Monitoring Dashboard")

    if st.session_state.history:
        df_hist = pd.DataFrame(st.session_state.history)

        st.line_chart(df_hist["risk"])

        counts = df_hist["result"].value_counts()
        st.bar_chart(counts)

        st.write(df_hist.tail(5))
    else:
        st.info("No data yet")
