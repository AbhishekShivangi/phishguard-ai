import streamlit as st
import pandas as pd
import requests
import socket
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- CONFIG ----------------
DATA_URL = "https://raw.githubusercontent.com/AbhishekShivangi/phishguard-ai/main/phishing_site_urls.csv"

st.set_page_config(page_title="PhishGuard AI Pro", layout="wide")

# ---------------- TITLE ----------------
st.title("🛡️ PhishGuard AI Pro")
st.markdown("Real-Time Phishing Detection using Machine Learning")

# ---------------- LOAD DATA ----------------
@st.cache_data
def load_dataset():
    df = pd.read_csv(DATA_URL)

    # Fix columns if needed
    if len(df.columns) != 2:
        df = df.iloc[:, :2]

    df.columns = ["url", "label"]
    df["label"] = df["label"].map({"bad":1, "good":0})

    return df

df = load_dataset()

st.success(f"Dataset Loaded: {len(df)} URLs")

# ---------------- TRAIN URL MODEL ----------------
@st.cache_resource
def train_url_model(df):
    def extract(url):
        return [
            len(url),
            url.count("."),
            url.count("-"),
            sum(k in url for k in ["login","bank","verify","secure","account"])
        ]

    X = [extract(u) for u in df["url"][:5000]]
    y = df["label"][:5000]

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, y)

    return model

url_model = train_url_model(df)

# ---------------- SMS MODEL ----------------
@st.cache_resource
def train_sms_model():
    sms_data = [
        ("Win money now click here",1),
        ("Your OTP is 1234",0),
        ("Verify your bank account immediately",1),
        ("Free prize claim now",1),
        ("Meeting at 5pm",0),
        ("Urgent: update account now",1),
        ("Your order delivered",0)
    ]

    texts = [d[0] for d in sms_data]
    labels = [d[1] for d in sms_data]

    vectorizer = TfidfVectorizer(stop_words="english")
    X = vectorizer.fit_transform(texts)

    model = MultinomialNB()
    model.fit(X, labels)

    return model, vectorizer

sms_model, vectorizer = train_sms_model()

# ---------------- NETWORK INFO ----------------
def get_network(url):
    try:
        host = url.split("//")[-1].split("/")[0]
        ip = socket.gethostbyname(host)
    except:
        ip = "Unknown"

    try:
        start = time.time()
        r = requests.get(url, timeout=3)
        rt = round((time.time()-start)*1000,2)
        return {"ip": ip, "response": rt}
    except:
        return {"ip": ip, "response": -1}

# ---------------- SESSION ----------------
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
        if not url:
            st.warning("Enter URL first")
        else:
            if not url.startswith("http"):
                url = "http://" + url

            features = [
                len(url),
                url.count("."),
                url.count("-"),
                sum(k in url for k in ["login","bank","verify","secure","account"])
            ]

            pred = url_model.predict([features])[0]
            prob = url_model.predict_proba([features])[0]

            label = "🚨 Phishing" if pred == 1 else "✅ Safe"
            confidence = round(max(prob)*100,2)

            risk = min(100, int(confidence + features[3]*10))

            net = get_network(url)

            st.session_state.history.append({
                "url": url,
                "result": label,
                "risk": risk
            })

            st.subheader(label)
            st.write("Confidence:", confidence)
            st.write("Risk Score:", risk)
            st.progress(risk/100)

            st.markdown("### 🌐 Network Info")
            st.write("IP:", net["ip"])
            st.write("Response Time:", net["response"])

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

            words = ["urgent","verify","bank","free","win","otp","click","account"]
            found = [w for w in words if w in sms.lower()]

            risk = min(100, int(confidence + len(found)*5))

            st.subheader(label)
            st.write("Confidence:", confidence)
            st.write("Risk Score:", risk)
            st.progress(risk/100)

            st.write("Suspicious Words:", found)

# =====================================================
# 📊 DASHBOARD
# =====================================================
with tab3:
    st.subheader("📊 Live Monitoring Dashboard")

    if st.session_state.history:
        hist = pd.DataFrame(st.session_state.history)

        st.line_chart(hist["risk"])
        st.bar_chart(hist["result"].value_counts())

        st.markdown("### Recent Activity")
        st.write(hist.tail(10))
    else:
        st.info("No scans yet")
