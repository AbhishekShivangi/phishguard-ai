import streamlit as st
import pandas as pd
import socket
import time
import random
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

st.set_page_config(page_title="PhishGuard AI", layout="wide")

# ---------------- CYBER STYLE ----------------
st.markdown("""
<style>
.stApp {background: #020617; color: white;}
h1 {color: #38bdf8;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard AI")
st.markdown("### ⚡ Real-Time Cyber Threat Intelligence System")

# ---------------- DATASET ----------------
@st.cache_data
def load_data():
    data = [
        ("https://google.com",0),
        ("http://secure-login-bank.xyz",1),
        ("https://github.com",0),
        ("http://verify-paypal-account.tk",1),
        ("https://amazon.in",0),
        ("http://free-money.click",1)
    ]
    return pd.DataFrame(data, columns=["url","label"])

df = load_data()

# ---------------- URL MODEL ----------------
@st.cache_resource
def train_model(df):
    def extract(url):
        return [
            len(url),
            url.count("."),
            url.count("-"),
            sum(k in url for k in ["login","bank","verify","secure"])
        ]

    X = [extract(u) for u in df["url"]]
    y = df["label"]

    model = RandomForestClassifier()
    model.fit(X, y)
    return model

model = train_model(df)

# ---------------- SMS MODEL ----------------
@st.cache_resource
def train_sms():
    texts = ["Win money now", "Your OTP is 1234", "Verify bank", "Meeting"]
    labels = [1,0,1,0]

    vec = TfidfVectorizer()
    X = vec.fit_transform(texts)

    model = MultinomialNB()
    model.fit(X, labels)
    return model, vec

sms_model, vec = train_sms()

# ---------------- HISTORY ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- TABS ----------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 URL Scanner",
    "📱 SMS Scanner",
    "📊 Dashboard",
    "🌍 Threat Intelligence"
])

# =====================================================
# URL SCANNER
# =====================================================
with tab1:
    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url.startswith("http"):
            url = "http://" + url

        features = [
            len(url),
            url.count("."),
            url.count("-"),
            sum(k in url for k in ["login","bank","verify","secure"])
        ]

        pred = model.predict([features])[0]
        prob = model.predict_proba([features])[0]

        label = "🚨 Phishing" if pred else "✅ Safe"
        confidence = round(max(prob)*100,2)
        risk = min(100, int(confidence + features[3]*10))

        try:
            ip = socket.gethostbyname(url.split("//")[-1])
        except:
            ip = "Unknown"

        st.session_state.history.append({
            "url": url,
            "result": label,
            "risk": risk
        })

        st.subheader(label)
        st.progress(risk/100)
        st.write("Confidence:", confidence)
        st.write("IP:", ip)

# =====================================================
# SMS SCANNER
# =====================================================
with tab2:
    sms = st.text_area("Enter SMS")

    if st.button("Analyze SMS"):
        X = vec.transform([sms])
        pred = sms_model.predict(X)[0]

        label = "🚨 Phishing" if pred else "✅ Safe"
        st.subheader(label)

# =====================================================
# DASHBOARD (GRAPHS)
# =====================================================
with tab3:
    st.subheader("📊 Threat Monitoring Dashboard")

    if st.session_state.history:
        hist = pd.DataFrame(st.session_state.history)

        col1, col2 = st.columns(2)

        with col1:
            st.write("📈 Risk Trend")
            st.line_chart(hist["risk"])

        with col2:
            st.write("📊 Detection Count")
            st.bar_chart(hist["result"].value_counts())

        st.write("📋 Recent Activity")
        st.dataframe(hist.tail(10))

    else:
        st.info("No data yet")

# =====================================================
# THREAT INTELLIGENCE (ADVANCED)
# =====================================================
with tab4:
    st.subheader("🌍 Live Threat Intelligence Feed")

    threats = [
        "malicious-bank-login.xyz",
        "free-crypto-win.click",
        "paypal-secure-update.tk",
        "verify-account-alert.info"
    ]

    risk_levels = [random.randint(70,100) for _ in threats]

    df_threat = pd.DataFrame({
        "Threat Domain": threats,
        "Risk Score": risk_levels
    })

    st.write("🔴 High Risk Domains")
    st.dataframe(df_threat)

    st.write("📊 Threat Risk Distribution")
    st.bar_chart(df_threat["Risk Score"])
