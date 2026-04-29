import streamlit as st
import pandas as pd
import socket
import time
import re
import random
import requests
import tldextract
import plotly.express as px

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- UI ----------------
st.set_page_config(page_title="PhishGuard AI Pro", layout="wide")

st.markdown("""
<style>
.stApp {background: #020617; color: white;}
h1 {color: #38bdf8;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard AI Pro")
st.markdown("### ⚡ Real-Time Cyber Threat Intelligence System")

# ---------------- TRUST ----------------
trusted_domains = ["google.com","github.com","amazon.in","facebook.com","microsoft.com"]

def get_domain(url):
    ext = tldextract.extract(url)
    return ext.domain + "." + ext.suffix

def is_trusted(url):
    return get_domain(url) in trusted_domains

# ---------------- FEATURE ----------------
def extract_features(url):
    return [
        len(url),
        url.count('.'),
        url.count('-'),
        int("https" in url),
        int("@" in url),
        int("login" in url.lower()),
        int("verify" in url.lower()),
        len(re.findall(r'\d+', url))
    ]

# ---------------- MODEL ----------------
@st.cache_resource
def train_model():
    data = [
        ("https://google.com",0),
        ("http://secure-login-bank.xyz",1),
        ("http://verify-account.tk",1),
        ("https://github.com",0)
    ]
    df = pd.DataFrame(data, columns=["url","label"])

    X = [extract_features(u) for u in df["url"]]
    y = df["label"]

    model = RandomForestClassifier()
    model.fit(X, y)
    return model

model = train_model()

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

# ---------------- NETWORK ----------------
def network_info(url):
    try:
        domain = get_domain(url)
        ip = socket.gethostbyname(domain)

        start = time.time()
        r = requests.get(url, timeout=3)
        latency = round((time.time()-start)*1000,2)

        return ip, latency, r.status_code
    except:
        return "Unknown", -1, 0

# ---------------- SESSION ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- TABS ----------------
tab1, tab2, tab3, tab4 = st.tabs([
    "🌐 URL Scanner",
    "📱 SMS Scanner",
    "📊 Dashboard",
    "🌍 Threat Feed"
])

# =====================================================
# URL SCANNER
# =====================================================
with tab1:
    st.subheader("🔍 Live URL Detection")

    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url.startswith("http"):
            url = "http://" + url

        domain = get_domain(url)

        if is_trusted(url):
            label = "✅ Safe (Trusted)"
            risk = 5
            confidence = 98
        else:
            features = extract_features(url)
            pred = model.predict([features])[0]
            prob = model.predict_proba([features])[0]

            label = "🚨 Phishing" if pred else "⚠️ Suspicious"
            confidence = round(max(prob)*100,2)
            risk = min(100, int(confidence + features[5]*5))

        ip, latency, status = network_info(url)

        st.session_state.history.append({
            "url": url,
            "risk": risk,
            "result": label,
            "latency": latency
        })

        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", risk)
        col2.metric("Latency (ms)", latency)
        col3.metric("Status Code", status)

        st.progress(risk/100)
        st.write("IP Address:", ip)

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
# DASHBOARD (ADVANCED GRAPHS)
# =====================================================
with tab3:
    st.subheader("📊 Advanced Monitoring")

    if st.session_state.history:
        df = pd.DataFrame(st.session_state.history)

        col1, col2 = st.columns(2)

        with col1:
            fig1 = px.line(df, y="risk", title="Risk Trend")
            st.plotly_chart(fig1, use_container_width=True)

        with col2:
            fig2 = px.histogram(df, x="risk", title="Risk Distribution")
            st.plotly_chart(fig2, use_container_width=True)

        # 3D GRAPH
        if len(df) > 2:
            df["index"] = range(len(df))
            fig3 = px.scatter_3d(df, x="index", y="risk", z="latency",
                                color="risk", title="3D Threat Visualization")
            st.plotly_chart(fig3, use_container_width=True)

# =====================================================
# THREAT FEED
# =====================================================
with tab4:
    st.subheader("🌍 Live Threat Feed")

    threats = [
        "phishing-bank-login.xyz",
        "crypto-free-win.click",
        "verify-paypal-alert.tk"
    ]

    risks = [random.randint(70,100) for _ in threats]

    df_threat = pd.DataFrame({
        "Domain": threats,
        "Risk": risks
    })

    st.dataframe(df_threat)

    fig = px.bar(df_threat, x="Domain", y="Risk", title="Threat Scores")
    st.plotly_chart(fig, use_container_width=True)
