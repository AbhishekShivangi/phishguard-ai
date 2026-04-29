import streamlit as st
import pandas as pd
import socket
import time
import re
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- UI ----------------
st.set_page_config(page_title="PhishGuard AI", layout="wide")

st.markdown("""
<style>
.stApp {background: #020617; color: white;}
h1 {color: #38bdf8;}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard AI")
st.markdown("### ⚡ Smart Phishing Detection (Reduced False Positives)")

# ---------------- TRUSTED DOMAINS ----------------
trusted_domains = [
    "google.com","github.com","amazon.in","facebook.com",
    "microsoft.com","apple.com","youtube.com","linkedin.com"
]

def get_domain(url):
    ext = tldextract.extract(url)
    return ext.domain + "." + ext.suffix

def is_trusted(url):
    return get_domain(url) in trusted_domains

# ---------------- DATA ----------------
@st.cache_data
def load_data():
    data = [
        ("https://google.com",0),
        ("https://github.com",0),
        ("http://secure-login-bank.xyz",1),
        ("http://verify-paypal-account.tk",1),
        ("https://amazon.in",0),
        ("http://free-money.click",1)
    ]
    return pd.DataFrame(data, columns=["url","label"])

df = load_data()

# ---------------- FEATURE EXTRACTION ----------------
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
def train_model(df):
    X = [extract_features(u) for u in df["url"]]
    y = df["label"]

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, y)
    return model

model = train_model(df)

# ---------------- SMS MODEL ----------------
@st.cache_resource
def train_sms():
    texts = ["Win money now", "Your OTP is 1234", "Verify bank account", "Meeting"]
    labels = [1,0,1,0]

    vec = TfidfVectorizer()
    X = vec.fit_transform(texts)

    model = MultinomialNB()
    model.fit(X, labels)
    return model, vec

sms_model, vec = train_sms()

# ---------------- SESSION ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs(["🌐 URL Scanner","📱 SMS Scanner","📊 Dashboard"])

# =====================================================
# URL SCANNER
# =====================================================
with tab1:
    st.subheader("🔍 URL Analysis")

    url = st.text_input("Enter URL")

    if st.button("Analyze URL"):
        if not url.startswith("http"):
            url = "http://" + url

        domain = get_domain(url)

        # TRUST CHECK
        if is_trusted(url):
            label = "✅ Safe (Trusted Domain)"
            confidence = 98
            risk = 5
            reason = ["Trusted domain verified"]

        else:
            features = extract_features(url)

            pred = model.predict([features])[0]
            prob = model.predict_proba([features])[0]

            label = "🚨 Phishing" if pred else "⚠️ Suspicious"
            confidence = round(max(prob)*100,2)

            keyword_score = features[5] + features[6]
            risk = min(100, int(confidence + keyword_score * 5))

            # EXPLANATION
            reason = []
            if features[5]: reason.append("Login keyword found")
            if features[6]: reason.append("Verify keyword found")
            if features[4]: reason.append("@ symbol detected")
            if features[2] > 2: reason.append("Too many hyphens")

        try:
            ip = socket.gethostbyname(domain)
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
        st.write("Risk Score:", risk)
        st.write("Domain:", domain)
        st.write("IP:", ip)

        st.markdown("### 🔍 Why this result?")
        st.write(reason if reason else "No suspicious patterns")

# =====================================================
# SMS SCANNER
# =====================================================
with tab2:
    st.subheader("📱 SMS Analysis")

    sms = st.text_area("Enter SMS")

    if st.button("Analyze SMS"):
        X = vec.transform([sms])
        pred = sms_model.predict(X)[0]

        label = "🚨 Phishing" if pred else "✅ Safe"
        st.subheader(label)

# =====================================================
# DASHBOARD
# =====================================================
with tab3:
    st.subheader("📊 Threat Dashboard")

    if st.session_state.history:
        hist = pd.DataFrame(st.session_state.history)

        col1, col2 = st.columns(2)

        with col1:
            st.write("📈 Risk Trend")
            st.line_chart(hist["risk"])

        with col2:
            st.write("📊 Detection Count")
            st.bar_chart(hist["result"].value_counts())

        st.write("📋 History")
        st.dataframe(hist.tail(10))

    else:
        st.info("No scans yet")
