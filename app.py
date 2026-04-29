import streamlit as st
import pandas as pd
import socket
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB

# ---------------- CYBER UI STYLE ----------------
st.set_page_config(page_title="PhishGuard AI", layout="wide")

st.markdown("""
<style>
body {
    background-color: #0f172a;
    color: #e2e8f0;
}
.stApp {
    background: linear-gradient(135deg, #020617, #0f172a);
}
h1, h2, h3 {
    color: #38bdf8;
    text-shadow: 0 0 10px #38bdf8;
}
div.stButton > button {
    background: #0ea5e9;
    color: white;
    border-radius: 10px;
    transition: 0.3s;
}
div.stButton > button:hover {
    background: #38bdf8;
    box-shadow: 0 0 15px #38bdf8;
}
.block-container {
    padding-top: 1rem;
}
.card {
    background: #020617;
    padding: 20px;
    border-radius: 12px;
    box-shadow: 0 0 10px #0ea5e9;
    margin-bottom: 10px;
}
</style>
""", unsafe_allow_html=True)

# ---------------- TITLE ----------------
st.title("🛡️ PhishGuard AI")
st.markdown("### ⚡ Real-Time Cyber Threat Detection System")

# ---------------- SAMPLE DATA ----------------
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

# ---------------- MODEL ----------------
@st.cache_resource
def train_model(df):
    def extract(url):
        return [
            len(url),
            url.count("."),
            url.count("-"),
            sum(k in url for k in ["login","bank","verify","secure","account"])
        ]

    X = [extract(u) for u in df["url"]]
    y = df["label"]

    model = RandomForestClassifier()
    model.fit(X, y)
    return model

model = train_model(df)

# ---------------- SMS MODEL ----------------
@st.cache_resource
def sms_model_train():
    texts = ["Win money now", "Your OTP is 1234", "Verify bank account", "Meeting at 5"]
    labels = [1,0,1,0]

    vec = TfidfVectorizer()
    X = vec.fit_transform(texts)

    model = MultinomialNB()
    model.fit(X, labels)

    return model, vec

sms_model, vec = sms_model_train()

# ---------------- SESSION ----------------
if "history" not in st.session_state:
    st.session_state.history = []

# ---------------- TABS ----------------
tab1, tab2, tab3 = st.tabs(["🌐 URL Scanner", "📱 SMS Scanner", "📊 Dashboard"])

# =====================================================
# URL SCANNER
# =====================================================
with tab1:
    st.markdown("### 🔍 Scan URL")

    url = st.text_input("Enter suspicious URL")

    if st.button("🚀 Analyze"):
        if not url:
            st.warning("Enter URL first")
        else:
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

            label = "🚨 PHISHING" if pred else "✅ SAFE"
            confidence = round(max(prob)*100,2)
            risk = min(100, int(confidence + features[3]*10))

            try:
                ip = socket.gethostbyname(url.split("//")[-1])
            except:
                ip = "Unknown"

            st.session_state.history.append({"result": label, "risk": risk})

            st.markdown(f"<div class='card'><h2>{label}</h2></div>", unsafe_allow_html=True)
            st.progress(risk/100)
            st.write("Confidence:", confidence)
            st.write("Risk Score:", risk)
            st.write("IP Address:", ip)

# =====================================================
# SMS SCANNER
# =====================================================
with tab2:
    st.markdown("### 📱 Analyze Message")

    sms = st.text_area("Enter SMS text")

    if st.button("🔍 Analyze SMS"):
        X = vec.transform([sms])
        pred = sms_model.predict(X)[0]
        prob = sms_model.predict_proba(X)[0]

        label = "🚨 PHISHING" if pred else "✅ SAFE"
        confidence = round(max(prob)*100,2)

        st.markdown(f"<div class='card'><h2>{label}</h2></div>", unsafe_allow_html=True)
        st.write("Confidence:", confidence)

# =====================================================
# DASHBOARD
# =====================================================
with tab3:
    st.markdown("### 📊 Threat Monitoring")

    if st.session_state.history:
        hist = pd.DataFrame(st.session_state.history)

        col1, col2 = st.columns(2)

        with col1:
            st.line_chart(hist["risk"])

        with col2:
            st.bar_chart(hist["result"].value_counts())

    else:
        st.info("No scans yet")
