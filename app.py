import streamlit as st
import requests

API = "http://localhost:5000/predict"

st.title("🛡️ PhishGuard AI Pro")

url = st.text_input("Enter URL")

if st.button("Analyze"):
    res = requests.post(API, json={"url": url}).json()

    st.subheader(res["prediction"])
    st.write("Confidence:", res["confidence"])
    st.write("Risk Score:", res["risk_score"])

    st.write("Reasons:", res["reasons"])

    st.write("🌐 Network:", res["network"])
    st.write("🌍 Location:", res["geo"])
    st.write("🔐 SSL:", res["ssl"])
    st.write("📅 Domain:", res["domain"])
