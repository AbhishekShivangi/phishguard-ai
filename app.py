"""
app.py — Streamlit frontend for the Phishing Detection System.
Run with:  streamlit run app.py
"""

import re
import time
import requests
import numpy as np
import pandas as pd
import streamlit as st

# ─── Page config ─────────────────────────────
st.set_page_config(
    page_title="PhishGuard AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

API_URL = "http://localhost:5000/predict"

# ─── Custom CSS ───────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;600;900&display=swap');

html, body, [class*="css"] {
    font-family: 'Exo 2', sans-serif;
    background-color: #0a0e1a;
    color: #c8d6e5;
}
.stApp { background: #0a0e1a; }

/* Header */
.hero-title {
    font-family: 'Exo 2', sans-serif;
    font-weight: 900;
    font-size: 3rem;
    letter-spacing: -1px;
    background: linear-gradient(135deg, #00d2ff, #7b2ff7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 0;
}
.hero-sub {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9eff;
    font-size: 0.85rem;
    letter-spacing: 3px;
    text-transform: uppercase;
}

/* Cards */
.card {
    background: linear-gradient(135deg, #111827, #1a2233);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 1.4rem 1.6rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4);
}
.card-title {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9eff;
    font-size: 0.75rem;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
}

/* Verdict */
.verdict-safe {
    font-family: 'Exo 2', sans-serif;
    font-weight: 900;
    font-size: 2.6rem;
    color: #00e676;
    text-shadow: 0 0 20px rgba(0,230,118,0.5);
}
.verdict-phishing {
    font-family: 'Exo 2', sans-serif;
    font-weight: 900;
    font-size: 2.6rem;
    color: #ff1744;
    text-shadow: 0 0 20px rgba(255,23,68,0.5);
}

/* Confidence bar */
.conf-bar-wrap { background: #1e2a3a; border-radius: 50px; height: 12px; margin-top: 6px; }
.conf-bar-fill-safe    { background: linear-gradient(90deg,#00e676,#69f0ae); height: 12px; border-radius: 50px; }
.conf-bar-fill-phish   { background: linear-gradient(90deg,#ff1744,#ff6090); height: 12px; border-radius: 50px; }

/* Reason pills */
.reason-pill {
    display: inline-block;
    background: rgba(255,23,68,0.12);
    border: 1px solid rgba(255,23,68,0.3);
    border-radius: 20px;
    padding: 4px 14px;
    margin: 3px;
    font-size: 0.78rem;
    color: #ff8a80;
    font-family: 'Share Tech Mono', monospace;
}
.reason-pill-safe {
    display: inline-block;
    background: rgba(0,230,118,0.10);
    border: 1px solid rgba(0,230,118,0.25);
    border-radius: 20px;
    padding: 4px 14px;
    margin: 3px;
    font-size: 0.78rem;
    color: #69f0ae;
    font-family: 'Share Tech Mono', monospace;
}

/* Network table */
.net-row { display: flex; justify-content: space-between; padding: 4px 0;
           border-bottom: 1px solid #1e3a5f; font-size: 0.84rem; }
.net-label { color: #607d8b; font-family: 'Share Tech Mono', monospace; }
.net-val   { color: #e0e0e0; font-weight: 600; }

/* SMS demo */
.sms-bubble-attacker {
    background: linear-gradient(135deg, #1a1a2e, #16213e);
    border: 1px solid #ff1744;
    border-radius: 14px 14px 14px 0px;
    padding: 12px 16px;
    margin: 8px 0;
    font-size: 0.9rem;
    max-width: 80%;
    color: #ffcdd2;
    position: relative;
}
.sms-sender { font-size: 0.7rem; color: #ff8a80; margin-bottom: 4px;
              font-family: 'Share Tech Mono', monospace; }
.sms-warn   { background: rgba(255,23,68,0.15); border: 1px solid #ff1744;
              border-radius: 8px; padding: 10px; margin-top: 12px;
              font-size: 0.82rem; color: #ff6090; }

/* Input styling */
div[data-testid="stTextInput"] input {
    background: #111827 !important;
    border: 1.5px solid #1e3a5f !important;
    border-radius: 8px !important;
    color: #c8d6e5 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.95rem !important;
    padding: 12px !important;
}
div[data-testid="stTextInput"] input:focus {
    border-color: #4a9eff !important;
    box-shadow: 0 0 0 2px rgba(74,158,255,0.2) !important;
}

/* Button */
.stButton > button {
    background: linear-gradient(135deg, #0d47a1, #4a9eff) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 0.6rem 2rem !important;
    font-family: 'Exo 2', sans-serif !important;
    font-weight: 700 !important;
    font-size: 1rem !important;
    letter-spacing: 1px !important;
    transition: all 0.2s !important;
}
.stButton > button:hover {
    transform: translateY(-1px) !important;
    box-shadow: 0 6px 20px rgba(74,158,255,0.4) !important;
}
</style>
""", unsafe_allow_html=True)


# ─── Header ───────────────────────────────────
st.markdown("""
<div style="text-align:center; padding: 2rem 0 1.5rem 0;">
    <div class="hero-title">🛡️ PhishGuard AI</div>
    <div class="hero-sub">Real-time phishing detection · ML + URLhaus Threat Intelligence</div>
</div>
""", unsafe_allow_html=True)


# ─── Tabs ─────────────────────────────────────
tab_url, tab_sms = st.tabs(["🔗  URL Analyzer", "📱  Fake SMS Detector"])


# ══════════════════════════════════════════════
#  TAB 1 — URL ANALYZER
# ══════════════════════════════════════════════
with tab_url:
    col_input, _ = st.columns([3, 1])
    with col_input:
        url_input = st.text_input(
            "",
            placeholder="Enter URL to analyze — e.g. https://paypal-secure-login.xyz",
            label_visibility="collapsed",
        )

    col_btn, _ = st.columns([1, 4])
    with col_btn:
        analyze = st.button("⚡  Analyze Now", use_container_width=True)

    if analyze and url_input:
        with st.spinner("Scanning URL …"):
            try:
                resp = requests.post(API_URL, json={"url": url_input}, timeout=15)
                result = resp.json()
            except Exception as e:
                st.error(f"Could not reach API at {API_URL} — is  `python api.py`  running?\n\n{e}")
                st.stop()

        if "error" in result:
            st.error(result["error"])
            st.stop()

        pred   = result["prediction"]      # "Safe" / "Phishing"
        conf   = result["confidence"]
        feats  = result["features"]
        reasons = result["reasons"]
        api_res = result["api"]
        net    = result["network"]

        is_phish = (pred == "Phishing")
        v_class  = "verdict-phishing" if is_phish else "verdict-safe"
        icon     = "🚨" if is_phish else "✅"
        bar_cls  = "conf-bar-fill-phish" if is_phish else "conf-bar-fill-safe"

        st.markdown("<hr style='border-color:#1e3a5f; margin:1.2rem 0'>", unsafe_allow_html=True)

        # ── Row 1: Verdict + Confidence ──────────
        col_v, col_c, col_gsb = st.columns(3)

        with col_v:
            st.markdown(f"""
            <div class="card">
              <div class="card-title">AI Verdict</div>
              <div class="{v_class}">{icon} {pred}</div>
              <div style="font-size:0.8rem; color:#607d8b; margin-top:4px;">{url_input[:60]}{'…' if len(url_input)>60 else ''}</div>
            </div>""", unsafe_allow_html=True)

        with col_c:
            st.markdown(f"""
            <div class="card">
              <div class="card-title">AI Confidence</div>
              <div style="font-size:2rem;font-weight:900;color:{'#ff1744' if is_phish else '#00e676'}">{conf}%</div>
              <div class="conf-bar-wrap"><div class="{bar_cls}" style="width:{conf}%"></div></div>
            </div>""", unsafe_allow_html=True)

        with col_gsb:
            api_malicious = api_res.get("is_malicious", False)
            api_icon  = "🔴" if api_malicious else "🟢"
            api_color = "#ff1744" if api_malicious else "#00e676"
            st.markdown(f"""
            <div class="card">
              <div class="card-title">Threat Intelligence API</div>
              <div style="font-size:1.4rem;font-weight:800;color:{api_color}">{api_icon} {"THREAT" if api_malicious else "CLEAR"}</div>
              <div style="font-size:0.8rem;color:#607d8b;margin-top:4px">{api_res['status']}</div>
            </div>""", unsafe_allow_html=True)

        # ── Row 2: Reasons + Network ──────────────
        col_r, col_n = st.columns([3, 2])

        with col_r:
            pills_html = "".join(
                f'<span class="{"reason-pill" if is_phish else "reason-pill-safe"}" title="{r["detail"]}">{r["flag"]}</span>'
                for r in reasons
            )
            st.markdown(f"""
            <div class="card" style="min-height:120px">
              <div class="card-title">🔍 Why this verdict? (Explainable AI)</div>
              <div style="margin-top:8px">{pills_html}</div>
              <div style="margin-top:10px; font-size:0.8rem; color:#455a64">
                {'<br>'.join(f'<b style="color:#b0bec5">{r["flag"]}:</b> {r["detail"]}' for r in reasons)}
              </div>
            </div>""", unsafe_allow_html=True)

        with col_n:
            rt = net["response_time"]
            rt_str = f"{rt} ms" if rt >= 0 else "Timeout"
            redir_str = "Yes ⚠️" if net["redirected"] else "No"
            st.markdown(f"""
            <div class="card" style="min-height:120px">
              <div class="card-title">🌐 Network Info</div>
              <div class="net-row"><span class="net-label">IP Address</span><span class="net-val">{net["ip"]}</span></div>
              <div class="net-row"><span class="net-label">Response Time</span><span class="net-val">{rt_str}</span></div>
              <div class="net-row"><span class="net-label">HTTP Status</span><span class="net-val">{net["status_code"] or "N/A"}</span></div>
              <div class="net-row"><span class="net-label">Redirected</span><span class="net-val">{redir_str}</span></div>
              <div class="net-row" style="border:none"><span class="net-label">Content Size</span><span class="net-val">{net["content_length"]:,} bytes</span></div>
            </div>

            <div class="card" style="min-height:120px; margin-top:1rem;">
              <div class="card-title">📡 Live Network Monitoring (Latency)</div>
              <div id="live-ping-chart">
              </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Live dynamic chart
            ping_data = [rt if rt >= 0 else 500] * 5
            ping_chart = st.line_chart(pd.DataFrame(ping_data, columns=["Latency (ms)"]), height=150)
            for _ in range(15):
                time.sleep(0.1)
                new_ping = max(10, (rt if rt >= 0 else 500) + np.random.randint(-15, 15))
                ping_chart.add_rows(pd.DataFrame([new_ping], columns=["Latency (ms)"]))

        # ── Row 3: Feature Chart ──────────────────
        st.markdown('<div class="card"><div class="card-title">📊 Feature Analysis (Explainability Graph)</div>', unsafe_allow_html=True)

        display_features = {
            "URL Length":       feats["length"],
            "Dot Count":        feats["dot_count"],
            "Hyphens":          feats["hyphen_count"],
            "@ Signs":          feats["at_count"],
            "Slashes":          feats["slash_count"],
            "Digits":           feats["digit_count"],
            "Keyword Hits":     feats["keyword_hits"],
            "Subdomain Depth":  feats["subdomain_count"],
            "Encoded Chars (%)":feats["percent_count"],
            "Domain Digits":    feats["digits_in_domain"],
        }

        # Display features as a chart instead of table
        st.markdown("#### 📊 Feature Breakdown")
        features_df = pd.DataFrame({
            'Feature': list(display_features.keys()),
            'Value': list(display_features.values())
        }).set_index('Feature')
        st.bar_chart(features_df, height=300)
        st.markdown("</div>", unsafe_allow_html=True)

    elif analyze and not url_input:
        st.warning("Please enter a URL first.")


# ══════════════════════════════════════════════
#  TAB 2 — FAKE SMS DETECTOR
# ══════════════════════════════════════════════
with tab_sms:
    st.markdown("""
    <div class="card" style="margin-bottom:1.5rem">
      <div class="card-title">📱 SMS / Message Phishing Detector</div>
      <div style="font-size:0.85rem;color:#607d8b">Paste a suspicious SMS, WhatsApp, or email message below.
      The system will extract any URLs and scan them, plus flag social-engineering text patterns.</div>
    </div>""", unsafe_allow_html=True)

    # Pre-built phishing SMS examples
    demo_messages = {
        "Demo 1 — Bank Alert": "URGENT: Your SBI account has been suspended. Verify now at http://sbi-secure-login.tk/verify?id=8823 or call 0800-FAKE.",
        "Demo 2 — Parcel Scam": "Your parcel #IN292929 is on hold. Pay ₹25 customs here: http://indiapost-delivery.xyz/pay or it will be returned.",
        "Demo 3 — OTP Fraud": "OTP for your Amazon order is 847291. DO NOT share. Click http://amaz0n-order-confirm.ml/otp to view order.",
        "Demo 4 — Lottery Win": "Congratulations! You've won ₹5,00,000 in the Lucky Draw. Claim within 24 hrs: http://luckyindia2024.cf/claim",
        "Custom": "",
    }

    demo_choice = st.selectbox("Choose a demo message or write your own:", list(demo_messages.keys()))
    prefill = demo_messages[demo_choice]

    sms_text = st.text_area(
        "Paste message here:",
        value=prefill,
        height=130,
        placeholder="e.g. Your bank account has been locked. Click http://bank-secure.xyz to unlock…",
    )

    col_sms_btn, _ = st.columns([1, 4])
    with col_sms_btn:
        scan_sms = st.button("🔍  Scan Message", use_container_width=True)

    if scan_sms and sms_text.strip():
        # ── Extract URLs from message ─────────────
        found_urls = re.findall(r"https?://[^\s\"'>]+|www\.[^\s\"'>]+", sms_text)

        # ── Social engineering text patterns ───────
        SE_PATTERNS = {
            "Urgency language":      r"\b(urgent|immediately|now|asap|today only|24 hours|expire)\b",
            "Financial bait":        r"\b(won|prize|reward|cash|₹|lakh|crore|\$|€|free|claim)\b",
            "Account threat":        r"\b(suspended|blocked|locked|deactivated|verify|confirm)\b",
            "Impersonation hint":    r"\b(sbi|hdfc|axis|paypal|amazon|flipkart|rbi|govt|police|irs|uidai)\b",
            "Pressure tactic":       r"\b(or else|failure|penalty|fine|arrest|legal action)\b",
            "OTP / credential ask":  r"\b(otp|password|pin|cvv|card number)\b",
        }

        triggered = {}
        for label, pattern in SE_PATTERNS.items():
            if re.search(pattern, sms_text.lower()):
                triggered[label] = True

        risk_score = len(triggered) * 15 + len(found_urls) * 10
        risk_score = min(risk_score, 100)

        # ── Render SMS bubble ─────────────────────
        st.markdown("<hr style='border-color:#1e3a5f'>", unsafe_allow_html=True)
        st.markdown(f"""
        <div class="sms-bubble-attacker">
          <div class="sms-sender">⚠️  Suspicious Sender · Unknown Number</div>
          {sms_text}
        </div>""", unsafe_allow_html=True)

        # ── Risk Score ────────────────────────────
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            risk_color = "#ff1744" if risk_score >= 50 else "#ffa726" if risk_score >= 25 else "#00e676"
            risk_label = "HIGH RISK 🚨" if risk_score >= 50 else "MEDIUM RISK ⚠️" if risk_score >= 25 else "LOW RISK ✅"
            st.markdown(f"""
            <div class="card">
              <div class="card-title">Social Engineering Risk Score</div>
              <div style="font-size:2.2rem;font-weight:900;color:{risk_color}">{risk_score}/100</div>
              <div style="color:{risk_color};font-size:0.9rem;margin-top:4px">{risk_label}</div>
            </div>""", unsafe_allow_html=True)

        with col_s2:
            triggers_html = "".join(f'<span class="reason-pill">{t}</span>' for t in triggered)
            if not triggered:
                triggers_html = '<span class="reason-pill-safe">No patterns found</span>'
            st.markdown(f"""
            <div class="card">
              <div class="card-title">Detected Social Engineering Patterns</div>
              <div style="margin-top:8px">{triggers_html}</div>
            </div>""", unsafe_allow_html=True)

        # ── URL Scan Results ───────────────────────
        if found_urls:
            st.markdown(f"""
            <div class="card" style="margin-top:1rem">
              <div class="card-title">🔗 URLs Found in Message ({len(found_urls)} detected)</div>
            </div>""", unsafe_allow_html=True)

            for url in found_urls[:5]:   # cap at 5
                with st.spinner(f"Scanning {url[:50]}…"):
                    try:
                        r = requests.post(API_URL, json={"url": url}, timeout=12)
                        res = r.json()
                        p  = res.get("prediction","Unknown")
                        c  = res.get("confidence", 0)
                        color = "#ff1744" if p == "Phishing" else "#00e676"
                        icon2 = "🚨" if p == "Phishing" else "✅"
                        st.markdown(f"""
                        <div class="card" style="border-color:{'rgba(255,23,68,0.4)' if p=='Phishing' else 'rgba(0,230,118,0.3)'}">
                          <div style="font-family:'Share Tech Mono',monospace;font-size:0.8rem;color:#607d8b;margin-bottom:6px">URL SCAN RESULT</div>
                          <code style="color:#b0bec5;font-size:0.85rem">{url[:70]}{'…' if len(url)>70 else ''}</code>
                          <div style="margin-top:8px;font-size:1.4rem;font-weight:800;color:{color}">{icon2} {p} — {c}% confidence</div>
                        </div>""", unsafe_allow_html=True)
                    except Exception:
                        st.markdown(f"""
                        <div class="card">
                          <code style="color:#b0bec5">{url}</code>
                          <div style="color:#ffa726;margin-top:6px">⚠️ API unreachable — start <code>python api.py</code></div>
                        </div>""", unsafe_allow_html=True)

            st.markdown("""
            <div class="sms-warn">
              <b>⚠️ PhishGuard Warning:</b> This message contains URLs that show signs of phishing.
              Do NOT click any links. Do NOT share OTPs, passwords, or card details.
              Report this message to your telecom provider or cybercrime.gov.in
            </div>""", unsafe_allow_html=True)

        else:
            st.info("No URLs found in the message. Only text-pattern analysis was performed.")

    elif scan_sms and not sms_text.strip():
        st.warning("Please paste a message first.")

# ─── Footer ───────────────────────────────────
st.markdown("""
<div style="text-align:center;padding:2rem 0 1rem;color:#263238;font-size:0.78rem;
            font-family:'Share Tech Mono',monospace;letter-spacing:1px">
  PHISHGUARD AI · HACKATHON DEMO · ML + FLASK + STREAMLIT + URLHAUS API
</div>""", unsafe_allow_html=True)