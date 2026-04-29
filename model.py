"""
model.py — Train & save the Random Forest phishing detection model.
Run once before starting the API:  python model.py
"""

import re
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

# ─────────────────────────────────────────────
#  FEATURE EXTRACTION  (shared with api.py)
# ─────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "secure", "bank", "account", "update", "verify",
    "signin", "password", "confirm", "paypal", "ebay", "amazon",
    "apple", "microsoft", "support", "billing", "invoice", "free",
]

def extract_features(url: str) -> dict:
    url = str(url).lower().strip()

    # Basic counts
    length            = len(url)
    dot_count         = url.count(".")
    hyphen_count      = url.count("-")
    at_count          = url.count("@")
    slash_count       = url.count("/")
    double_slash      = int("//" in url)
    question_mark     = int("?" in url)
    equal_sign        = int("=" in url)
    ampersand         = url.count("&")
    percent_count     = url.count("%")
    digit_count       = sum(c.isdigit() for c in url)

    # Protocol / domain
    has_https         = int(url.startswith("https://"))
    has_http          = int(url.startswith("http://"))
    has_ip            = int(bool(re.search(r"\d{1,3}(\.\d{1,3}){3}", url)))

    # Suspicious keywords
    keyword_hits      = sum(kw in url for kw in SUSPICIOUS_KEYWORDS)

    # Domain-level
    try:
        domain_part = url.split("/")[2] if "//" in url else url.split("/")[0]
    except IndexError:
        domain_part = url
    domain_length     = len(domain_part)
    digits_in_domain  = sum(c.isdigit() for c in domain_part)
    subdomain_count   = domain_part.count(".")

    # Suspicious TLDs
    suspicious_tlds   = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
    has_suspicious_tld = int(any(url.endswith(t) for t in suspicious_tlds))

    return {
        "length":             length,
        "dot_count":          dot_count,
        "hyphen_count":       hyphen_count,
        "at_count":           at_count,
        "slash_count":        slash_count,
        "double_slash":       double_slash,
        "question_mark":      question_mark,
        "equal_sign":         equal_sign,
        "ampersand":          ampersand,
        "percent_count":      percent_count,
        "digit_count":        digit_count,
        "has_https":          has_https,
        "has_http":           has_http,
        "has_ip":             has_ip,
        "keyword_hits":       keyword_hits,
        "domain_length":      domain_length,
        "digits_in_domain":   digits_in_domain,
        "subdomain_count":    subdomain_count,
        "has_suspicious_tld": has_suspicious_tld,
    }

FEATURE_NAMES = list(extract_features("http://example.com").keys())


# ─────────────────────────────────────────────
#  SYNTHETIC DATASET GENERATOR
#  (Replace with your own CSV: columns = url, label)
# ─────────────────────────────────────────────

def build_synthetic_dataset(n=2000):
    """Generate a balanced synthetic dataset for demo purposes."""
    rng = np.random.default_rng(42)

    safe_templates = [
        "https://www.{domain}.com/{path}",
        "https://{domain}.org/{path}",
        "https://{domain}.edu/about",
        "https://docs.{domain}.com/guide",
    ]
    phish_templates = [
        "http://{domain}-login.tk/secure/{path}?verify=1",
        "http://secure-{domain}.xyz/account/update",
        "http://192.168.{a}.{b}/{path}?token=abc123",
        "http://{domain}.bankverify.cf/signin?redirect={domain}",
        "http://paypal-{domain}-billing.ml/confirm",
    ]
    safe_domains  = ["google","github","stackoverflow","wikipedia","microsoft",
                     "amazon","apple","youtube","reddit","bbc","cnn","nytimes"]
    phish_domains = ["securebank","loginupdate","accountverify","paypaluser",
                     "amazonsupport","appleid","microsoftoffice","ebayitem"]
    paths         = ["home","index","about","products","news","docs","blog"]

    rows = []
    for _ in range(n // 2):
        d  = rng.choice(safe_domains)
        p  = rng.choice(paths)
        t  = rng.choice(safe_templates)
        url = t.format(domain=d, path=p)
        rows.append({"url": url, "label": 0})

    for _ in range(n // 2):
        d  = rng.choice(phish_domains)
        p  = rng.choice(paths)
        t  = rng.choice(phish_templates)
        a, b = rng.integers(1, 255), rng.integers(1, 255)
        url  = t.format(domain=d, path=p, a=a, b=b)
        rows.append({"url": url, "label": 1})

    df = pd.DataFrame(rows).sample(frac=1, random_state=42).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────
#  TRAIN
# ─────────────────────────────────────────────

def train(csv_path: str = None):
    print("📂  Loading dataset …")
    if csv_path:
        df = pd.read_csv(csv_path)
        # Normalise column names
        df.columns = [c.strip().lower() for c in df.columns]
        if "label" not in df.columns:
            # Try common alternatives
            for alt in ["result","class","phishing","is_phishing","target"]:
                if alt in df.columns:
                    df.rename(columns={alt: "label"}, inplace=True)
                    break
        df["label"] = df["label"].astype(int)
    else:
        print("   No CSV provided — generating synthetic dataset …")
        df = build_synthetic_dataset(n=4000)

    print(f"   {len(df)} samples  |  phishing: {df['label'].sum()}  |  safe: {(df['label']==0).sum()}")

    print("🔧  Extracting features …")
    feature_rows = [extract_features(u) for u in df["url"]]
    X = pd.DataFrame(feature_rows)[FEATURE_NAMES].values
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("🌲  Training Random Forest …")
    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        min_samples_split=4,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    acc    = accuracy_score(y_test, y_pred)
    print(f"\n✅  Test accuracy: {acc*100:.2f}%")
    print(classification_report(y_test, y_pred, target_names=["Safe","Phishing"]))

    # Persist
    with open("model.pkl", "wb") as f:
        pickle.dump(clf, f)
    print("💾  model.pkl saved.\n")
    return clf


if __name__ == "__main__":
    import sys
    csv = sys.argv[1] if len(sys.argv) > 1 else None
    train(csv)