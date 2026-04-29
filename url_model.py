import pickle
from sklearn.linear_model import LogisticRegression

FEATURE_NAMES = ["length", "keyword_hits"]

def extract_features(url):
    keywords = ["login", "verify", "bank", "secure"]
    return {
        "length": len(url),
        "keyword_hits": sum(k in url.lower() for k in keywords)
    }

def train():
    data = [
        ("https://google.com", 0),
        ("http://secure-login-bank.xyz", 1),
        ("http://verify-account-alert.com", 1),
        ("https://github.com", 0)
    ]

    X, y = [], []

    for url, label in data:
        f = extract_features(url)
        X.append([f[k] for k in FEATURE_NAMES])
        y.append(label)

    model = LogisticRegression()
    model.fit(X, y)

    pickle.dump(model, open("url_model.pkl", "wb"))

if __name__ == "__main__":
    train()
