import pickle, re, pandas as pd
from sklearn.ensemble import RandomForestClassifier

def extract_features(url):
    return {
        "length": len(url),
        "keyword_hits": sum(k in url for k in ["login","bank","verify"])
    }

FEATURE_NAMES = ["length","keyword_hits"]

def train():
    data = [
        ("https://google.com",0),
        ("http://secure-login-bank.xyz",1)
    ]

    X = []
    y = []

    for url,label in data:
        f = extract_features(url)
        X.append([f[k] for k in FEATURE_NAMES])
        y.append(label)

    model = RandomForestClassifier()
    model.fit(X,y)

    pickle.dump(model, open("model.pkl","wb"))

train()
