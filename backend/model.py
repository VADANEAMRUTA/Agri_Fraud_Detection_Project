import pickle
import re

model = pickle.load(open("backend/model.pkl", "rb"))
vectorizer = pickle.load(open("backend/vectorizer.pkl", "rb"))

def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-zA-Z0-9\s]", "", text)
    return text.strip()

def predict_text(text):
    text = clean_text(text)
    vec = vectorizer.transform([text])
    label = model.predict(vec)[0]
    confidence = max(model.predict_proba(vec)[0])
    return label, round(confidence * 100, 2)
