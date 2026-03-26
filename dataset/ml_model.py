import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

# Load OCR dataset
df = pd.read_csv("dataset/data.csv")

# Quick look
print(df.head())

# ------------------------
# STEP 1: TEXT PREPROCESSING
# ------------------------
import re

def clean_text(text):
    # Lowercase
    text = text.lower()
    # Remove URLs
    text = re.sub(r"http\S+|bit\.ly/\S+|wa\.me/\S+|telegram\.me/\S+", "", text)
    # Remove special characters except letters and numbers
    text = re.sub(r"[^a-zA-Z0-9\s]", "", text)
    # Remove extra spaces
    text = re.sub(r"\s+", " ", text).strip()
    return text

df['clean_text'] = df['text'].apply(clean_text)

# ------------------------
# STEP 2: FEATURE ENGINEERING (TF-IDF)
# ------------------------
vectorizer = TfidfVectorizer(max_features=500)
X = vectorizer.fit_transform(df['clean_text'])
y = df['label']

# ------------------------
# STEP 3: TRAIN-TEST SPLIT
# ------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ------------------------
# STEP 4: MODEL TRAINING
# ------------------------
# Naive Bayes
nb_model = MultinomialNB()
nb_model.fit(X_train, y_train)

# Logistic Regression
lr_model = LogisticRegression(max_iter=1000)
lr_model.fit(X_train, y_train)

# ------------------------
# STEP 5: EVALUATION
# ------------------------
for model_name, model in [("Naive Bayes", nb_model), ("Logistic Regression", lr_model)]:
    y_pred = model.predict(X_test)
    print(f"\n=== {model_name} ===")
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))
    print("Classification Report:\n", classification_report(y_test, y_pred))

# ------------------------
# STEP 6: PREDICTION WITH CONFIDENCE SCORE
# ------------------------
def predict_ad(text, model=lr_model):
    text = clean_text(text)
    vector = vectorizer.transform([text])
    pred = model.predict(vector)[0]
    conf = max(model.predict_proba(vector)[0])
    return pred, conf

# Test prediction
sample_text = "🚨 Farmer Alert Get 90% Fertilizer Subsidy Click here 👉 bit.ly/farm123"
label, confidence = predict_ad(sample_text)
print("\nSample Prediction:", label, "with confidence", round(confidence, 2))

import pickle

# Save best model (Logistic Regression)
pickle.dump(lr_model, open("backend/model.pkl", "wb"))
pickle.dump(vectorizer, open("backend/vectorizer.pkl", "wb"))

print("✅ Model & Vectorizer saved for backend")
