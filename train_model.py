"""Train a multilingual social media fraud detection model.

This script:
1. Generates a realistic synthetic dataset for fraud, genuine, and neutral posts.
2. Builds a custom vectorizer with TF-IDF, character features, handcrafted pattern
   features, and latent semantic embedding features.
3. Trains a balanced multi-class Logistic Regression classifier.
4. Evaluates the model and stores artifacts compatible with ml_model.MLFraudDetector.

Run:
    python train_model.py
"""

from __future__ import annotations

import json
import os
import random
import re
import sys
from collections import Counter
from dataclasses import dataclass
from itertools import product
from pathlib import Path
from typing import Iterable, List

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix, hstack
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.decomposition import TruncatedSVD
from sklearn.feature_extraction.text import ENGLISH_STOP_WORDS, TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split


RANDOM_SEED = 42
MODELS_DIR = Path("models")
MODEL_PATH = MODELS_DIR / "fraud_detector.pkl"
VECTORIZER_PATH = MODELS_DIR / "vectorizer.pkl"
METRICS_PATH = MODELS_DIR / "training_metrics.json"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")


def _dedupe_keep_order(items: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for item in items:
        normalized = " ".join(item.split())
        if normalized not in seen:
            seen.add(normalized)
            result.append(normalized)
    return result


def _take(items: Iterable[str], count: int) -> List[str]:
    values = _dedupe_keep_order(items)
    if len(values) < count:
        raise ValueError(f"Needed {count} samples but generated only {len(values)}.")
    return values[:count]


def generate_fraud_posts() -> List[str]:
    english_prefixes = [
        "URGENT", "ALERT", "WINNER", "LIMITED TIME", "FINAL NOTICE", "ACT NOW",
        "CONGRATS", "EXCLUSIVE", "ATTENTION", "LAST CHANCE",
    ]
    english_lures = [
        "you won {reward}",
        "your account will be locked unless you verify",
        "claim your {reward} today",
        "government subsidy is waiting for release",
        "instant loan approval guaranteed",
        "crypto giveaway confirmed for selected users",
        "your KYC failed and needs urgent update",
        "free recharge available for premium users",
    ]
    english_actions = [
        "click {link}",
        "send OTP to agent now",
        "pay processing fee immediately",
        "share bank details in DM",
        "confirm card number today",
        "login here {link}",
        "download attachment from {link}",
        "reply with full account number",
    ]
    english_rewards = [
        "$1000", "$5000", "iPhone 15", "free voucher", "lottery prize", "bonus credit",
    ]
    english_links = [
        "http://verify-now.net", "bit.ly/claim-fast", "tinyurl.com/freebonus",
        "http://secure-login-check.com", "wa.me/919999999999", "t.me/helpdesk_verify",
    ]
    english_suffixes = [
        "#winner #giveaway", "#urgent #claimnow", "100% guaranteed", "NO RISK",
        "limited slots left", "offer expires tonight", "dm now", "reply instantly",
    ]

    hindi_prefixes = [
        "जरूरी सूचना", "तुरंत ध्यान दें", "बधाई हो", "अंतिम मौका", "सीमित समय ऑफर",
        "फाइनल अलर्ट", "अभी करें", "कन्फर्म विनर", "विशेष ऑफर", "सावधान",
    ]
    hindi_lures = [
        "आपने {reward} जीता है",
        "आपका अकाउंट बंद होने वाला है",
        "सरकारी सब्सिडी रिलीज के लिए तैयार है",
        "तुरंत लोन अप्रूवल मिल सकता है",
        "मुफ्त रिचार्ज आपके नाम पर है",
        "आपका केवाईसी फेल हो गया है",
        "लॉटरी इनाम अभी क्लेम करें",
        "कैशबैक केवल चुने हुए यूजर्स के लिए है",
    ]
    hindi_actions = [
        "{link} पर क्लिक करें",
        "ओटीपी अभी भेजें",
        "प्रोसेसिंग फीस तुरंत जमा करें",
        "बैंक डिटेल्स डीएम करें",
        "कार्ड नंबर वेरिफाई करें",
        "फॉर्म तुरंत भरें",
        "व्हाट्सएप पर जवाब दें",
        "अपना पासवर्ड कन्फर्म करें",
    ]
    hindi_rewards = [
        "1000 रुपये", "5000 रुपये", "मोबाइल फोन", "फ्री कूपन", "लकी ड्रा इनाम", "कैश बोनस",
    ]
    hindi_links = [
        "http://claim-subsidy.in", "bit.ly/fast-loan", "tinyurl.com/verify-kyc",
        "http://offer-center.xyz", "wa.me/918888888888", "t.me/official_help_claim",
    ]
    hindi_suffixes = [
        "#जीत #ऑफर", "#अभीकरें #लास्टचांस", "100 प्रतिशत गारंटी", "आज रात तक वैध",
        "सीटें कम हैं", "तुरंत जवाब दें", "कन्फर्म ऑफर", "कोई रिस्क नहीं",
    ]

    hinglish_prefixes = [
        "Urgent bhai", "Final warning", "Aaj ka special", "Congrats dost",
        "Attention users", "Instant offer", "Limited deal", "Account alert",
    ]
    hinglish_lures = [
        "aapka account suspend hone wala hai",
        "free cashback mil raha hai",
        "selected users ko {reward} mil raha hai",
        "verification pending hai",
        "loan approve karwana hai to abhi karo",
        "reward claim karne ka last chance hai",
        "free gift pack ready hai",
        "exclusive payment release pending hai",
    ]
    hinglish_actions = [
        "abhi {link} kholo",
        "OTP send karo",
        "processing fee pay karo",
        "DM me bank info bhejo",
        "login details share karo",
        "KYC abhi update karo",
        "message me PAN bhejo",
        "WhatsApp pe contact karo",
    ]
    hinglish_rewards = [
        "1000 rs", "5000 rs", "free iPhone", "gift voucher", "lottery reward", "bonus amount",
    ]
    hinglish_links = [
        "bit.ly/reward-now", "http://login-check.in", "tinyurl.com/otpclaim",
        "wa.me/917777777777", "t.me/quick_verify_help", "http://bonus-wallet.cc",
    ]
    hinglish_suffixes = [
        "#offer #jaldi", "#claimnow", "100% pakka", "reply fast", "aaj hi",
        "limited stock", "fake mat samjho", "abhi varna late ho jayega",
    ]

    posts = []
    for prefix, lure, action, reward, link, suffix in product(
        english_prefixes[:6], english_lures[:6], english_actions[:6],
        english_rewards[:4], english_links[:4], english_suffixes[:4]
    ):
        posts.append(f"{prefix}! {lure.format(reward=reward)}. {action.format(link=link)}. {suffix}")

    for prefix, lure, action, reward, link, suffix in product(
        hindi_prefixes[:6], hindi_lures[:6], hindi_actions[:6],
        hindi_rewards[:4], hindi_links[:4], hindi_suffixes[:4]
    ):
        posts.append(f"{prefix}! {lure.format(reward=reward)}. {action.format(link=link)}. {suffix}")

    for prefix, lure, action, reward, link, suffix in product(
        hinglish_prefixes[:6], hinglish_lures[:6], hinglish_actions[:6],
        hinglish_rewards[:4], hinglish_links[:4], hinglish_suffixes[:4]
    ):
        posts.append(f"{prefix}! {lure.format(reward=reward)}. {action.format(link=link)}. {suffix}")

    posts.extend([
        "WINNER!!! You've won $1000 cash. Click here http://verify-now.net and enter OTP now.",
        "URGENT! Your Instagram account will be locked. Verify at tinyurl.com/freebonus immediately.",
        "बधाई हो! आपने 5000 रुपये जीते हैं। प्रोसेसिंग फीस अभी जमा करें।",
        "Urgent bhai free recharge mil raha hai, bas OTP send karo aur reward claim karo.",
        "Final notice: your bank KYC failed, update now at http://secure-login-check.com",
    ])
    return _take(posts, 240)


def generate_genuine_posts() -> List[str]:
    english_subjects = [
        "morning walk", "new phone review", "family dinner", "football match",
        "coding practice", "college project", "coffee break", "photography tips",
        "weekend trip", "book recommendation",
    ]
    english_contexts = [
        "sharing my honest thoughts", "today's experience felt great",
        "this product worked well for me", "the service was smooth and reliable",
        "happy to recommend this to friends", "posting an update from my day",
        "small review after using it for a month", "nothing fancy just a normal update",
    ]
    english_hashtags = [
        "#dailylife", "#review", "#weekend", "#friends", "#travel", "#tech", "#happy", "#update",
    ]

    hindi_subjects = [
        "आज की चाय", "परिवार के साथ समय", "नया फोन", "कॉलेज प्रोजेक्ट",
        "सुबह की सैर", "किताब पढ़ना", "वीकेंड प्लान", "खाने की फोटो",
    ]
    hindi_contexts = [
        "आज का दिन अच्छा रहा", "ईमानदार रिव्यू शेयर कर रहा हूँ",
        "सेवा ठीक लगी", "दोस्तों के साथ अच्छा समय बिताया",
        "बस एक सामान्य अपडेट है", "अनुभव काफी अच्छा रहा",
        "फोटो अच्छी आई तो पोस्ट कर दी", "यह मेरा व्यक्तिगत अनुभव है",
    ]
    hindi_hashtags = [
        "#आज", "#दोस्त", "#रिव्यू", "#यादें", "#सामान्यपोस्ट", "#वीकेंड", "#खुशी", "#अपडेट",
    ]

    hinglish_subjects = [
        "movie night", "gym session", "office lunch", "new headphones",
        "road trip", "class notes", "festival shopping", "mobile camera test",
    ]
    hinglish_contexts = [
        "bas normal update share kar raha hoon", "honest review after one week use",
        "kaafi acha laga overall", "friends ke saath mast time tha",
        "just posting for memories", "service expected se better thi",
        "thoda mixed experience tha but okay", "simple post no drama",
    ]
    hinglish_hashtags = [
        "#vibes", "#reviewtime", "#normalpost", "#weekendvibes", "#memories", "#techlover",
    ]

    posts = []
    for subject, context, hashtag in product(english_subjects, english_contexts, english_hashtags[:5]):
        posts.append(f"Posting about my {subject}. {context}. {hashtag}")

    for subject, context, hashtag in product(hindi_subjects, hindi_contexts, hindi_hashtags[:5]):
        posts.append(f"{subject} के बारे में पोस्ट। {context}. {hashtag}")

    for subject, context, hashtag in product(hinglish_subjects, hinglish_contexts, hinglish_hashtags[:4]):
        posts.append(f"Aaj ka {subject} update. {context}. {hashtag}")

    posts.extend([
        "Tried a local cafe today and the coffee was actually pretty good. #review",
        "आज दोस्तों के साथ फोटोशूट किया, मौसम भी अच्छा था। #यादें",
        "New headphones ka sound balanced laga, battery bhi decent hai. #techlover",
        "Watched a match with family and had a quiet evening. #dailylife",
        "Phone camera low light me theek perform kar raha hai. #reviewtime",
    ])
    return _take(posts, 240)


def generate_neutral_posts() -> List[str]:
    english_topics = [
        "weather update", "market prices", "district traffic", "network issue",
        "maintenance notice", "public announcement", "meeting reminder", "schedule change",
    ]
    english_contexts = [
        "information may change during the day",
        "details will be updated later",
        "waiting for confirmation from the team",
        "more context is needed before acting",
        "nothing unusual has been confirmed yet",
        "this is for general awareness only",
    ]

    hindi_topics = [
        "मौसम अपडेट", "सार्वजनिक सूचना", "समय परिवर्तन", "नेटवर्क समस्या",
        "बैठक याद दिलाना", "प्रक्रिया अपडेट", "स्थानीय घोषणा", "स्टेटस संदेश",
    ]
    hindi_contexts = [
        "अधिक जानकारी बाद में दी जाएगी",
        "फिलहाल केवल सामान्य सूचना है",
        "अभी पुष्टि का इंतजार है",
        "स्थिति बदल सकती है",
        "निर्णय लेने से पहले और जानकारी चाहिए",
        "यह सिर्फ जागरूकता के लिए है",
    ]

    hinglish_topics = [
        "system update", "office notice", "community reminder", "status message",
        "general info", "event timing", "internet problem", "registration note",
    ]
    hinglish_contexts = [
        "abhi clear confirmation nahi hai",
        "ye sirf informational post hai",
        "details baad me update hongi",
        "filhal observe kar rahe hain",
        "normal status update only",
        "context aur chahiye before conclusion",
    ]

    posts = []
    for topic, context in product(english_topics, english_contexts):
        posts.append(f"{topic}: {context}.")

    for topic, context in product(hindi_topics, hindi_contexts):
        posts.append(f"{topic}: {context}.")

    for topic, context in product(hinglish_topics, hinglish_contexts):
        posts.append(f"{topic}: {context}.")

    posts.extend([
        "Random thought for the day: sometimes less information creates more confusion.",
        "Status unclear right now, waiting for the official update before saying more.",
        "आज सिर्फ सामान्य नोट डाल रहा हूँ, आगे और जानकारी आएगी।",
        "Meeting timing tentative hai, final message baad me aayega.",
    ])
    return _take(posts, 120)


def build_dataset() -> pd.DataFrame:
    fraud_posts = generate_fraud_posts()
    genuine_posts = generate_genuine_posts()
    neutral_posts = generate_neutral_posts()

    rows = (
        [{"text": text, "label": "fraud"} for text in fraud_posts] +
        [{"text": text, "label": "genuine"} for text in genuine_posts] +
        [{"text": text, "label": "neutral"} for text in neutral_posts]
    )

    random.Random(RANDOM_SEED).shuffle(rows)
    dataset = pd.DataFrame(rows)
    print(f"Dataset size: {len(dataset)}")
    print(f"Class counts: {dict(Counter(dataset['label']))}")
    return dataset


@dataclass
class TrainingArtifacts:
    model: LogisticRegression
    vectorizer: "SocialMediaVectorizer"


class SocialMediaVectorizer(BaseEstimator, TransformerMixin):
    """Custom vectorizer combining multiple text representations."""

    def __init__(self):
        self.word_vectorizer = TfidfVectorizer(
            analyzer="word",
            ngram_range=(1, 2),
            max_features=4000,
            min_df=2,
            sublinear_tf=True,
        )
        self.char_vectorizer = TfidfVectorizer(
            analyzer="char_wb",
            ngram_range=(3, 5),
            max_features=2500,
            min_df=2,
            sublinear_tf=True,
        )
        self.embedding_model = TruncatedSVD(n_components=64, random_state=RANDOM_SEED)
        self._feature_names = np.array([])
        self._hinglish_stopwords = {
            "hai", "hoga", "hogi", "ho", "kar", "karo", "ki", "ke", "ka", "mein",
            "mera", "meri", "mere", "abhi", "kal", "bas", "sirf", "wala", "wali",
            "liye", "se", "par", "aur", "ya", "to", "do", "kr", "pls", "please",
        }
        self._hindi_stopwords = {
            "है", "का", "की", "के", "को", "से", "और", "पर", "में", "यह", "वह",
            "एक", "ही", "भी", "तो", "या", "करें", "कर", "लिए", "आज", "अभी",
        }
        self._fraud_keywords = {
            "winner", "urgent", "verify", "otp", "lottery", "free", "claim", "reward",
            "subsidy", "click", "prize", "locked", "bonus", "gift", "cashback",
            "account", "processing", "fee", "kyc", "loan", "bank", "password",
            "जीता", "इनाम", "तुरंत", "ओटीपी", "फीस", "सब्सिडी", "क्लिक", "वेरिफाई",
            "loan", "verify", "gift", "cash", "dm", "login",
        }

    def fit(self, texts, y=None):
        cleaned = [self.preprocess_text(text) for text in texts]
        word_features = self.word_vectorizer.fit_transform(cleaned)
        char_features = self.char_vectorizer.fit_transform(cleaned)
        combined_sparse = hstack([word_features, char_features], format="csr")
        self.embedding_model.fit(combined_sparse)

        feature_names = []
        feature_names.extend([f"word::{name}" for name in self.word_vectorizer.get_feature_names_out()])
        feature_names.extend([f"char::{name}" for name in self.char_vectorizer.get_feature_names_out()])
        feature_names.extend([f"meta::{name}" for name in self._manual_feature_names()])
        feature_names.extend([f"embed::{index}" for index in range(self.embedding_model.n_components)])
        self._feature_names = np.array(feature_names, dtype=object)
        return self

    def transform(self, texts):
        cleaned = [self.preprocess_text(text) for text in texts]
        word_features = self.word_vectorizer.transform(cleaned)
        char_features = self.char_vectorizer.transform(cleaned)
        combined_sparse = hstack([word_features, char_features], format="csr")
        embedding_features = csr_matrix(self.embedding_model.transform(combined_sparse))
        manual_features = csr_matrix(np.array([self.extract_manual_features(text) for text in texts], dtype=float))
        return hstack([word_features, char_features, manual_features, embedding_features], format="csr")

    def get_feature_names_out(self):
        return self._feature_names

    def preprocess_text(self, text: str) -> str:
        text = str(text or "")
        text = text.lower()
        text = re.sub(r"https?://\S+|www\.\S+", " urltoken ", text)
        text = re.sub(r"@\w+", " mentiontoken ", text)
        text = re.sub(r"#(\w+)", r" hashtag_\1 ", text)
        text = re.sub(r"[^0-9a-z\u0900-\u097f_\s!?$₹%]", " ", text)
        tokens = []
        for token in text.split():
            if token in ENGLISH_STOP_WORDS or token in self._hinglish_stopwords or token in self._hindi_stopwords:
                continue
            tokens.append(token)
        return " ".join(tokens)

    def extract_manual_features(self, text: str) -> List[float]:
        text = str(text or "")
        lower_text = text.lower()
        tokens = re.findall(r"[\w\u0900-\u097f]+", lower_text)
        url_count = len(re.findall(r"https?://\S+|www\.\S+|bit\.ly/\S+|tinyurl\.com/\S+|wa\.me/\S+|t\.me/\S+", lower_text))
        suspicious_url_count = len(re.findall(r"bit\.ly|tinyurl|wa\.me|t\.me|login|verify|claim", lower_text))
        mention_count = len(re.findall(r"@\w+", text))
        hashtag_count = len(re.findall(r"#\w+", text))
        exclamation_count = text.count("!")
        currency_count = len(re.findall(r"₹|\$|rs\b|rupees", lower_text))
        digit_ratio = sum(char.isdigit() for char in text) / max(len(text), 1)
        uppercase_ratio = sum(char.isupper() for char in text) / max(sum(char.isalpha() for char in text), 1)
        keyword_hits = sum(token in self._fraud_keywords for token in tokens)
        suspicious_phrases = len(re.findall(r"urgent|winner|click here|otp|verify|account|locked|processing fee", lower_text))
        average_token_length = np.mean([len(token) for token in tokens]) if tokens else 0.0

        return [
            float(url_count),
            float(suspicious_url_count),
            float(mention_count),
            float(hashtag_count),
            float(exclamation_count),
            float(currency_count),
            float(digit_ratio),
            float(uppercase_ratio),
            float(keyword_hits),
            float(suspicious_phrases),
            float(average_token_length),
        ]

    @staticmethod
    def _manual_feature_names() -> List[str]:
        return [
            "url_count",
            "suspicious_url_count",
            "mention_count",
            "hashtag_count",
            "exclamation_count",
            "currency_count",
            "digit_ratio",
            "uppercase_ratio",
            "keyword_hits",
            "suspicious_phrase_hits",
            "average_token_length",
        ]


def top_features_by_class(model: LogisticRegression, vectorizer: SocialMediaVectorizer, top_n: int = 12):
    feature_names = vectorizer.get_feature_names_out()
    report = {}
    for class_index, class_name in enumerate(model.classes_):
        top_indices = np.argsort(model.coef_[class_index])[-top_n:][::-1]
        report[class_name] = [
            {"feature": str(feature_names[index]), "weight": float(model.coef_[class_index][index])}
            for index in top_indices
        ]
    return report


def print_confusion_matrix(labels: List[str], matrix: np.ndarray):
    print("\nConfusion Matrix:")
    header = "predicted-> " + " | ".join(f"{label:>8}" for label in labels)
    print(header)
    print("-" * len(header))
    for label, row in zip(labels, matrix):
        values = " | ".join(f"{value:>8}" for value in row)
        print(f"{label:>10} | {values}")


def train_model() -> TrainingArtifacts:
    print("=" * 70)
    print("Training multilingual social media fraud detection model")
    print("=" * 70)

    MODELS_DIR.mkdir(exist_ok=True)
    dataset = build_dataset()

    x_train, x_test, y_train, y_test = train_test_split(
        dataset["text"],
        dataset["label"],
        test_size=0.2,
        random_state=RANDOM_SEED,
        stratify=dataset["label"],
    )

    vectorizer = SocialMediaVectorizer()
    x_train_features = vectorizer.fit_transform(x_train)
    x_test_features = vectorizer.transform(x_test)

    print(f"Training samples: {len(x_train)}")
    print(f"Testing samples: {len(x_test)}")
    print(f"Feature dimension: {x_train_features.shape[1]}")

    model = LogisticRegression(
        max_iter=2000,
        class_weight="balanced",
        solver="lbfgs",
        random_state=RANDOM_SEED,
    )
    model.fit(x_train_features, y_train)

    predictions = model.predict(x_test_features)
    probabilities = model.predict_proba(x_test_features)
    accuracy = accuracy_score(y_test, predictions)

    print(f"\nAccuracy: {accuracy:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions, digits=4))

    labels = list(model.classes_)
    matrix = confusion_matrix(y_test, predictions, labels=labels)
    print_confusion_matrix(labels, matrix)

    feature_report = top_features_by_class(model, vectorizer)
    print("\nTop features by class:")
    for label, items in feature_report.items():
        formatted = ", ".join(f"{item['feature']} ({item['weight']:.3f})" for item in items[:8])
        print(f"  {label}: {formatted}")

    joblib.dump(model, MODEL_PATH)
    joblib.dump(vectorizer, VECTORIZER_PATH)

    metrics_payload = {
        "accuracy": float(accuracy),
        "labels": labels,
        "confusion_matrix": matrix.tolist(),
        "classification_report": classification_report(y_test, predictions, output_dict=True),
        "feature_importance": feature_report,
        "dataset_size": int(len(dataset)),
        "class_counts": {key: int(value) for key, value in Counter(dataset["label"]).items()},
        "average_confidence": float(np.mean(np.max(probabilities, axis=1))),
    }
    with METRICS_PATH.open("w", encoding="utf-8") as metrics_file:
        json.dump(metrics_payload, metrics_file, indent=2, ensure_ascii=False)

    print(f"\nSaved model to: {MODEL_PATH}")
    print(f"Saved vectorizer to: {VECTORIZER_PATH}")
    print(f"Saved metrics to: {METRICS_PATH}")

    return TrainingArtifacts(model=model, vectorizer=vectorizer)


def test_saved_model():
    from ml_model import MLFraudDetector

    print("\nSample predictions using MLFraudDetector:")
    detector = MLFraudDetector(str(MODEL_PATH), str(VECTORIZER_PATH))
    samples = [
        "WINNER! You have won $1000, verify now at bit.ly/claim-fast and send OTP.",
        "आज दोस्तों के साथ कैफे गया था, कॉफी और फोटो दोनों अच्छे थे।",
        "General reminder: timing may change after official notice.",
        "Urgent bhai account block hone wala hai, abhi login-check.in kholo.",
        "New headphones ka mic decent hai and battery backup bhi theek nikla.",
    ]
    for sample in samples:
        label, confidence = detector.predict(sample)
        explanation = detector.explain_prediction(sample, top_n=5)
        print(f"\nText: {sample}")
        print(f"Prediction: {label}")
        print(f"Confidence: {confidence:.4f}")
        print("Top signals:")
        for item in explanation[:5]:
            print(f"  - {item['feature']}: {item['importance']:.4f}")


def main():
    try:
        artifacts = train_model()
        _ = artifacts
        test_saved_model()
        print("\nTraining completed successfully.")
        print("The Flask app will automatically use the ML model when these files exist.")
    except Exception as exc:
        print(f"Training failed: {exc}")
        raise


if __name__ == "__main__":
    main()
