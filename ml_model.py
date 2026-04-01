import os
import re
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

import joblib
import numpy as np


def _first_url_from_text(text: str) -> Optional[str]:
    match = re.search(r"https?://\S+|www\.\S+", text or "", re.IGNORECASE)
    return match.group(0) if match else None


class MLFraudDetector:
    def __init__(
        self,
        model_path: str = "models/fraud_detector_v2.pkl",
        vectorizer_path: str = "models/vectorizer_v2.pkl",
    ):
        self.model = None
        self.vectorizer = None
        self.metadata: Dict[str, object] = {}
        self.is_loaded = False
        self.load_model(model_path, vectorizer_path)

    @property
    def is_trained(self) -> bool:
        return self.is_loaded

    def load_model(self, model_path: str = "models/fraud_detector_v2.pkl", vectorizer_path: str = "models/vectorizer_v2.pkl"):
        """Load the v2 fraud model and associated vectorizer."""
        try:
            os.makedirs("models", exist_ok=True)
            model_file = Path(model_path)
            vectorizer_file = Path(vectorizer_path)

            if not model_file.exists() or not vectorizer_file.exists():
                print("Model files not found. Using rule-based only.")
                print(f"   Looking for: {model_file}")
                print(f"   Looking for: {vectorizer_file}")
                self.model = None
                self.vectorizer = None
                self.metadata = {}
                self.is_loaded = False
                return

            # Ensure custom classes are importable before joblib deserializes artifacts.
            try:
                import train_model_v2 as train_module

                for attr in [
                    "FraudVectorizer",
                    "DomainFeatureExtractor",
                    "DomainReputationCache",
                    "SentenceEmbeddingExtractor",
                    "FallbackEmbeddingProjector",
                ]:
                    if hasattr(train_module, attr):
                        setattr(sys.modules["__main__"], attr, getattr(train_module, attr))
            except Exception:
                pass

            print(f"Loading ML model from {model_file}...")
            self.model = joblib.load(model_file)
            self.vectorizer = joblib.load(vectorizer_file)
            self.metadata = self.model.get("metadata", {}) if isinstance(self.model, dict) else {}
            self.is_loaded = True
            print("ML model loaded successfully")
        except Exception as exc:
            print(f"Error loading model: {exc}")
            self.model = None
            self.vectorizer = None
            self.metadata = {}
            self.is_loaded = False

    def _predict_record(self, text: str, url: Optional[str] = None) -> Dict[str, object]:
        if not self.is_loaded or self.model is None or self.vectorizer is None:
            return {
                "label": "neutral",
                "display_label": "⚠️ ML: Needs Review",
                "confidence": 0.5,
                "probabilities": {"neutral": 0.5},
                "url": url or _first_url_from_text(text),
            }

        resolved_url = url or _first_url_from_text(text)
        record = {"text": text or "", "url": resolved_url or ""}

        try:
            typosquat_target = ""
            if hasattr(self.vectorizer, "domain_features") and resolved_url:
                registered_domain = ""
                if hasattr(self.vectorizer.domain_features, "detect_typosquatting"):
                    try:
                        import train_model_v2 as train_module

                        registered_domain = train_module.split_domain(resolved_url).get("registered_domain", "")
                    except Exception:
                        registered_domain = resolved_url
                typosquat_flag, typosquat_target, _ = self.vectorizer.domain_features.detect_typosquatting(registered_domain)
                if typosquat_flag:
                    return {
                        "label": "fraud",
                        "display_label": "🚨 ML: Potential Fraud",
                        "confidence": 0.999,
                        "probabilities": {"fraud": 0.999, "genuine": 0.0005, "neutral": 0.0005},
                        "url": resolved_url,
                        "override_reason": f"Typosquatting detected: {registered_domain or resolved_url} is trying to mimic {typosquat_target}",
                    }

            features = self.vectorizer.transform_records([record])
            classifier = self.model["classifier"]
            label_encoder = self.model["label_encoder"]
            probabilities = classifier.predict_proba(features)[0]
            predicted_index = int(np.argmax(probabilities))
            raw_label = label_encoder.inverse_transform([predicted_index])[0]
            class_names = [str(value) for value in label_encoder.classes_]
            probability_map = {
                class_name: float(probabilities[index])
                for index, class_name in enumerate(class_names)
            }

            result_map = {
                "fraud": "🚨 ML: Potential Fraud",
                "genuine": "✅ ML: Genuine Content",
                "neutral": "⚠️ ML: Needs Review",
            }

            return {
                "label": raw_label,
                "display_label": result_map.get(raw_label, f"ML: {raw_label.title()}"),
                "confidence": float(probability_map.get(raw_label, 0.5)),
                "probabilities": probability_map,
                "url": resolved_url,
            }
        except Exception as exc:
            print(f"ML prediction error: {exc}")
            return {
                "label": "neutral",
                "display_label": "⚠️ ML: Error",
                "confidence": 0.5,
                "probabilities": {"neutral": 0.5},
                "url": resolved_url,
            }

    def predict(self, text: str, url: Optional[str] = None) -> Tuple[str, float]:
        prediction = self._predict_record(text, url)
        return str(prediction["display_label"]), float(prediction["confidence"])

    def predict_label(self, text: str, url: Optional[str] = None) -> Tuple[str, float]:
        prediction = self._predict_record(text, url)
        return str(prediction["label"]), float(prediction["confidence"])

    def predict_proba(self, text: str, url: Optional[str] = None) -> Dict[str, float]:
        prediction = self._predict_record(text, url)
        return dict(prediction["probabilities"])

    def predict_details(self, text: str, url: Optional[str] = None) -> Dict[str, object]:
        prediction = self._predict_record(text, url)
        explanation = self.explain_prediction(text, url=url, top_n=8)
        override_reason = prediction.get("override_reason")
        if override_reason:
            alert_feature = f"alert::{override_reason}"
            if not any(item.get("feature") == alert_feature for item in explanation):
                explanation = [{"feature": alert_feature, "importance": 12.0}] + explanation
        prediction["explanation"] = explanation
        return prediction

    def explain_prediction(self, text: str, url: Optional[str] = None, top_n: int = 8):
        if not self.is_loaded or self.vectorizer is None:
            return []

        try:
            return self.vectorizer.explain_record({"text": text or "", "url": url or _first_url_from_text(text) or ""}, top_n=top_n)
        except Exception as exc:
            print(f"Explanation error: {exc}")
            return []

    def train(self):
        """Train and reload the v2 model artifacts."""
        from train_model_v2 import train_model_v2

        train_model_v2()
        self.load_model()

    def get_status(self):
        return {
            "loaded": self.is_loaded,
            "has_model": self.model is not None,
            "has_vectorizer": self.vectorizer is not None,
            "artifact_version": self.metadata.get("artifact_version", "v2") if self.metadata else "unloaded",
        }


ml_model = MLFraudDetector()
