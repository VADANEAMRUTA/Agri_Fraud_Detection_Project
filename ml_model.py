# ml_model.py
import joblib
import numpy as np
import json
from pathlib import Path
import os

class MLFraudDetector:
    def __init__(self, model_path='models/fraud_detector.pkl', 
                 vectorizer_path='models/vectorizer.pkl'):
        self.model = None
        self.vectorizer = None
        self.is_loaded = False
        self.load_model(model_path, vectorizer_path)
        
    def load_model(self, model_path, vectorizer_path):
        """Load trained model and vectorizer"""
        try:
            # Create models directory if it doesn't exist
            os.makedirs('models', exist_ok=True)
            
            if Path(model_path).exists() and Path(vectorizer_path).exists():
                print(f"📦 Loading ML model from {model_path}...")
                self.model = joblib.load(model_path)
                self.vectorizer = joblib.load(vectorizer_path)
                self.is_loaded = True
                print("✅ ML Model loaded successfully")
            else:
                print("⚠️ Model files not found. Using rule-based only.")
                print(f"   Looking for: {model_path}")
                print(f"   Looking for: {vectorizer_path}")
                self.model = None
                self.vectorizer = None
                self.is_loaded = False
        except Exception as e:
            print(f"❌ Error loading model: {e}")
            self.model = None
            self.vectorizer = None
            self.is_loaded = False
    
    def predict(self, text):
        """Predict fraud using ML model"""
        if not self.is_loaded or self.model is None or self.vectorizer is None:
            return "neutral", 0.5  # Default if model not loaded
        
        try:
            # Transform text
            text_vec = self.vectorizer.transform([text])
            
            # Get prediction and probability
            prediction = self.model.predict(text_vec)[0]
            probabilities = self.model.predict_proba(text_vec)[0]
            
            # Get confidence (max probability)
            confidence = max(probabilities)
            
            # Map prediction to readable format
            result_map = {
                'fraud': '🚨 ML: Potential Fraud',
                'genuine': '✅ ML: Genuine Content',
                'neutral': '⚠️ ML: Needs Review'
            }
            
            return result_map.get(prediction, '⚠️ ML: Unknown'), confidence
            
        except Exception as e:
            print(f"❌ ML Prediction error: {e}")
            return "⚠️ ML: Error", 0.5
    
    def explain_prediction(self, text, top_n=5):
        """Explain why ML made this prediction"""
        if not self.is_loaded or self.vectorizer is None or self.model is None:
            return []
        
        try:
            # Get feature names
            feature_names = self.vectorizer.get_feature_names_out()
            text_vec = self.vectorizer.transform([text])
            
            # Get feature contributions
            feature_weights = text_vec.toarray()[0]
            important_features = []
            
            for idx, weight in enumerate(feature_weights):
                if weight > 0.01:  # Only include meaningful weights
                    # Calculate approximate importance
                    importance = weight
                    important_features.append({
                        'feature': feature_names[idx],
                        'weight': float(weight),
                        'importance': float(importance)
                    })
            
            # Sort by importance
            important_features.sort(key=lambda x: x['importance'], reverse=True)
            return important_features[:top_n]
            
        except Exception as e:
            print(f"❌ Explanation error: {e}")
            return []
    
    def get_status(self):
        """Get model status"""
        return {
            'loaded': self.is_loaded,
            'has_model': self.model is not None,
            'has_vectorizer': self.vectorizer is not None
        }