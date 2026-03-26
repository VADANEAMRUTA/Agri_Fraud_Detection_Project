# train_ml_model.py
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import os

def create_sample_training_data():
    """Create sample training data for testing"""
    print("📝 Creating sample training data...")
    
    # More comprehensive training data
    fraud_examples = [
        # English fraud examples
        "free seeds no payment needed guaranteed delivery",
        "limited time offer buy one get ten free fertilizer",
        "secret government subsidy only for selected farmers",
        "urgent send money to get agricultural loan approved",
        "fake pesticide at 50 percent discount special offer",
        "get rich quick farming scheme earn millions monthly",
        "exclusive offer only for you confidential",
        "win tractor in lottery send registration fee",
        "miracle growth hormone doubles crop yield instantly",
        "government grant money transfer fees required",
        
        # Hindi fraud examples
        "मुफ्त बीज बिना भुगतान गारंटीड डिलीवरी",
        "सीमित समय ऑफर खरीदें एक मुफ्त दस उर्वरक",
        "गुप्त सरकारी सब्सिडी केवल चयनित किसानों के लिए",
        "अत्यावश्यक पैसे भेजें कृषि ऋण स्वीकृत करवाएं",
        "नकली कीटनाशक पचास प्रतिशत छूट विशेष ऑफर",
    ]
    
    genuine_examples = [
        # English genuine examples
        "namdhari seeds certified organic farming products with quality guarantee",
        "government agriculture department subsidy scheme for small farmers",
        "tata chemicals fertilizer with iso certification available at authorized dealers",
        "krishi vigyan kendra training program registration for modern farming techniques",
        "mahindra tractor authorized dealer showroom with service warranty",
        "coromandel international fertilizer company official distributor",
        "green gold organic products certified by agriculture ministry",
        "watermarket irrigation systems with government approved standards",
        "national seeds corporation limited certified seed varieties",
        "agriculture university workshop on sustainable farming practices",
        
        # Hindi genuine examples
        "नमधारी बीज प्रमाणित जैविक खेती उत्पाद गुणवत्ता गारंटी",
        "सरकार कृषि विभाग सब्सिडी योजना छोटे किसानों के लिए",
        "टाटा केमिकल्स उर्वरक आईएसओ प्रमाणन अधिकृत डीलरों पर उपलब्ध",
        "कृषि विज्ञान केंद्र प्रशिक्षण कार्यक्रम आधुनिक खेती तकनीक",
        "महिंद्रा ट्रैक्टर अधिकृत डीलर शोरूम सेवा वारंटी",
    ]
    
    neutral_examples = [
        # Neutral/Informational examples
        "agriculture farming techniques for better yield and soil health",
        "crop rotation methods improve soil fertility and reduce pests",
        "water conservation practices in agricultural irrigation systems",
        "organic farming workshop scheduled for next week at kvk",
        "market prices for wheat rice and pulses updated daily",
        "weather forecast for agricultural planning and crop management",
        "soil testing facilities available at district agriculture office",
        "new farming equipment demonstration at agriculture exhibition",
        "government guidelines for pesticide use and safety measures",
        "crop insurance scheme details and enrollment procedure",
    ]
    
    data = {
        'text': fraud_examples + genuine_examples + neutral_examples,
        'label': (['fraud'] * len(fraud_examples) + 
                  ['genuine'] * len(genuine_examples) + 
                  ['neutral'] * len(neutral_examples))
    }
    
    df = pd.DataFrame(data)
    print(f"✅ Created dataset with {len(df)} samples")
    print(f"   Fraud: {len(fraud_examples)}, Genuine: {len(genuine_examples)}, Neutral: {len(neutral_examples)}")
    
    return df

def train_model(save_path='models'):
    """Train ML model and save it"""
    print("="*60)
    print("🤖 TRAINING ML FRAUD DETECTION MODEL")
    print("="*60)
    
    # Create directory if it doesn't exist
    os.makedirs(save_path, exist_ok=True)
    
    # Load training data
    df = create_sample_training_data()
    
    # Prepare features and labels
    X = df['text']
    y = df['label']
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"📊 Data split: Train={len(X_train)}, Test={len(X_test)}")
    
    # Create TF-IDF features
    print("🔧 Creating text features...")
    vectorizer = TfidfVectorizer(
        max_features=1500,
        stop_words='english',
        ngram_range=(1, 3),
        min_df=2,
        max_df=0.9
    )
    
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)
    
    print(f"   Features created: {X_train_vec.shape[1]} dimensions")
    
    # Train model
    print("🧠 Training Random Forest model...")
    model = RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        class_weight='balanced',
        max_depth=10,
        min_samples_split=5,
        n_jobs=-1
    )
    
    model.fit(X_train_vec, y_train)
    
    # Evaluate
    train_score = model.score(X_train_vec, y_train)
    test_score = model.score(X_test_vec, y_test)
    
    print("\n📈 Model Performance:")
    print(f"   Training accuracy: {train_score:.2%}")
    print(f"   Testing accuracy: {test_score:.2%}")
    
    # Detailed classification report
    y_pred = model.predict(X_test_vec)
    print("\n📊 Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['fraud', 'genuine', 'neutral']))
    
    # Feature importance
    print("\n🔍 Top 10 Important Features:")
    feature_names = vectorizer.get_feature_names_out()
    importances = model.feature_importances_
    top_indices = importances.argsort()[-10:][::-1]
    
    for idx in top_indices:
        print(f"   {feature_names[idx]}: {importances[idx]:.4f}")
    
    # Save model and vectorizer
    model_path = os.path.join(save_path, 'fraud_detector.pkl')
    vectorizer_path = os.path.join(save_path, 'vectorizer.pkl')
    
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    
    print("\n💾 Model saved to:")
    print(f"   Model: {model_path}")
    print(f"   Vectorizer: {vectorizer_path}")
    
    # Save feature names for reference
    feature_names_path = os.path.join(save_path, 'feature_names.txt')
    with open(feature_names_path, 'w', encoding='utf-8') as f:
        for name in feature_names:
            f.write(name + '\n')
    
    print("="*60)
    print("✅ MODEL TRAINING COMPLETE!")
    print("="*60)
    
    return model, vectorizer

def test_model_sample():
    """Test the trained model with sample inputs"""
    print("\n🧪 Testing Model with Sample Inputs:")
    
    # Load model
    try:
        model = joblib.load('models/fraud_detector.pkl')
        vectorizer = joblib.load('models/vectorizer.pkl')
    except:
        print("   Model not found, training first...")
        model, vectorizer = train_model()
    
    # Test samples
    test_samples = [
        "free seeds guaranteed delivery no payment",
        "namdhari certified organic seeds",
        "agriculture farming techniques workshop",
        "secret government money transfer fees",
        "tata chemicals official fertilizer dealer"
    ]
    
    for text in test_samples:
        vec = vectorizer.transform([text])
        pred = model.predict(vec)[0]
        proba = model.predict_proba(vec)[0]
        confidence = max(proba)
        
        print(f"\n   Text: {text[:50]}...")
        print(f"   Prediction: {pred}")
        print(f"   Confidence: {confidence:.2%}")

if __name__ == "__main__":
    # Train model
    model, vectorizer = train_model()
    
    # Test with samples
    test_model_sample()