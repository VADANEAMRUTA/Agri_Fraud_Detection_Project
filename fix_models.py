# fix_models.py
import joblib
import os

print("=" * 50)
print("Fixing ML Models for Linux/Render Compatibility")
print("=" * 50)

# Check if models exist
if not os.path.exists('models/fraud_detector_v2.pkl'):
    print("❌ fraud_detector_v2.pkl not found!")
    exit(1)

if not os.path.exists('models/vectorizer_v2.pkl'):
    print("❌ vectorizer_v2.pkl not found!")
    exit(1)

print("✅ Models found. Re-saving for Linux compatibility...")

# Load models
model = joblib.load('models/fraud_detector_v2.pkl')
vectorizer = joblib.load('models/vectorizer_v2.pkl')

# Save them again (this removes Windows paths)
joblib.dump(model, 'models/fraud_detector_v2.pkl')
joblib.dump(vectorizer, 'models/vectorizer_v2.pkl')

print("✅ Models re-saved successfully!")
print("✅ Now push to GitHub:")
print("   git add models/*.pkl")
print("   git commit -m 'Fix ML models for Linux'")
print("   git push origin main")