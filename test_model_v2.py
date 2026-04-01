from pathlib import Path

from ml_model import MLFraudDetector


def main():
    try:
        import sys

        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    model_path = Path("models/fraud_detector_v2.pkl")
    vectorizer_path = Path("models/vectorizer_v2.pkl")

    if not model_path.exists() or not vectorizer_path.exists():
        from train_model_v2 import train_model_v2

        print("v2 artifacts not found. Training them now...")
        train_model_v2()

    detector = MLFraudDetector(str(model_path), str(vectorizer_path))
    samples = [
        {
            "name": "legitimate_farmer_gov",
            "text": "Official farmer scheme information is available on the government portal.",
            "url": "https://farmer.gov.in/scheme",
        },
        {
            "name": "typosquat_former_gov",
            "text": "URGENT: verify your farmer subsidy immediately or your account will be blocked.",
            "url": "https://former.gov.in/verify",
        },
        {
            "name": "typosquat_india_gov",
            "text": "Urgent India portal verification is pending. Open the link now.",
            "url": "https://lndia.gov.in/verify",
        },
    ]

    for sample in samples:
        details = detector.predict_details(sample["text"], url=sample["url"])
        print("=" * 72)
        print(sample["name"])
        print(f"url: {sample['url']}")
        print(f"label: {details['label']}")
        print(f"display: {details['display_label']}")
        print(f"confidence: {details['confidence']:.4f}")
        print(f"probabilities: {details['probabilities']}")
        print("signals:")
        for item in details["explanation"][:6]:
            print(f"  - {item['feature']}: {item['importance']:.4f}")


if __name__ == "__main__":
    main()
