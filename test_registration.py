# test_registration.py - Test registration logic
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def test_registration_logic():
    """Test the registration logic without actually registering"""
    print("🧪 Testing Registration Logic...")

    # Test data
    test_cases = [
        {
            "role": "farmer",
            "admin_key": "",
            "expected_final_role": "farmer",
            "description": "Normal farmer registration"
        },
        {
            "role": "admin",
            "admin_key": "AgriGuard@2025",
            "expected_final_role": "admin",
            "description": "Valid admin registration"
        },
        {
            "role": "admin",
            "admin_key": "wrong_key",
            "expected_final_role": "farmer",  # Should be set to farmer due to invalid key
            "description": "Invalid admin key (should fail)"
        },
        {
            "role": "admin",
            "admin_key": "",
            "expected_final_role": "farmer",  # Should be set to farmer due to missing key
            "description": "Missing admin key (should fail)"
        }
    ]

    correct_key = os.getenv("ADMIN_SECRET_KEY", "AgriGuard@2025")
    print(f"✅ Admin key from .env: '{correct_key}'")

    for i, test in enumerate(test_cases, 1):
        print(f"\n📋 Test {i}: {test['description']}")
        print(f"   Input role: {test['role']}")
        print(f"   Input admin_key: '{test['admin_key']}'")

        # Simulate the logic
        final_role = "farmer"
        if test['role'] == "admin":
            if not test['admin_key'] or test['admin_key'] != correct_key:
                print("   ❌ Admin validation failed - would redirect with error")
                final_role = "farmer"
            else:
                print("   ✅ Admin validation passed")
                final_role = "admin"

        print(f"   Expected final_role: {test['expected_final_role']}")
        print(f"   Actual final_role: {final_role}")

        if final_role == test['expected_final_role']:
            print("   ✅ PASS")
        else:
            print("   ❌ FAIL")

    print("\n🎉 Registration logic test completed!")

if __name__ == "__main__":
    test_registration_logic()