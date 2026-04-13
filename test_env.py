# test_env.py - Test environment variable loading
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

print("=" * 50)
print("ENVIRONMENT VARIABLES TEST:")
print(f"ADMIN_SECRET_KEY: '{os.getenv('ADMIN_SECRET_KEY')}'")
print(f"ADMIN_REGISTRATION_KEY: '{os.getenv('ADMIN_REGISTRATION_KEY')}'")
print(f"MYSQL_HOST: '{os.getenv('MYSQL_HOST')}'")
print(f"MYSQL_USER: '{os.getenv('MYSQL_USER')}'")
print("=" * 50)

# Test key matching
key = os.getenv('ADMIN_SECRET_KEY', 'NOT FOUND')
expected = 'AgriGuard@2025'
print(f"Key matches expected '{expected}': {'✅ YES' if key == expected else '❌ NO'}")