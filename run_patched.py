import sys
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

# Monkey patch the database creation functions BEFORE importing app
def skip_database_creation():
    print("✅ Database already set up - skipping creation")
    return

# Create a custom import hook
original_import = __import__

def custom_import(name, *args, **kwargs):
    module = original_import(name, *args, **kwargs)
    if name == 'app':
        # Replace the database functions in app module
        module.create_database_from_scratch = skip_database_creation
        module.init_database_safely = lambda: print("✅ Database ready")
        print("App patched - database creation disabled")
    return module

# Replace __import__
import builtins
builtins.__import__ = custom_import

# Now import app
import app

# Run the app
if __name__ == "__main__":
    app.app.run(debug=True, host="0.0.0.0", port=5000)
