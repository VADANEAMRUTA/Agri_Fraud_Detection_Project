# create_admin.py - Run this to create admin directly
import mysql.connector
from werkzeug.security import generate_password_hash
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def create_admin_user():
    """Create an admin user in the MySQL database"""
    try:
        # Connect to database
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", "root"),
            database=os.getenv("MYSQL_DB_USERS", "social_media_fraud_users")
        )
        cursor = conn.cursor()

        # Check if admin already exists
        cursor.execute("SELECT * FROM users WHERE username = 'admin'")
        existing_admin = cursor.fetchone()

        if existing_admin:
            print("⚠️ Admin user already exists!")
            # Update to admin if not already
            cursor.execute("UPDATE users SET account_type = 'admin' WHERE username = 'admin'")
            conn.commit()
            print("✅ Updated existing 'admin' user to admin type")
        else:
            # Create new admin user
            password_hash = generate_password_hash("admin123")
            cursor.execute("""
                INSERT INTO users (username, email, mobile, password, account_type, fullname)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, ('admin', 'admin@agriguard.com', '9999999999', password_hash, 'admin', 'System Administrator'))

            conn.commit()
            print("✅ Admin user created successfully!")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Email: admin@agriguard.com")
            print("   Role: admin")

        cursor.close()
        conn.close()

    except Exception as e:
        print(f"❌ Error creating admin: {e}")

if __name__ == "__main__":
    create_admin_user()