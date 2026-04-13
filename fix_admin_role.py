# fix_admin_role.py - Fix admin role for existing users
import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def fix_admin_role():
    """Update user role to admin"""
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", "root"),
            database=os.getenv("MYSQL_DB_USERS", "social_media_fraud_users")
        )
        cursor = conn.cursor(dictionary=True)

        # Check current user
        username = "Shree"
        cursor.execute("SELECT id, username, email, role FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if user:
            print(f"Current user: {user}")
            if user['role'] != 'admin':
                # Update role to admin
                cursor.execute("UPDATE users SET role = 'admin' WHERE username = %s", (username,))
                conn.commit()
                print(f"✅ Updated {username} role to 'admin'")
            else:
                print(f"✅ {username} already has admin role")
        else:
            print(f"❌ User '{username}' not found in database")

        # Show all admin users
        cursor.execute("SELECT id, username, email, role FROM users WHERE role = 'admin'")
        admins = cursor.fetchall()
        print(f"\n📋 All admin users: {admins}")

        conn.close()

    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    fix_admin_role()