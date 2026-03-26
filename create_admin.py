# create_admin.py
import sqlite3

def create_admin_user():
    """Create an admin user in the database"""
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if admin already exists
        c.execute("SELECT * FROM users WHERE username = 'admin'")
        existing_admin = c.fetchone()
        
        if existing_admin:
            print("⚠️ Admin user already exists!")
            # Update to admin if not already
            c.execute("UPDATE users SET account_type = 'admin' WHERE username = 'admin'")
            conn.commit()
            print("✅ Updated existing 'admin' user to admin type")
        else:
            # Create new admin user
            c.execute("""
                INSERT INTO users (username, email, password, account_type, fullname, mobile)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('admin', 'admin@agriguard.com', 'admin123', 'admin', 'System Administrator', '9999999999'))
            
            conn.commit()
            print("✅ Admin user created successfully!")
            print("   Username: admin")
            print("   Password: admin123")
            print("   Email: admin@agriguard.com")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Error creating admin: {e}")

if __name__ == "__main__":
    create_admin_user()