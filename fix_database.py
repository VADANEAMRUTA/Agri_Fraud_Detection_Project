# fix_database.py - Fix MySQL database schema for AgriGuard
import mysql.connector
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def fix_database_schema():
    """Add missing columns to users table"""
    try:
        # Connect to MySQL database
        conn = mysql.connector.connect(
            host=os.getenv("MYSQL_HOST", "127.0.0.1"),
            port=int(os.getenv("MYSQL_PORT", 3306)),
            user=os.getenv("MYSQL_USER", "root"),
            password=os.getenv("MYSQL_PASSWORD", "root"),
            database=os.getenv("MYSQL_DB_USERS", "social_media_fraud_users")
        )
        cursor = conn.cursor()

        print("🔧 Fixing database schema...")

        # Add role column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'farmer'")
            print("✅ Added 'role' column")
        except mysql.connector.Error as e:
            if "Duplicate column name" in str(e):
                print("ℹ️ 'role' column already exists")
            else:
                print(f"❌ Error adding 'role' column: {e}")

        # Add account_type column if it doesn't exist (for backward compatibility)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN account_type VARCHAR(50) DEFAULT 'farmer'")
            print("✅ Added 'account_type' column")
        except mysql.connector.Error as e:
            if "Duplicate column name" in str(e):
                print("ℹ️ 'account_type' column already exists")
            else:
                print(f"❌ Error adding 'account_type' column: {e}")

        # Add mobile column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN mobile VARCHAR(15)")
            print("✅ Added 'mobile' column")
        except mysql.connector.Error as e:
            if "Duplicate column name" in str(e):
                print("ℹ️ 'mobile' column already exists")
            else:
                print(f"❌ Error adding 'mobile' column: {e}")

        # Add created_at column if it doesn't exist
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            print("✅ Added 'created_at' column")
        except mysql.connector.Error as e:
            if "Duplicate column name" in str(e):
                print("ℹ️ 'created_at' column already exists")
            else:
                print(f"❌ Error adding 'created_at' column: {e}")

        # Check current table structure
        cursor.execute("DESCRIBE users")
        columns = cursor.fetchall()
        print(f"\n📋 Current users table structure:")
        for col in columns:
            print(f"   - {col[0]}: {col[1]}")

        conn.commit()
        cursor.close()
        conn.close()

        print("\n✅ Database schema fixed successfully!")

    except Exception as e:
        print(f"❌ Error fixing database schema: {e}")

if __name__ == "__main__":
    fix_database_schema()
        risk_level VARCHAR(50),
        analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(post_id)
    )
""")

# Create suspicious_patterns table (fixed for MySQL)
print("Creating suspicious_patterns table...")
cursor2.execute("""
    CREATE TABLE IF NOT EXISTS suspicious_patterns (
        id INT AUTO_INCREMENT PRIMARY KEY,
        pattern_name VARCHAR(100),
        description TEXT,
        severity VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

print("All tables created successfully!")

# Close connections
cursor.close()
conn.close()
cursor2.close()
conn2.close()

print("\n✅ Database setup completed!")
print("You can now run: python app.py")