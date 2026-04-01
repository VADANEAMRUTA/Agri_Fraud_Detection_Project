import pymysql
import os
from dotenv import load_dotenv

# Load environment
load_dotenv()

print("=" * 60)
print("FIXING DATABASE TABLES")
print("=" * 60)

# Connect to MySQL without selecting database
config = {
    "host": os.getenv("MYSQL_HOST", "127.0.0.1"),
    "port": int(os.getenv("MYSQL_PORT", 3306)),
    "user": os.getenv("MYSQL_USER", "root"),
    "password": os.getenv("MYSQL_PASSWORD", "")
}

conn = pymysql.connect(**config)
cursor = conn.cursor()

# Drop existing databases to start fresh
print("Dropping existing databases...")
try:
    cursor.execute("DROP DATABASE IF EXISTS social_media_fraud_agriguard")
    cursor.execute("DROP DATABASE IF EXISTS social_media_fraud_users")
    print("Old databases dropped")
except Exception as e:
    print(f"Note: {e}")

# Create fresh databases
print("Creating fresh databases...")
cursor.execute("CREATE DATABASE social_media_fraud_users")
cursor.execute("CREATE DATABASE social_media_fraud_agriguard")
print("Databases created")

conn.close()

# Create tables in users database
print("\nCreating users table...")
conn = pymysql.connect(
    host=os.getenv("MYSQL_HOST", "127.0.0.1"),
    user=os.getenv("MYSQL_USER", "root"),
    password=os.getenv("MYSQL_PASSWORD", ""),
    database="social_media_fraud_users"
)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        reset_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")
print("Users table created")

conn.close()

# Create tables in agriguard database
print("\nCreating AgriGuard tables...")
conn = pymysql.connect(
    host=os.getenv("MYSQL_HOST", "127.0.0.1"),
    user=os.getenv("MYSQL_USER", "root"),
    password=os.getenv("MYSQL_PASSWORD", ""),
    database="social_media_fraud_agriguard"
)
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(255) NOT NULL UNIQUE,
        content TEXT,
        platform VARCHAR(50),
        author VARCHAR(100),
        timestamp DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

cursor.execute("""
    CREATE TABLE analysis_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(255) NOT NULL,
        fraud_score FLOAT,
        classification VARCHAR(50),
        risk_level VARCHAR(50),
        analysis_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(post_id)
    )
""")

cursor.execute("""
    CREATE TABLE suspicious_patterns (
        id INT AUTO_INCREMENT PRIMARY KEY,
        pattern_name VARCHAR(100),
        description TEXT,
        severity VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

print("All AgriGuard tables created")
conn.close()

print("\n" + "=" * 60)
print("✅ DATABASE SETUP COMPLETE")
print("=" * 60)
print("\nNow starting the application...")
print("=" * 60)

# Now run the original app
import app
