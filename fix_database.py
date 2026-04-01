import pymysql
import os
from dotenv import load_dotenv

load_dotenv()

# Get MySQL connection settings
config = {
    'host': os.getenv('MYSQL_HOST', '127.0.0.1'),
    'port': int(os.getenv('MYSQL_PORT', 3306)),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', ''),
    'database': os.getenv('MYSQL_DB_USERS', 'social_media_fraud_users'),
    'autocommit': True
}

print("Connecting to MySQL...")
conn = pymysql.connect(**config)
cursor = conn.cursor()

# Create users table (fixed for MySQL)
print("Creating users table...")
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(100) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        reset_token VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

print("Users table created successfully!")

# Connect to AgriGuard database
config['database'] = os.getenv('MYSQL_DB_AGRIGUARD', 'social_media_fraud_agriguard')
conn2 = pymysql.connect(**config)
cursor2 = conn2.cursor()

# Create posts table (fixed for MySQL)
print("Creating posts table...")
cursor2.execute("""
    CREATE TABLE IF NOT EXISTS posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(255) NOT NULL UNIQUE,
        content TEXT,
        platform VARCHAR(50),
        author VARCHAR(100),
        timestamp DATETIME,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
""")

# Create analysis_results table (fixed for MySQL)
print("Creating analysis_results table...")
cursor2.execute("""
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        post_id VARCHAR(255) NOT NULL,
        fraud_score FLOAT,
        classification VARCHAR(50),
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