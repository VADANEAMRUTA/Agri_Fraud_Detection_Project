import mysql.connector
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

load_dotenv()

MYSQL_HOST = os.getenv("MYSQL_HOST", "nozomi.proxy.rlwy.net")
MYSQL_PORT = os.getenv("MYSQL_PORT", "44001")
MYSQL_USER = os.getenv("MYSQL_USER", "root")
MYSQL_PASSWORD = os.getenv("MYSQL_PASSWORD", "REPAGvsrvKQbpiePjVMnTQUHhOAhWwnQ")
MYSQL_DB_USERS = os.getenv("MYSQL_DB_USERS", "railway")
MYSQL_DB_AGRIGUARD = os.getenv("MYSQL_DB_AGRIGUARD", "railway")


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def get_connection(database):
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=_safe_int(MYSQL_PORT, 44001),
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=database,
    )


def create_tables(database):
    print(f"Creating tables in database: {database}")
    conn = get_connection(database)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL UNIQUE,
            email VARCHAR(255) NOT NULL UNIQUE,
            mobile VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(255) NOT NULL,
            fullname VARCHAR(255),
            location VARCHAR(255),
            profile_pic VARCHAR(255),
            language VARCHAR(10) DEFAULT 'en',
            email_notifications BOOLEAN DEFAULT TRUE,
            account_type VARCHAR(50) DEFAULT 'standard',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reset_token VARCHAR(255),
            reset_token_expiry DATETIME
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            content_type VARCHAR(50),
            content TEXT,
            result TEXT,
            confidence FLOAT,
            detection_method VARCHAR(100) DEFAULT 'rule-based',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_activity (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            action VARCHAR(255),
            details TEXT,
            type VARCHAR(100),
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    conn.commit()
    cursor.close()
    conn.close()
    print("✅ Tables ensured.")


def create_admin_user(database):
    print(f"Ensuring admin user exists in database: {database}")
    conn = get_connection(database)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = 'admin' LIMIT 1")
    existing_admin = cursor.fetchone()

    if existing_admin:
        print("⚠️ Admin user already exists.")
        cursor.execute("UPDATE users SET account_type = 'admin' WHERE username = 'admin'")
        conn.commit()
        print("✅ Updated existing admin user to admin account type.")
    else:
        password_hash = generate_password_hash("admin123")
        cursor.execute(
            """
            INSERT INTO users (username, email, mobile, password, account_type, fullname)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            ('admin', 'admin@agriguard.com', '9999999999', password_hash, 'admin', 'System Administrator')
        )
        conn.commit()
        print("✅ Admin user created successfully.")
        print("   Username: admin")
        print("   Password: admin123")

    cursor.close()
    conn.close()


if __name__ == '__main__':
    print("Initializing Railway MySQL database...")
    print(f"Host: {MYSQL_HOST}")
    print(f"Port: {_safe_int(MYSQL_PORT, 44001)}")
    print(f"User: {MYSQL_USER}")
    print(f"Database: {MYSQL_DB_USERS}")

    create_tables(MYSQL_DB_USERS)
    create_admin_user(MYSQL_DB_USERS)
    print("Initialization complete.")
