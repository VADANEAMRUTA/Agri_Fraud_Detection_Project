import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

DB_NAME = "users.db"

def create_user_table():
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            email TEXT,
            mobile TEXT,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

def register_user(username, email, mobile, password):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    hashed_password = generate_password_hash(password)
    cur.execute(
        "INSERT INTO users VALUES (NULL, ?, ?, ?, ?)",
        (username, email, mobile, hashed_password)
    )
    conn.commit()
    conn.close()

def validate_user(email, password):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute("SELECT password FROM users WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()
    if row:
        return check_password_hash(row[0], password)
    return False
