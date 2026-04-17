#!/usr/bin/env python3
"""
create_scans_table.py - Create the scans table in Railway MySQL for AgriGuard app

This script creates the scans table with proper schema if it doesn't exist.
Safe to run multiple times - will not error if table already exists.
"""

import mysql.connector
from mysql.connector import Error

# ANSI color codes for output
class Colors:
    GREEN = '\033[92m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_success(msg):
    print(f"{Colors.GREEN}✅ {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}ℹ️  {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠️  {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}❌ {msg}{Colors.END}")

def print_header(msg):
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{msg.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")

def connect_to_railway():
    """Connect to Railway MySQL database"""
    print_info("Connecting to Railway MySQL...")
    try:
        conn = mysql.connector.connect(
            host='nozomi.proxy.rlwy.net',
            port=44001,
            user='root',
            password='REPAGvsrvKQbpiePjVMnTQUHhOAhWwnQ',
            database='railway'
        )
        print_success("Connected to Railway MySQL successfully!")
        return conn
    except Error as e:
        print_error(f"Failed to connect to Railway MySQL: {e}")
        return None

def table_exists(cursor, table_name):
    """Check if a table exists"""
    cursor.execute(
        "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
        (table_name,)
    )
    return cursor.fetchone()[0] > 0

def create_scans_table(cursor):
    """Create the scans table if it doesn't exist"""
    if table_exists(cursor, 'scans'):
        print_warning("Table 'scans' already exists - skipping creation")
        return

    print_info("Creating scans table...")

    create_table_sql = """
    CREATE TABLE scans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        content_type VARCHAR(50),
        content TEXT,
        result VARCHAR(100),
        confidence FLOAT,
        detection_method VARCHAR(100) DEFAULT 'rule-based',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_user_id (user_id),
        INDEX idx_created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    """

    try:
        cursor.execute(create_table_sql)
        print_success("Created scans table successfully!")
    except Error as e:
        print_error(f"Failed to create scans table: {e}")
        raise

def show_table_columns(cursor, table_name):
    """Show columns of a table"""
    print_info(f"Columns in '{table_name}' table:")
    cursor.execute("SHOW COLUMNS FROM " + table_name)
    columns = cursor.fetchall()
    for col in columns:
        print(f"  - {col[0]}: {col[1]} {'NULL' if col[2] == 'YES' else 'NOT NULL'} {'AUTO_INCREMENT' if col[5] == 'auto_increment' else ''}")

def main():
    print_header("CREATE SCANS TABLE - RAILWAY MYSQL")
    print_info("This script will create the scans table if it doesn't exist")

    conn = connect_to_railway()
    if not conn:
        return

    cursor = conn.cursor()

    try:
        # Create table
        create_scans_table(cursor)

        # Commit changes
        conn.commit()
        print_success("Database changes committed successfully!")

        # Verify table
        if table_exists(cursor, 'scans'):
            show_table_columns(cursor, 'scans')
        else:
            print_error("Table 'scans' was not created successfully")

    except Error as e:
        print_error(f"Database error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()
        print_success("Database connection closed")

    print_header("SCANS TABLE CREATION COMPLETE")
    print_info("You can now run check_data.py to verify the database state")

if __name__ == '__main__':
    main()
