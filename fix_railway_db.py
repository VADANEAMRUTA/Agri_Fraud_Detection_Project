#!/usr/bin/env python3
"""
fix_railway_db.py - Fix Railway MySQL database schema for AgriGuard app

This script adds missing columns to the users and scans tables in Railway MySQL.
Safe to run multiple times - will not error if columns already exist.
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

def get_existing_columns(cursor, table_name):
    """Get list of existing columns in a table"""
    cursor.execute("SHOW COLUMNS FROM " + table_name)
    return [col[0] for col in cursor.fetchall()]

def add_column(cursor, table_name, column_name, definition):
    """Add a column to a table if it doesn't exist"""
    try:
        sql = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {definition}"
        cursor.execute(sql)
        print_success(f"Added column '{column_name}' to table '{table_name}'")
    except Error as e:
        if "Duplicate column name" in str(e):
            print_info(f"Column '{column_name}' already exists in '{table_name}'")
        else:
            print_error(f"Failed to add column '{column_name}' to '{table_name}': {e}")

def fix_users_table(cursor):
    """Fix the users table by adding missing columns"""
    print_header("FIXING USERS TABLE")

    existing_columns = get_existing_columns(cursor, 'users')
    print_info(f"Existing columns in users: {existing_columns}")

    # Define columns to add
    columns_to_add = {
        'created_at': 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP',
        'role': "VARCHAR(20) DEFAULT 'farmer'",
        'fullname': 'VARCHAR(255) NULL'
    }

    for col_name, definition in columns_to_add.items():
        if col_name not in existing_columns:
            add_column(cursor, 'users', col_name, definition)
        else:
            print_info(f"Column '{col_name}' already exists in users")

def fix_scans_table(cursor):
    """Fix the scans table by adding missing columns"""
    print_header("FIXING SCANS TABLE")

    existing_columns = get_existing_columns(cursor, 'scans')
    print_info(f"Existing columns in scans: {existing_columns}")

    # Add created_at if missing
    if 'created_at' not in existing_columns:
        add_column(cursor, 'scans', 'created_at', 'TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    else:
        print_info("Column 'created_at' already exists in scans")

def update_admin_user(cursor):
    """Update the admin user to have role='admin'"""
    print_header("UPDATING ADMIN USER")

    try:
        cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
        affected_rows = cursor.rowcount
        if affected_rows > 0:
            print_success(f"Updated {affected_rows} user(s) to admin role")
        else:
            print_warning("No users with username 'admin' found to update")
    except Error as e:
        print_error(f"Failed to update admin user: {e}")

def show_final_state(cursor):
    """Show final column lists and sample users"""
    print_header("FINAL DATABASE STATE")

    # Show users table columns
    print_info("Final columns in users table:")
    users_columns = get_existing_columns(cursor, 'users')
    for col in users_columns:
        print(f"  - {col}")

    # Show scans table columns
    print_info("Final columns in scans table:")
    scans_columns = get_existing_columns(cursor, 'scans')
    for col in scans_columns:
        print(f"  - {col}")

    # Show sample users
    print_info("Sample users in database:")
    try:
        cursor.execute("SELECT id, username, email, role, created_at FROM users LIMIT 5")
        users = cursor.fetchall()
        if users:
            for user in users:
                print(f"  ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}, Created: {user[4]}")
        else:
            print("  (no users found)")
    except Error as e:
        print_error(f"Failed to fetch sample users: {e}")

    # Show total counts
    try:
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM scans")
        scan_count = cursor.fetchone()[0]
        print_success(f"Database now has {user_count} users and {scan_count} scans")
    except Error as e:
        print_error(f"Failed to get counts: {e}")

def main():
    print_header("RAILWAY MYSQL DATABASE FIX")
    print_info("This script will add missing columns to your Railway MySQL database")
    print_info("Safe to run multiple times - existing data will be preserved")

    conn = connect_to_railway()
    if not conn:
        return

    cursor = conn.cursor()

    try:
        # Fix tables
        fix_users_table(cursor)
        fix_scans_table(cursor)

        # Update admin user
        update_admin_user(cursor)

        # Commit changes
        conn.commit()
        print_success("All database changes committed successfully!")

        # Show final state
        show_final_state(cursor)

    except Error as e:
        print_error(f"Database error: {e}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()
        print_success("Database connection closed")

    print_header("DATABASE FIX COMPLETE")
    print_info("You can now redeploy your Flask app on Render.com")
    print_info("The admin dashboard should work with the updated schema")

if __name__ == '__main__':
    main()
