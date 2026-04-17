#!/usr/bin/env python3
"""
check_data.py - Verify Railway MySQL database state for AgriGuard app

Shows users and scans data to verify the database is working correctly.
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

def show_users_data(cursor):
    """Show users data"""
    print_header("USERS DATA")

    try:
        # Get total users count
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        print_success(f"Total users: {user_count}")

        if user_count > 0:
            print_info("List of users:")
            cursor.execute("SELECT id, username, email, role, created_at FROM users ORDER BY id")
            users = cursor.fetchall()
            for user in users:
                print(f"  ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}, Created: {user[4]}")
        else:
            print_warning("No users found in database")

    except Error as e:
        print_error(f"Failed to fetch users data: {e}")

def show_scans_data(cursor):
    """Show scans data"""
    print_header("SCANS DATA")

    try:
        # Check if scans table exists
        cursor.execute(
            "SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'scans'"
        )
        if cursor.fetchone()[0] == 0:
            print_warning("Scans table does not exist")
            return

        # Get total scans count
        cursor.execute("SELECT COUNT(*) FROM scans")
        scan_count = cursor.fetchone()[0]
        print_success(f"Total scans: {scan_count}")

        if scan_count > 0:
            print_info("Recent scans (last 10):")
            cursor.execute("""
                SELECT s.id, s.user_id, u.username, s.content_type, s.result, s.confidence, s.created_at
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.id
                ORDER BY s.created_at DESC
                LIMIT 10
            """)
            scans = cursor.fetchall()
            for scan in scans:
                username = scan[2] if scan[2] else 'Unknown'
                print(f"  ID: {scan[0]}, User: {username} (ID:{scan[1]}), Type: {scan[3]}, Result: {scan[4]}, Confidence: {scan[5]}, Created: {scan[6]}")
        else:
            print_warning("No scans found in database")

    except Error as e:
        print_error(f"Failed to fetch scans data: {e}")

def main():
    print_header("CHECK RAILWAY MYSQL DATA")
    print_info("Verifying users and scans data in Railway MySQL")

    conn = connect_to_railway()
    if not conn:
        return

    cursor = conn.cursor()

    try:
        # Show data
        show_users_data(cursor)
        show_scans_data(cursor)

    except Error as e:
        print_error(f"Database error: {e}")
    finally:
        cursor.close()
        conn.close()
        print_success("Database connection closed")

    print_header("DATA CHECK COMPLETE")
    print_info("If you see users and scans data above, your database is ready!")
    print_info("If scans table is missing, run create_scans_table.py first")

if __name__ == '__main__':
    main()


if __name__ == '__main__':
    main()
