# fix_mysql_tables.py
import mysql.connector

print("=" * 60)
print("FIXING RAILWAY MYSQL DATABASE - ADD MISSING COLUMNS")
print("=" * 60)

# Railway MySQL connection
conn = mysql.connector.connect(
    host='nozomi.proxy.rlwy.net',
    port=44001,
    user='root',
    password='REPAGvsrvKQbpiePjVMnTQUHhOAhWwnQ',
    database='railway'
)

cursor = conn.cursor()

# ========== CHECK USERS TABLE ===========
print("\n📋 Checking users table...")

# Get existing columns
cursor.execute("SHOW COLUMNS FROM users")
existing_columns = [col[0] for col in cursor.fetchall()]
print(f"Existing columns: {existing_columns}")

# Add missing columns
missing = []

if 'created_at' not in existing_columns:
    print("➕ Adding created_at column...")
    cursor.execute("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    missing.append('created_at')

if 'role' not in existing_columns:
    print("➕ Adding role column...")
    cursor.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'farmer'")
    missing.append('role')

if 'fullname' not in existing_columns:
    print("➕ Adding fullname column...")
    cursor.execute("ALTER TABLE users ADD COLUMN fullname VARCHAR(255)")
    missing.append('fullname')

if 'mobile' not in existing_columns:
    print("➕ Adding mobile column...")
    cursor.execute("ALTER TABLE users ADD COLUMN mobile VARCHAR(15)")
    missing.append('mobile')

if not missing:
    print("✅ No missing columns found!")

# ========== CHECK SCANS TABLE ===========
print("\n📋 Checking scans table...")

cursor.execute("SHOW COLUMNS FROM scans")
scan_columns = [col[0] for col in cursor.fetchall()]
print(f"Existing columns: {scan_columns}")

if 'created_at' not in scan_columns:
    print("➕ Adding created_at column to scans...")
    cursor.execute("ALTER TABLE scans ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
else:
    print("✅ created_at column already exists")

# ========== UPDATE ADMIN USER ===========
print("\n🔧 Updating admin user...")
cursor.execute("UPDATE users SET role = 'admin' WHERE username = 'admin'")
conn.commit()
print(f"✅ Updated {cursor.rowcount} user(s) to admin role")

# ========== VERIFY RESULTS ===========
print("\n📋 Final columns in users table:")
cursor.execute("SHOW COLUMNS FROM users")
for col in cursor.fetchall():
    print(f"   - {col[0]}")

# Show users
print("\n👥 Users in database:")
cursor.execute("SELECT id, username, email, role, created_at FROM users")
for user in cursor.fetchall():
    print(f"   ID: {user[0]}, Username: {user[1]}, Email: {user[2]}, Role: {user[3]}, Created: {user[4]}")

# Count scans
cursor.execute("SELECT COUNT(*) FROM scans")
scan_count = cursor.fetchone()[0]
print(f"\n📊 Total scans: {scan_count}")

conn.commit()
cursor.close()
conn.close()

print("\n" + "=" * 60)
print("✅ DATABASE FIX COMPLETE!")
print("=" * 60)
print("\nNow redeploy on Render and test admin dashboard.")
