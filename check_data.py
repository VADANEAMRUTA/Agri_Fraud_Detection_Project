import os
import sys
import mysql.connector
from mysql.connector import Error


def get_mysql_connection():
    host = os.getenv('MYSQL_HOST')
    port = int(os.getenv('MYSQL_PORT', '44001'))
    user = os.getenv('MYSQL_USER')
    password = os.getenv('MYSQL_PASSWORD')
    database = os.getenv('MYSQL_DB_USERS')

    missing = [name for name, value in {
        'MYSQL_HOST': host,
        'MYSQL_USER': user,
        'MYSQL_PASSWORD': password,
        'MYSQL_DB_USERS': database,
    }.items() if not value]

    if missing:
        raise ValueError(
            'Missing required environment variables: ' + ', '.join(missing) +
            '. Set MYSQL_HOST, MYSQL_PORT, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB_USERS.'
        )

    return mysql.connector.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        connection_timeout=10,
    )


def fetch_rows(cursor, query, params=None, limit=10):
    cursor.execute(query, params or ())
    rows = cursor.fetchall()
    if len(rows) > limit:
        rows = rows[:limit]
    return rows


def main():
    print('Checking Railway MySQL connection...')
    try:
        conn = get_mysql_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute('SELECT COUNT(*) AS user_count FROM users')
        user_count = cursor.fetchone().get('user_count', 0)
        cursor.execute('SELECT COUNT(*) AS scan_count FROM scans')
        scan_count = cursor.fetchone().get('scan_count', 0)

        print(f'Connected successfully to {os.getenv("MYSQL_DB_USERS")}')
        print(f'- users count: {user_count}')
        print(f'- scans count: {scan_count}')

        print('\nLatest users:')
        users = fetch_rows(cursor, 'SELECT id, username, email, mobile, role, created_at FROM users ORDER BY created_at DESC')
        for row in users:
            print(f"  id={row['id']} username={row['username']} role={row['role']} created_at={row['created_at']}")

        print('\nLatest scans:')
        scans = fetch_rows(cursor, '''
            SELECT s.id, s.user_id, COALESCE(u.username, 'Anonymous') AS username,
                   s.content_type, s.result, s.confidence, s.created_at
            FROM scans s
            LEFT JOIN users u ON s.user_id = u.id
            ORDER BY s.created_at DESC
        ''')
        for row in scans:
            print(f"  id={row['id']} user_id={row['user_id']} username={row['username']} result={row['result']} confidence={row['confidence']} created_at={row['created_at']}")

    except (ValueError, Error) as exc:
        print('ERROR: ' + str(exc), file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            if cursor:
                cursor.close()
        except NameError:
            pass
        try:
            if conn:
                conn.close()
        except NameError:
            pass


if __name__ == '__main__':
    main()
