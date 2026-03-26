# database.py - Simplified version that matches your SQLite approach
import sqlite3
from sqlite3 import Error

class AgriGuardDB:
    def __init__(self, db_file="agriguard.db"):
        self.db_file = db_file
        self.init_database()
    
    def create_connection(self):
        """Create a database connection"""
        try:
            conn = sqlite3.connect(self.db_file)
            conn.row_factory = sqlite3.Row
            return conn
        except Error as e:
            print(f"Error connecting to database: {e}")
            return None
    
    def init_database(self):
        """Initialize agriguard database tables"""
        conn = self.create_connection()
        if conn:
            try:
                cursor = conn.cursor()
                
                # Create user_activity table if not exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS user_activity_agri (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        activity_type TEXT NOT NULL,
                        description TEXT,
                        ip_address TEXT,
                        user_agent TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Create contact_messages table if not exists
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS contact_messages (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        subject TEXT,
                        message TEXT NOT NULL,
                        phone TEXT,
                        message_type TEXT DEFAULT 'general',
                        status TEXT DEFAULT 'unread',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                conn.close()
                print("AgriGuard database tables initialized!")
            except Error as e:
                print(f"Error creating AgriGuard tables: {e}")
    
    def get_user_activity(self, user_id=None, limit=50):
        """Get user activity logs"""
        try:
            conn = self.create_connection()
            cursor = conn.cursor()
            
            if user_id:
                cursor.execute('''
                    SELECT * FROM user_activity_agri 
                    WHERE user_id = ?
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT * FROM user_activity_agri 
                    ORDER BY created_at DESC
                    LIMIT ?
                ''', (limit,))
            
            activities = cursor.fetchall()
            conn.close()
            
            # Convert to list of dictionaries
            result = []
            for activity in activities:
                result.append(dict(activity))
            return result
        except Error as e:
            print(f"Error fetching activity: {e}")
            return []
    
    def add_activity_log(self, user_id, activity_type, description, ip_address=None, user_agent=None):
        """Add a new activity log"""
        try:
            conn = self.create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_activity_agri (user_id, activity_type, description, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, activity_type, description, ip_address, user_agent))
            conn.commit()
            conn.close()
            return True
        except Error as e:
            print(f"Error adding activity log: {e}")
            return False
    
    def add_contact_message(self, name, email, message, subject=None, phone=None, message_type='general'):
        """Add contact message to database"""
        try:
            conn = self.create_connection()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO contact_messages (name, email, subject, message, phone, message_type)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (name, email, subject, message, phone, message_type))
            conn.commit()
            message_id = cursor.lastrowid
            conn.close()
            return message_id
        except Error as e:
            print(f"Error adding contact message: {e}")
            return None

# Create a global instance
db_instance = AgriGuardDB()