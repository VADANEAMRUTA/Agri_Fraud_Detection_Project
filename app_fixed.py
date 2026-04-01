from dotenv import load_dotenv
load_dotenv()
import sqlite3
from flask import Flask, request, render_template, redirect, session, flash, jsonify, url_for
from PIL import Image, ImageEnhance, ImageFilter
import pytesseract
import re
import os
import tempfile
import requests
from bs4 import BeautifulSoup
import urllib.parse
from urllib.parse import urlparse
import json
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from content_validator import ContentValidator
# Import the database instance
from database import db_instance


# Import ML model - handle import errors gracefully
try:
    from ml_model import MLFraudDetector
    ml_detector = MLFraudDetector()
    ML_AVAILABLE = True
except ImportError:
    print("⚠️ ML Model not available. Using rule-based detection only.")
    ml_detector = None
    ML_AVAILABLE = False

# Create uploads directory if it doesn't exist
os.makedirs('static/uploads/profile_pics', exist_ok=True)

# ---------------- FLASK SETUP ----------------
app = Flask(__name__)
app.secret_key = "agri_fraud_secret"
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

DATABASE_ALIASES = ['users.db', 'agriguard.db']


def mysql_connection_available(db_name):
    """Check whether the configured MySQL schema is reachable."""
    try:
        conn = sqlite3.connect(db_name)
        conn.execute("SELECT 1")
        conn.close()
        return True
    except Exception:
        return False

# ---------------- LOGIN REQUIRED DECORATOR ----------------
def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first", "error")
            return redirect(url_for('login_selector'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------- ADMIN REQUIRED DECORATOR ----------------
def admin_required(f):
    """Decorator to require admin access"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first", "error")
            return redirect(url_for('login_selector'))
        
        # Check if user is admin
        is_admin = (session.get('account_type') == 'admin' or 
                   session.get('username') == 'admin')
        
        if not is_admin:
            flash("Admin access required!", "error")
            return render_template("admin_access.html")
        
        return f(*args, **kwargs)
    return decorated_function

# ---------------- DATABASE INITIALIZATION ----------------
def init_database_safely():
    """Initialize database safely without dropping existing data"""
    import sqlite3
    import os
    
    print("="*50)
    print("CHECKING DATABASE...")
    print("="*50)
    
    # Check if database exists
    if not os.path.exists("users.db"):
        print("📁 users.db not found, creating new database...")
        create_database_from_scratch()
    else:
        print("✅ users.db exists, checking structure...")
        verify_and_repair_database()
    
    # Create admin user if not exists
    create_admin_user()
    
    print("="*50 + "\n")

def create_database_from_scratch():
    """Create a completely new database"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Create users table (ONLY if it doesn't exist)
        c.execute("""
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                mobile TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                fullname TEXT,
                location TEXT,
                profile_pic TEXT,
                language TEXT DEFAULT 'en',
                email_notifications BOOLEAN DEFAULT 1,
                account_type TEXT DEFAULT 'standard',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_token_expiry DATETIME
            )
        """)
        
        # Create scans table (ONLY if it doesn't exist)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                content_type TEXT,
                content TEXT,
                result TEXT,
                confidence REAL,
                detection_method TEXT DEFAULT 'rule-based',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Create user_activity table (ONLY if it doesn't exist)
        c.execute("""
            CREATE TABLE IF NOT EXISTS user_activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT,
                details TEXT,
                type TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        
        # Create indexes for better performance
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_user_id ON user_activity(user_id)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON user_activity(timestamp)")
        
        conn.commit()
        conn.close()
        
        print("✅ Created new users.db with all tables!")
        
    except Exception as e:
        print(f"❌ Error creating database: {e}")
        raise e

def verify_and_repair_database():
    """Verify database structure and add missing tables/columns WITHOUT dropping data"""
    import sqlite3
    
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Check which tables exist
        c.execute("SELECT name FROM sqlite_master WHERE type='table'")
        existing_tables = [row[0] for row in c.fetchall()]
        print(f"   Found tables: {existing_tables}")
        
        # Create missing tables WITHOUT dropping existing ones
        if 'users' not in existing_tables:
            print("   Creating missing 'users' table...")
            c.execute("""
                CREATE TABLE users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    mobile TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    fullname TEXT,
                    location TEXT,
                    profile_pic TEXT,
                    language TEXT DEFAULT 'en',
                    email_notifications BOOLEAN DEFAULT 1,
                    account_type TEXT DEFAULT 'standard',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    reset_token TEXT,
                    reset_token_expiry DATETIME
                )
            """)
        
        if 'scans' not in existing_tables:
            print("   Creating missing 'scans' table...")
            c.execute("""
                CREATE TABLE scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    content_type TEXT,
                    content TEXT,
                    result TEXT,
                    confidence REAL,
                    detection_method TEXT DEFAULT 'rule-based',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at)")
        
        if 'user_activity' not in existing_tables:
            print("   Creating missing 'user_activity' table...")
            c.execute("""
                CREATE TABLE user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    details TEXT,
                    type TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            c.execute("CREATE INDEX IF NOT EXISTS idx_activity_user_id ON user_activity(user_id)")
            c.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON user_activity(timestamp)")
        
        # Check and add missing columns to users table WITHOUT dropping
        c.execute("PRAGMA table_info(users)")
        existing_columns = [col[1] for col in c.fetchall()]
        
        # Define all required columns
        required_columns = [
            ('fullname', 'TEXT'),
            ('location', 'TEXT'),
            ('profile_pic', 'TEXT'),
            ('language', 'TEXT'),
            ('email_notifications', 'INTEGER'),
            ('account_type', 'TEXT'),
            ('created_at', 'TIMESTAMP'),
            ('reset_token', 'TEXT'),
            ('reset_token_expiry', 'DATETIME')
        ]
        
        for column_name, column_type in required_columns:
            if column_name not in existing_columns:
                print(f"   Adding missing column: {column_name}")
                try:
                    if column_type == 'INTEGER':
                        c.execute(f"ALTER TABLE users ADD COLUMN {column_name} INTEGER DEFAULT 1")
                    elif column_type == 'TEXT':
                        c.execute(f"ALTER TABLE users ADD COLUMN {column_name} TEXT")
                    else:
                        c.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
                except Exception as e:
                    print(f"   Warning: Could not add column {column_name}: {e}")
        
        # Check and add missing columns to scans table
        c.execute("PRAGMA table_info(scans)")
        existing_columns = [col[1] for col in c.fetchall()]
        
        if 'detection_method' not in existing_columns:
            print("   Adding detection_method column to scans...")
            try:
                c.execute("ALTER TABLE scans ADD COLUMN detection_method TEXT DEFAULT 'rule-based'")
            except Exception as e:
                print(f"   Warning: Could not add detection_method column: {e}")
        
        # Count current users
        c.execute("SELECT COUNT(*) FROM users")
        user_count = c.fetchone()[0]
        print(f"   Total users in database: {user_count}")
        
        conn.commit()
        conn.close()
        
        print("✅ Database structure verified and repaired!")
        
    except Exception as e:
        print(f"❌ Error verifying database: {e}")

# ---------------- CREATE ADMIN USER ----------------
def create_admin_user():
    """Create admin user if not exists"""
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # First, check if admin column exists
        c.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in c.fetchall()]
        
        # Add account_type column if it doesn't exist
        if 'account_type' not in columns:
            print("   Adding account_type column...")
            c.execute("ALTER TABLE users ADD COLUMN account_type TEXT DEFAULT 'standard'")
            conn.commit()
        
        # Check if admin exists
        c.execute("SELECT * FROM users WHERE username = 'admin' OR account_type = 'admin'")
        admins = c.fetchall()
        
        if not admins:
            # Create admin user
            c.execute("""
                INSERT INTO users (username, email, mobile, password, fullname, account_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, ('admin', 'admin@agriguard.com', '9999999999', 'admin123', 'System Administrator', 'admin'))
            
            conn.commit()
            print("✅ Admin user created: admin/admin123")
        else:
            print(f"✅ {len(admins)} admin user(s) already exist")
        
        # Count total users
        c.execute("SELECT COUNT(*) FROM users")
        total_users = c.fetchone()[0]
        print(f"   Total users in system: {total_users}")
        
        conn.close()
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")

# ---------------- VERIFY DATABASES ----------------
def verify_databases():
    """Verify all databases are working properly"""
    import sqlite3
    import os
    
    print("\n" + "="*50)
    print("VERIFYING DATABASES...")
    print("="*50)
    
    databases = [
        ("users.db", [
            ("users", "SELECT COUNT(*) FROM users"),
            ("scans", "SELECT COUNT(*) FROM scans"),
            ("user_activity", "SELECT COUNT(*) FROM user_activity")
        ]),
        ("agriguard.db", [
            ("user_activity_agri", "SELECT COUNT(*) FROM user_activity_agri"),
            ("contact_messages", "SELECT COUNT(*) FROM contact_messages")
        ])
    ]
    
    for db_file, tables in databases:
        if os.path.exists(db_file):
            try:
                conn = sqlite3.connect(db_file)
                c = conn.cursor()
                
                # Verify it's a valid SQLite database
                c.execute("SELECT sqlite_version()")
                version = c.fetchone()[0]
                print(f"✅ {db_file}: SQLite version {version}")
                
                # Check tables
                c.execute("SELECT name FROM sqlite_master WHERE type='table'")
                existing_tables = [row[0] for row in c.fetchall()]
                print(f"   Tables: {existing_tables}")
                
                # Count records in each table
                for table_name, count_query in tables:
                    if table_name in existing_tables:
                        c.execute(count_query)
                        count = c.fetchone()[0]
                        print(f"   📊 {table_name}: {count} records")
                
                conn.close()
                
            except sqlite3.DatabaseError as e:
                print(f"❌ {db_file} is corrupted: {e}")
                # Try to repair or recreate
                try:
                    os.remove(db_file)
                    print(f"   Deleted corrupted {db_file}")
                except:
                    print(f"   Could not delete {db_file}")
            except Exception as e:
                print(f"⚠️ Error checking {db_file}: {e}")
        else:
            print(f"📁 {db_file} not found (will be created when needed)")
    
    print("="*50 + "\n")

# ---------------- PASSWORD RESET FUNCTIONS ----------------
def send_reset_email(email, reset_link, username):
    """Send password reset email"""
    try:
        # For development/testing, we'll print the link to console
        print("\n" + "="*60)
        print("AGRIGUARD - PASSWORD RESET EMAIL")
        print("="*60)
        print(f"To: {email}")
        print(f"Subject: AgriGuard - Password Reset Request")
        print(f"\nHello {username},")
        print(f"\nWe received a request to reset your password.")
        print(f"\nClick this link to reset your password:")
        print(f"\n{reset_link}")
        print(f"\nThis link expires in 1 hour.")
        print(f"\nIf you didn't request this, please ignore this email.")
        print(f"\nStay safe,")
        print("The AgriGuard Team")
        print("="*60 + "\n")
        
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

# ---------------- KEYWORDS ----------------
agri_keywords = [
    # Core agriculture terms
    "agriculture", "agricultural", "agri", "agro", "farming", "farm", "farmer",
    "crop", "crops", "cultivation", "plantation", "harvest", "yield", "produce",
    
    # Inputs & materials
    "fertilizer", "fertilizers", "fertiliser", "seed", "seeds", "sapling", "saplings",
    "pesticide", "pesticides", "insecticide", "herbicide", "fungicide",
    "organic", "chemical", "nutrient", "nutrition",
    
    # Equipment & infrastructure
    "tractor", "equipment", "tools", "machinery", "implement", "irrigation",
    "sprinkler", "pump", "generator", "storage", "warehouse", "shed",
    
    # Business & market
    "market", "marketing", "supply", "distribution", "wholesale", "retail",
    "dealer", "distributor", "supplier", "vendor", "store", "shop",
    
    # General terms with agricultural context
    "green", "natural", "sustainable", "eco", "environment", "growth", "grow",
    "water", "soil", "land", "field", "earth", "climate", "weather",
    "plant", "plants", "tree", "trees", "vegetable", "vegetables", "fruit", "fruits",
    "grain", "grains", "cereal", "cereals", "pulse", "pulses",
    
    # Hindi terms
    "खेती", "कृषि", "किसान", "फसल", "बीज", "खाद", "उर्वरक", "कीटनाशक",
    "जैविक", "रासायनिक", "सिंचाई", "ट्रैक्टर", "यंत्र", "मशीन",
    "बाजार", "वितरण", "विक्रेता", "दुकान",
    "हरा", "प्राकृतिक", "टिकाऊ", "विकास", "बढ़ना",
    "पानी", "मिट्टी", "जमीन", "खेत", "जलवायु", "मौसम",
    
    # Marathi terms
    "शेती", "कृषी", "शेतकरी", "पीक", "बियाणे", "खते", "कीटकनाशके",
    "सेंद्रिय", "रासायनिक", "सिंचन", "ट्रॅक्टर", "यंत्रणा", "यंत्र",
    "बाजार", "वितरण", "विक्रेता", "दुकान",
    "हिरवा", "नैसर्गिक", "शाश्वत", "वाढ", "वाढणे",
    "पाणी", "माती", "जमीन", "शेत", "हवामान",

    # GLOBAL FERTILIZER BRANDS
    "Nutrien", "Nutrien fertilizers", "Nutrien products",
    "Yara International", "Yara fertilizers", "Yara crop nutrition",
    "CF Industries", "CF Industries fertilizers",
    "Mosaic Company", "Mosaic fertilizers", "Mosaic phosphate", "Mosaic potash",
    "Bayer CropScience", "Bayer fertilizers",
    "BASF", "BASF agricultural solutions",
    "Syngenta", "Syngenta crop protection",
    "Dow AgroSciences", "Corteva Agriscience", "DuPont",
    "ICL Group", "ICL fertilizers", "Haifa Group", "Haifa fertilizers",
    
    # INDIAN FERTILIZER BRANDS
    "IFFCO", "Indian Farmers Fertiliser Cooperative", "IFFCO fertilizers",
    "Chambal Fertilisers", "Chambal Group", "Chambal urea",
    "Coromandel International", "Coromandel fertilizers", "Coromandel Gromor",
    "Deepak Fertilisers", "Deepak fertilizers", "Deepak Crop Science",
    "RCF", "Rashtriya Chemicals and Fertilizers", "RCF urea",
    "Tata Chemicals", "Tata fertilizers", "Tata agricultural products",
    "National Fertilizers Ltd", "NFL", "NFL urea",
    "GSFC", "Gujarat State Fertilizers & Chemicals",
    "GNFC", "Gujarat Narmada Valley Fertilizers",
    "KRIBHCO", "Krishak Bharati Cooperative",
    "Mangalore Chemicals", "MCFL",
    "Southern Petrochemicals", "SPIC",
    "Zuari Agro Chemicals", "Zuari fertilizers",
    "Madras Fertilizers", "MFL",
    "Paradeep Phosphates", "PPL",
    "FACT", "Fertilizers and Chemicals Travancore",
    "Gujarat State Fertilizers",
    "Karnataka State Co-operative Marketing Federation", "KFL",
    
    # INDIAN SEED BRANDS
    "Mahyco", "Maharashtra Hybrid Seeds Company",
    "Nuziveedu Seeds", "Nuziveedu",
    "Rasi Seeds",
    "Kaveri Seeds",
    "Advanta Seeds", "UPL Advanta",
    "JK Seeds",
    "Namdhari Seeds",
    "Monsanto India",
    "Pioneer Seeds", "DuPont Pioneer",
    "Bayer Seeds",
    "Syngenta Seeds",
    
    # INDIAN PESTICIDE BRANDS
    "UPL Limited", "United Phosphorus Limited",
    "PI Industries",
    "Dhanuka Agritech",
    "Rallis India",
    "Insecticides India",
    "Excel Crop Care",
    "Bayer CropScience India",
    "BASF India",
    "Sumitomo Chemical India",
    "Indofil Industries",
    
    # INDIAN TRACTOR BRANDS
    "Mahindra Tractors", "Mahindra & Mahindra",
    "TAFE", "Tractors and Farm Equipment",
    "Escorts Tractors", "Escorts Group",
    "Sonalika Tractors", "International Tractors",
    "John Deere India",
    "New Holland Agriculture",
    "Kubota Agricultural Machinery",
    "Force Motors", "Force Tractors",
    "Preet Tractors",
    "VST Tillers",
    
    # FERTILIZER TYPES (Common terms)
    "urea", "DAP", "diammonium phosphate", "NPK", "complex fertilizers",
    "single super phosphate", "SSP", "triple super phosphate", "TSP",
    "muriate of potash", "MOP", "sulphate of potash", "SOP",
    "ammonium sulphate", "ammonium nitrate", "calcium ammonium nitrate", "CAN",
    "micronutrients", "biofertilizers", "organic fertilizers", "vermicompost",
    "water soluble fertilizers", "WSF", "liquid fertilizers",
    
    # HINDI FERTILIZER TERMS
    "यूरिया", "डीएपी", "एनपीके", "जटिल उर्वरक", "सुपर फॉस्फेट",
    "पोटाश", "सूक्ष्म पोषक तत्व", "जैव उर्वरक", "जैविक खाद",
    "केंचुआ खाद", "तरल उर्वरक",
    
    # MARATHI FERTILIZER TERMS
    "युरिया", "डीएपी", "एनपीके", "कंप्लेक्स खते", "सुपर फॉस्फेट",
    "पोटॅश", "सूक्ष्म पोषक द्रव्ये", "जैविक खते", "जैविक खत",
    "केंचू खत", "द्रवरूप खते",
    
    # Add these specific scheme names
    "Pradhanmantri Bhartiya Jan Urvarak Pariyojana",
    "Bhartiya Jan Urvarak Pariyojana",
    "Jan Urvarak Pariyojana",
    "PM BJUP",  # Abbreviation

    # Add fertilizer grade formats
    "18:46:0",  # DAP fertilizer grade
    "N 18% P2O5 46%",  # Nutrient content format
    "46% DAP", "18% Nitrogen 46% Phosphate",
    
    # More specific KRIBHCO variations
    "KRIBHCO", "Krishak Bharati Cooperative",
    "Krishak Bharati Cooperative Limited",
    "Krishi Bharati", "KRIBHCO fertilizers",

    # Contact format patterns (legitimate)
    "0120-2534631", "Ext.: 218", "e-mail: sanjaysingh@kribhco.net",
    "Ph. :", "Ext.:", "e-mail:", "contact :",
    
    # Price format patterns (legitimate)
    "Rs. 2982.05", "Rs. 1632.05", "Rs. 1350.00", "Rs. 27.00",
    "per bag", "per kg", "Maximum Retail Price",
    "Actual cost =", "Govt. of India Subsidy =",
    "MRP", "Maximum Retail Price (Incl. all Taxes)",
    
    # Legitimate packaging info
    "Net Weight = 50 kg", "Gross Weight = 50.129 kg",
    "PACKED & MARKETED BY", "MARKETED BY",
    "Net Weight =", "Gross Weight =",
    "50 kg bag", "50kg",
]

fraud_keywords = [
    # English fraud indicators
    "free", "fake", "scam", "fraud", "cheat", "illegal", "unauthorized",
    "counterfeit", "duplicate", "copy", "imitation", "fake", "false",
    "guaranteed", "100%", "assured", "promised", "limited", "offer",
    "discount", "sale", "cheap", "lowest", "best price", "urgent",
    "immediate", "instant", "quick", "fast", "hurry", "last chance",
    "secret", "hidden", "revealed", "exposed", "truth", "shocking",
    
    # Hindi fraud indicators
    "फ्री", "मुफ्त", "नकली", "जाली", "धोखा", "अवैध", "अनधिकृत",
    "प्रतिबद्ध", "गारंटी", "सीमित", "ऑफर", "छूट", "सस्ता", "सबसे सस्ता",
    "जल्दी", "तुरंत", "तत्काल", "अंतिम मौका", "गुप्त", "खुलासा",
    
    # Marathi fraud indicators
    "मोफत", "खोटे", "फसवणूक", "बनावट", "अवैध", "अनधिकृत",
    "हमी", "मर्यादित", "ऑफर", "सवलत", "स्वस्त", "सर्वात स्वस्त",
    "लवकर", "तात्काळ", "शेवटची संधी", "गुप्त", "उघड"
]

genuine_brands = [
    # English brand names
    "namdhari", "rk fertilizer", "coromandel", "safal", "green gold", "greengold",
    "green gate", "watermarket", "tata chemicals", "godrej agrovet",
    "krishna fertilizer", "paradeep", "uday fertilizer", "nutrifarm", "fertiplus",
    "puregrow", "krishicare", "bigfarm", "ibr", "nfl", "clarus",
    "mahindra", "john deere", "escorts", "sonalika", "force", "bajaj",
    "dupont", "syngenta", "bayer", "monsanto", "cargill", "adm",
    
    # Hindi brand names
    "नमधारी", "सफल", "कृषिकेअर", "ग्रीन गोल्ड", "परादीप", "क्लारस",
    "ग्रीन गेट", "वॉटरमार्केट", "टाटा केमिकल्स", "गोदरेज एग्रोवेट",
    "महिंद्रा", "जॉन डीयर",
    
    # Marathi brand names
    "नमधारी", "सफल", "कृषिकेअर", "ग्रीन गोल्ड", "परादीप",
    "ग्रीन गेट", "वॉटरमार्केट"
]

# Trusted government domains
trusted_government_domains = [
    '.gov.in', '.nic.in', '.gov', '.gov.uk', '.gov.au', '.gc.ca',
    '.gob.mx', '.gouv.fr', '.gov.cn', '.go.jp'
]

# ---------------- GOVERNMENT DOMAIN CHECKER ----------------
def check_government_domain_first(url, content=""):
    """
    First check: If it's a government domain, return high confidence genuine
    This should run BEFORE any other detection logic
    """
    if not url:
        return None
    
    url_lower = url.lower()
    
    # ====== GOVERNMENT DOMAIN WHITELIST ======
    # Always mark these as 98%+ genuine regardless of accessibility
    government_domains = [
        "farmer.gov.in",
        "pmkisan.gov.in",
        "agricoop.nic.in", 
        "dahd.nic.in",
        "icar.gov.in",
        "agriculture.gov.in",
        "mofpi.nic.in",
        ".gov.in",  # Any .gov.in domain
        ".nic.in",   # Any .nic.in domain
        "mahaagri.gov.in",
        "upagriculture.com",
        "raitamitra.karnataka.gov.in",
        "agri.mp.gov.in",
        "ikisan.com",
        "agmarknet.gov.in",
        "agri.assam.gov.in"
    ]
    
    # Check if URL contains any government domain
    for domain in government_domains:
        if domain in url_lower:
            return {
                'result': '✅ GENUINE - Government Website',
                'confidence': 98.5,
                'method': 'Rule-Based',
                'rules_triggered': [f"Government domain detected: {domain}"],
                'details': 'Legitimate government agricultural portal',
                'verification_tips': 'This is an official government website for farmers',
                'category': 'government'
            }
    
    return None

# ---------------- OCR HELPER FUNCTIONS ----------------
from content_validator import ContentValidator

@app.route('/process_image', methods=['POST'])
def process_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'})
    
    # Save uploaded file
    filename = secure_filename(file.filename)
    upload_path = os.path.join('static', 'uploads', filename)
    file.save(upload_path)
    
    # STEP 1: VALIDATE CONTENT BEFORE PROCESSING
    is_valid, validation_msg, extracted_text = ContentValidator.validate_image(upload_path)
    
    # If not agriculture-related, show warning
    if not is_valid:
        return render_template('non_agriculture_warning.html',
                             image=upload_path,
                             message=validation_msg,
                             extracted_text=extracted_text[:500] if extracted_text else "")
    
    # STEP 2: If valid, proceed with enhanced OCR
    if len(extracted_text) < 50:  # If validation extracted minimal text
        extracted_text = extract_text_from_image(upload_path)  # Use enhanced OCR
    
    # STEP 3: Analyze for fraud
    result, confidence = check_fraud(extracted_text)
    
    # STEP 4: Log the scan
    if 'user_id' in session:
        log_scan(session['user_id'], 'image', extracted_text[:200], result, confidence)
    
    return render_template('result.html',
                         result=result,
                         confidence=confidence,
                         extracted_text=extracted_text,
                         input_type='Image Upload',
                         validation_passed=True)

#---------------------------------------
def check_fraud(content, url=None):
    """Check content for agricultural fraud patterns"""
    
    content_lower = content.lower()
    
    # 1. IMMEDIATE BRAND RECOGNITION - Add this
    legitimate_brands = {
        'iffco': ('✅ GENUINE - IFFCO Fertilizer', 95.0),
        'kribhco': ('✅ GENUINE - KRIBHCO Fertilizer', 95.0),
        'nfl': ('✅ GENUINE - NFL Fertilizer', 92.0),
        'zuari': ('✅ GENUINE - Zuari Fertilizer', 92.0),
        'paradeep': ('✅ GENUINE - Paradeep Fertilizer', 90.0),
        'coromandel': ('✅ GENUINE - Coromandel Fertilizer', 92.0),
    }
    
    for brand, (result, confidence) in legitimate_brands.items():
        if brand in content_lower:
            return result, confidence
    
    # Rest of your existing fraud detection code...
    # (government check, keyword analysis, etc.)

def is_agriculture_content(text):
    """Quick check if text contains agriculture keywords"""
    text_lower = text.lower()
    
    agri_indicators = [
        'fertilizer', 'seed', 'crop', 'farm', 'farmer', 'agriculture',
        'krishi', 'kisan', 'खेत', 'फसल', 'बीज', 'शेती', 'शेतकरी',
        'dap', 'urea', 'npk', 'compost', 'manure', 'pesticide',
        'सब्सिडी', 'मंडी', 'सिंचाई', 'उर्वरक', 'खाद'
    ]
    
    count = sum(1 for keyword in agri_indicators if keyword in text_lower)
    return count >= 2  # At least 2 agriculture indicators
#---------------------------------------
def extract_text_from_image(image_path):
    """Extract text from image with improved OCR settings"""
    try:
        # Add language parameter for Hindi/English text
        pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'  # Windows
        # For Linux: remove above line or adjust path
        
        # Try multiple languages and configurations
        configs = [
            '--oem 3 --psm 6 -l eng',  # English
            '--oem 3 --psm 6 -l hin',  # Hindi
            '--oem 3 --psm 6 -l eng+hin',  # Both English and Hindi
            '--oem 3 --psm 11',  # Sparse text
            '--oem 3 --psm 12',  # Sparse text with orientation
        ]
        
        best_text = ""
        best_score = 0
        
        for config in configs:
            try:
                text = pytesseract.image_to_string(Image.open(image_path), config=config)
                # Score the extracted text (more meaningful words = higher score)
                meaningful_words = [word for word in text.split() if len(word) > 2 and word.isalpha()]
                score = len(meaningful_words)
                
                if score > best_score:
                    best_score = score
                    best_text = text
            except:
                continue
        
        # If no good text found, try with preprocessing
        if best_score < 5:
            text = extract_text_with_preprocessing(image_path)
            return text if text else "Could not extract text. Please ensure clear image with visible text."
        
        return best_text.strip() if best_text.strip() else "No text extracted. Image may be blurry or text not visible."
    
    except Exception as e:
        return f"OCR Error: {str(e)}"

import pytesseract
from PIL import Image, ImageEnhance, ImageFilter
import cv2
import numpy as np
import os

def extract_text_from_image(image_path):
    """
    WORKING OCR FUNCTION - Properly extracts text from fertilizer images
    """
    try:
        # 1. FIRST - Set correct Tesseract path for Windows
        if os.name == 'nt':  # Windows
            tesseract_paths = [
                r"C:\Program Files\Tesseract-OCR\tesseract.exe",
                r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
            ]
            for path in tesseract_paths:
                if os.path.exists(path):
                    pytesseract.pytesseract.tesseract_cmd = path
                    print(f"Using Tesseract at: {path}")
                    break
            else:
                return "ERROR: Tesseract not installed. Download from: https://github.com/UB-Mannheim/tesseract/wiki"
        
        # 2. Open image
        img = Image.open(image_path)
        
        # 3. PREPROCESSING - CRITICAL FOR GOOD OCR
        # Convert to grayscale
        if img.mode != 'L':
            img = img.convert('L')
        
        # Increase size if too small
        if img.width < 600:
            new_width = 1200
            ratio = new_width / img.width
            new_height = int(img.height * ratio)
            img = img.resize((new_width, new_height), Image.Resampling.LANCZOS)
        
        # Increase contrast
        enhancer = ImageEnhance.Contrast(img)
        img = enhancer.enhance(3.0)  # Strong contrast
        
        # Increase sharpness
        enhancer = ImageEnhance.Sharpness(img)
        img = enhancer.enhance(2.0)
        
        # Apply slight blur to reduce noise
        img = img.filter(ImageFilter.MedianFilter(3))
        
        # 4. OCR WITH OPTIMAL SETTINGS
        # Try multiple configurations to get best result
        configs = [
            '--psm 6 --oem 3 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.:%/- ',  # Block of text
            '--psm 11 --oem 3',  # Sparse text
            '--psm 12 --oem 3',  # Sparse text with OSD
            '--psm 13 --oem 3',  # Raw line
        ]
        
        best_text = ""
        best_length = 0
        
        for config in configs:
            try:
                text = pytesseract.image_to_string(img, config=config)
                # Clean the text
                text = ' '.join(text.split())  # Remove extra whitespace
                
                # Check if this result is better
                if len(text) > best_length and "¢" not in text and "€" not in text:
                    best_text = text
                    best_length = len(text)
            except:
                continue
        
        # If no good text, try simple method
        if not best_text or len(best_text) < 20:
            text = pytesseract.image_to_string(img, lang='eng')
            best_text = text
        
        # Clean up the extracted text
        best_text = clean_ocr_text(best_text)
        
        return best_text if best_text.strip() else "No text could be extracted. Please try with a clearer image."
    
    except Exception as e:
        return f"OCR Error: {str(e)}"

def clean_ocr_text(text):
    """Clean OCR extracted text"""
    if not text:
        return ""
    
    # Common OCR errors and their corrections
    replacements = {
        'STASSIUN': 'POTASSIUM',
        'rm': 'NITRATE',
        'Ws': 'Water Soluble',
        'yeones': 'Farmers',
        'shee': 'IFFCO',
        'ry ais': 'IFFCO',
        'PO': 'P2O5',
        'Copperflews': 'Cooperatives',
        'vregspecifics': 'Water Soluble',
        'arders': 'Fertiliser',
        'Fertigation': 'Fertigation',
        'Insurance': 'Insurance',
        'Guinea': 'Guinea',
        'Helian': 'Indian',
    }
    
    # Apply replacements
    for wrong, correct in replacements.items():
        text = text.replace(wrong, correct)
    
    # Fix common OCR issues
    text = text.replace('  ', ' ')  # Double spaces
    text = text.replace(' .', '.')  # Space before period
    text = text.replace(' ,', ',')  # Space before comma
    
    return text.strip()

# ---------------- WEB SCRAPING FUNCTIONS ----------------
def is_valid_url(url):
    """Validate URL format"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def fetch_website_content(url, timeout=15):
    """Fetch content from a website with error handling"""
    try:
        # Common user agents
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        # Try to fetch the website
        try:
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
        except:
            # Try with session
            session = requests.Session()
            session.verify = False
            response = session.get(url, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            return f"Website returned status code: {response.status_code}"
        
        # Try to decode content
        try:
            content = response.content.decode('utf-8')
        except:
            content = response.content.decode('latin-1')
        
        # Extract text using regex (simple approach)
        import re
        
        # Remove scripts and styles
        content = re.sub(r'<script.*?</script>', '', content, flags=re.DOTALL)
        content = re.sub(r'<style.*?</style>', '', content, flags=re.DOTALL)
        
        # Get title
        title_match = re.search(r'<title>(.*?)</title>', content, re.IGNORECASE)
        title = title_match.group(1) if title_match else ""
        
        # Get meta description
        desc_match = re.search(r'<meta.*?name="description".*?content="(.*?)"', content, re.IGNORECASE)
        description = desc_match.group(1) if desc_match else ""
        
        # Extract visible text (between tags)
        text_content = re.sub(r'<[^>]+>', ' ', content)  # Remove HTML tags
        text_content = re.sub(r'\s+', ' ', text_content).strip()  # Normalize whitespace
        
        result = f"""
        URL: {url}
        TITLE: {title}
        DESCRIPTION: {description}
        
        CONTENT EXCERPT:
        {text_content[:3000]}
        """
        
        return result
        
    except Exception as e:
        return f"Error accessing website: {str(e)}"
        
def extract_domain_info(url):
    """Extract domain information for analysis"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check for suspicious domain patterns
        suspicious_patterns = [
            '.tk', '.ml', '.ga', '.cf', '.gq',  # Free domains often used for scams
            'bit.ly', 'tinyurl', 'shorturl',    # URL shorteners
        ]
        
        domain_info = {
            'domain': domain,
            'is_suspicious_domain': any(pattern in domain for pattern in suspicious_patterns),
            'has_ip_address': any(char.isdigit() for char in domain.split('.')[0]),
            'subdomain_count': len(domain.split('.')) - 2,
            'is_https': parsed.scheme == 'https'
        }
        
        return domain_info
    except:
        return None

def is_government_site(url, content=""):
    """Check if a website is a legitimate government site"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check for government domains
        for gov_domain in trusted_government_domains:
            if domain.endswith(gov_domain):
                return True
        
        # Check for government indicators in domain
        government_domain_indicators = [
            'gov.', 'government.', 'state.', 'national.',
            'ministry.', 'department.', 'official.'
        ]
        
        for indicator in government_domain_indicators:
            if indicator in domain:
                return True
        
        # Check content for government keywords
        if content:
            content_lower = content.lower()
            government_keywords = [
                'government', 'ministry', 'department', 'official',
                'public service', 'government of', 'state government',
                'central government', 'scheme', 'subsidy', 'portal',
                'farmer portal', 'agriculture department', 'pm-',
                'pradhan mantri', 'prime minister', 'minister'
            ]
            
            gov_keyword_count = 0
            for keyword in government_keywords:
                if keyword in content_lower:
                    gov_keyword_count += 1
            
            if gov_keyword_count >= 3:  # If at least 3 government keywords found
                return True
        
        return False
        
    except:
        return False

# ---------------- FRAUD DETECTION FUNCTIONS ----------------
def highlight_keywords(content):
    """Highlight keywords in the content for better visualization"""
    if not content:
        return content
    
    content_lower = content.lower()
    highlighted = content
    
    # Highlight genuine brands in green
    for brand in genuine_brands:
        if brand.lower() in content_lower:
            # Use regex to find whole word only
            pattern = r'\b(' + re.escape(brand) + r')\b'
            highlighted = re.sub(
                pattern, 
                r'<mark class="brand-highlight">\1</mark>', 
                highlighted, 
                flags=re.IGNORECASE
            )
    
    # Highlight fraud keywords in red
    for word in fraud_keywords:
        if word.lower() in content_lower:
            pattern = r'\b(' + re.escape(word) + r')\b'
            highlighted = re.sub(
                pattern, 
                r'<mark class="fraud-highlight">\1</mark>', 
                highlighted, 
                flags=re.IGNORECASE
            )
    
    # Highlight agriculture keywords in blue
    for word in agri_keywords:
        if word.lower() in content_lower:
            pattern = r'\b(' + re.escape(word) + r')\b'
            highlighted = re.sub(
                pattern, 
                r'<mark class="agri-highlight">\1</mark>', 
                highlighted, 
                flags=re.IGNORECASE
            )
    
    return highlighted

def enhanced_check_fraud(content, url=None):
    """Enhanced fraud detection with website-specific checks"""
    if not content or not content.strip():
        return "⚠️ No readable content detected", 0, []
    
    content_lower = content.lower()
    
    # ========== CHECK FOR GOVERNMENT SITES FIRST ==========
    # If URL is provided, check if it's a government domain
    if url:
        gov_check = check_government_domain_first(url, content)
        if gov_check:
            return gov_check['result'], gov_check['confidence'], []
    
    # ========== ORIGINAL CODE CONTINUES ==========
    # If URL provided, do additional domain analysis
    domain_warning = ""
    if url and is_valid_url(url):
        domain_info = extract_domain_info(url)
        if domain_info:
            warnings = []
            if domain_info['is_suspicious_domain']:
                warnings.append("Suspicious domain detected")
            if domain_info['has_ip_address']:
                warnings.append("IP address in domain")
            if domain_info['subdomain_count'] > 3:
                warnings.append("Many subdomains")
            if not domain_info['is_https']:
                warnings.append("Not HTTPS secured")
            
            if warnings:
                domain_warning = " (" + ", ".join(warnings) + ")"
    
    # Check for genuine brands
    found_brands = []
    for brand in genuine_brands:
        pattern = r'\b' + re.escape(brand.lower()) + r'\b'
        if re.search(pattern, content_lower):
            found_brands.append(brand)
    
    if found_brands:
        return f"✅ Genuine Product Detected{domain_warning}", 95, found_brands
    
    # Check for agriculture keywords
    found_agri = []
    for word in agri_keywords:
        pattern = r'\b' + re.escape(word.lower()) + r'\b'
        if re.search(pattern, content_lower):
            found_agri.append(word)
    
    # Check for fraud keywords
    found_fraud = []
    for word in fraud_keywords:
        pattern = r'\b' + re.escape(word.lower()) + r'\b'
        if re.search(pattern, content_lower):
            found_fraud.append(word)
    
    # Calculate enhanced confidence score
    confidence = 50  # Base confidence
    
    # Agriculture content boosts confidence
    if found_agri:
        confidence += min(25, len(found_agri) * 5)
    
    # Fraud indicators reduce confidence
    if found_fraud:
        confidence -= min(40, len(found_fraud) * 10)
    
    # Government terms boost confidence significantly
    government_terms = ['gov.in', 'government', 'ministry', 'department', 'official', 'scheme', 'subsidy', 'portal']
    gov_term_count = 0
    for term in government_terms:
        if term in content_lower:
            gov_term_count += 1
    
    if gov_term_count >= 2:
        confidence += 30  # Big boost for government content
        domain_warning += " (Government content detected)"
    
    # Clamp confidence between 0 and 100
    confidence = max(0, min(100, confidence))
    
    # Determine result with enhanced logic
    if not found_agri:
        return f"⚠️ Suspicious: Not related to agriculture{domain_warning}", confidence, []
    elif found_fraud and confidence < 30:
        return f"🚨 High Risk Website Detected{domain_warning}", confidence, found_fraud
    elif found_fraud:
        return f"🚨 Potential Fraud Detected{domain_warning}", confidence, found_fraud
    elif confidence >= 70:
        return f"✅ Website Looks Safe{domain_warning}", confidence, []
    elif confidence >= 40:
        return f"⚠️ Website Needs Review{domain_warning}", confidence, []
    else:
        return f"🚨 High Risk Website{domain_warning}", confidence, []

# ---------------- ENHANCED FRAUD DETECTION WITH ML ----------------
def enhanced_check_fraud_with_ml(content, url=None):
    """
    Enhanced fraud detection combining ML + Rule-based
    """
    # ========== CHECK FOR GOVERNMENT SITES FIRST ==========
    # If URL is provided, check if it's a government domain
    if url:
        gov_check = check_government_domain_first(url, content)
        if gov_check:
            # Return government result (bypass ML)
            return gov_check['result'], gov_check['confidence'], [], []
    
    # First, do rule-based detection
    rule_result, rule_confidence, keywords = enhanced_check_fraud(content, url)
    
    # If ML model is not available, return rule-based results
    if not ML_AVAILABLE or ml_detector is None:
        return rule_result, rule_confidence, keywords, []
    
    try:
        # Get ML prediction
        ml_result, ml_confidence = ml_detector.predict(content)
        
        # Convert ML confidence to percentage (0-100)
        ml_confidence_percent = ml_confidence * 100
        
        # Combine predictions
        # Weight: ML 60% + Rules 40%
        final_confidence = (ml_confidence_percent * 0.6) + (rule_confidence * 0.4)
        
        # Determine final result
        if "🚨" in ml_result:
            if "🚨" in rule_result:
                final_result = "🚨 AI Confirmed: High Fraud Risk"
                final_confidence = min(100, final_confidence * 1.1)
            else:
                final_result = "⚠️ AI Suspects Fraud (Rules: OK)"
        elif "✅" in ml_result:
            if "✅" in rule_result:
                final_result = "✅ AI Confirmed: Likely Genuine"
                final_confidence = max(0, final_confidence * 0.9)
            else:
                final_result = "⚠️ AI: Genuine (Rules: Suspicious)"
        else:
            # ML says neutral
            if "🚨" in rule_result:
                final_result = "⚠️ Rules: Fraud (AI: Neutral)"
            elif "✅" in rule_result:
                final_result = "⚠️ Rules: Genuine (AI: Neutral)"
            else:
                final_result = "⚠️ Both Methods: Needs Review"
        
        # Get ML explanation if confidence is low
        ml_explanation = []
        if final_confidence < 70:
            ml_explanation = ml_detector.explain_prediction(content, top_n=5)
        
        # Clamp confidence
        final_confidence = max(0, min(100, final_confidence))
        
        return final_result, final_confidence, keywords, ml_explanation
        
    except Exception as e:
        print(f"❌ ML integration error: {e}")
        # Fallback to rule-based
        return rule_result, rule_confidence, keywords, []

# ---------------- DATABASE HELPER FUNCTIONS ----------------
def get_db_connection():
    """Create database connection"""
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn

def log_scan(user_id, content_type, content, result, confidence):
    """Log scan to database"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (user_id, content_type, content, result, confidence)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, content_type, content[:500], result, confidence))
        conn.commit()
        conn.close()
        
        # Log activity
        log_user_activity(user_id, 'Fraud Analysis', 
                         f'Analyzed {content_type} with result: {result}', 'scan')
    except Exception as e:
        print(f"Error logging scan: {e}")

def log_scan_with_method(user_id, content_type, content, result, confidence, detection_method):
    """Log scan with detection method"""
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
            INSERT INTO scans (user_id, content_type, content, result, confidence, detection_method)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (user_id, content_type, content[:500], result, confidence, detection_method))
        conn.commit()
        conn.close()
        
        # Log activity
        log_user_activity(user_id, 'Fraud Analysis', 
                         f'Analyzed {content_type} with {detection_method}: {result}', 'scan')
        return True
    except Exception as e:
        print(f"Error logging scan with method: {e}")
        return False

def get_total_scans(user_id):
    """Get total number of scans by user"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM scans WHERE user_id = ?", (user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else 0
    except:
        return 0

def get_fraud_detected(user_id):
    """Get number of fraud cases detected by user"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM scans 
            WHERE user_id = ? AND (result LIKE '%Fraud%' OR result LIKE '%Risk%')
        """, (user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else 0
    except:
        return 0

def get_genuine_ads(user_id):
    """Get number of genuine ads detected by user"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            SELECT COUNT(*) FROM scans 
            WHERE user_id = ? AND (result LIKE '%Genuine%' OR result LIKE '%Safe%')
        """, (user_id,))
        result = c.fetchone()
        conn.close()
        return result[0] if result else 0
    except:
        return 0

def get_accuracy_rate(user_id):
    """Calculate user accuracy rate"""
    total = get_total_scans(user_id)
    if total > 0:
        genuine = get_genuine_ads(user_id)
        accuracy = (genuine / total) * 100
        return round(accuracy, 1)
    return 0.0

def get_recent_activity(user_id, limit=5):
    """Get recent user activity"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            SELECT * FROM user_activity 
            WHERE user_id = ? 
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (user_id, limit))
        activities = c.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        result = []
        for activity in activities:
            result.append({
                'id': activity[0],
                'user_id': activity[1],
                'action': activity[2],
                'details': activity[3],
                'type': activity[4],
                'timestamp': activity[5]
            })
        return result
    except:
        return []

def get_recent_scans(user_id, limit=5):
    """Get recent scans by user"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            SELECT id, content_type, content, result, created_at
            FROM scans 
            WHERE user_id = ? 
            ORDER BY created_at DESC 
            LIMIT ?
        """, (user_id, limit))
        scans = c.fetchall()
        conn.close()
        
        # Convert to list of dictionaries
        result = []
        for scan in scans:
            result.append({
                'id': scan[0],
                'content_type': scan[1],
                'content': scan[2][:50] + '...' if len(scan[2]) > 50 else scan[2],
                'result': scan[3],
                'date': scan[4]
            })
        return result
    except:
        return []

def log_user_activity(user_id, action, details, activity_type):
    """Log user activity to database"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("""
            INSERT INTO user_activity (user_id, action, details, type)
            VALUES (?, ?, ?, ?)
        """, (user_id, action, details, activity_type))
        conn.commit()
        conn.close()
    except:
        pass

def get_user_full_profile(user_id):
    """Get complete user profile information"""
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = c.fetchone()
        conn.close()
        
        if user:
            return {
                'id': user[0],
                'username': user[1],
                'email': user[2],
                'mobile': user[3],
                'fullname': user[4] if len(user) > 4 else user[1],
                'location': user[5] if len(user) > 5 else 'Not set',
                'profile_pic': user[6] if len(user) > 6 else None,
                'language': user[7] if len(user) > 7 else 'en',
                'email_notifications': user[8] if len(user) > 8 else True,
                'account_type': user[9] if len(user) > 9 else 'standard',
                'created_at': user[10] if len(user) > 10 else '2024-01-01',
                'reset_token': user[12] if len(user) > 12 else None,
                'reset_token_expiry': user[13] if len(user) > 13 else None
            }
    except:
        pass
    return None

def create_translation_files():
    """Create comprehensive translation files if they don't exist"""
    translations_dir = 'static/languages'
    os.makedirs(translations_dir, exist_ok=True)
    
    # Comprehensive English instructions
    en_data = {
        "title": "AgriGuard - User Guide",
        "welcome": "Welcome to AgriGuard",
        "subtitle": "Your Agricultural Fraud Detection System",
        "introduction": "AgriGuard helps you detect fraudulent agricultural advertisements using AI and rule-based analysis. Protect yourself from scams in agricultural products, seeds, fertilizers, and equipment.",
        
        "features_title": "Key Features",
        "features": [
            "📷 Image Upload - Upload images of agricultural ads for text extraction and analysis",
            "📝 Text Input - Direct text input for fraud detection",
            "🔗 Website URL - Analyze websites with web scraping",
            "🌐 Multi-language Support - Works in English, Hindi, and Marathi",
            "📊 Confidence Scoring - Detailed analysis with confidence percentages",
            "👤 User Profile - Track your scans and activity history",
            "🛡️ Government Site Detection - Automatically recognizes .gov.in domains",
            "⚡ Real-time Analysis - Instant fraud detection results"
        ]
    }
    
    # Hindi translation
    hi_data = {
        "title": "AgriGuard - उपयोगकर्ता मार्गदर्शिका",
        "welcome": "AgriGuard में आपका स्वागत है",
        "subtitle": "आपकी कृषि धोखाधड़ी पहचान प्रणाली",
        "introduction": "AgriGuard AI और नियम-आधारित विश्लेषण का उपयोग करके कृषि विज्ञापनों में धोखाधड़ी का पता लगाने में आपकी मदद करता है। कृषि उत्पादों, बीजों, उर्वरकों और उपकरणों में होने वाली धोखाधड़ी से अपनी सुरक्षा करें।",
        
        "features_title": "मुख्य विशेषताएं",
        "features": [
            "📷 छवि अपलोड - पाठ निष्कर्षण और विश्लेषण के लिए कृषि विज्ञापनों की छवियां अपलोड करें",
            "📝 पाठ इनपुट - धोखाधड़ी पहचान के लिए सीधा पाठ इनपुट",
            "🔗 वेबसाइट यूआरएल - वेब स्क्रैपिंग के साथ वेबसाइटों का विश्लेषण",
            "🌐 बहुभाषी समर्थन - अंग्रेजी, हिंदी और मराठी में काम करता है",
            "📊 आत्मविश्वास स्कोरिंग - आत्मविश्वास प्रतिशत के साथ विस्तृत विश्लेषण",
            "👤 उपयोगकर्ता प्रोफाइल - अपने स्कैन और गतिविधि इतिहास को ट्रैक करें",
            "🏛️ सरकारी साइट पहचान - .gov.in डोमेन को स्वचालित रूप से पहचानता है",
            "⚡ रियल-टाइम विश्लेषण - तत्काल धोखाधड़ी पहचान परिणाम"
        ]
    }
    
    # Marathi translation (simplified)
    mr_data = {
        "title": "AgriGuard - वापरकर्ता मार्गदर्शिका",
        "welcome": "AgriGuard मध्ये आपले स्वागत आहे",
        "subtitle": "आपली कृषी फसवणूक ओळख प्रणाली",
        "introduction": "AgriGuard AI आणि नियम-आधारित विश्लेषण वापरून कृषी जाहिरातींमध्ये फसवणूक ओळखण्यात आपली मदत करते. कृषी उत्पादने, बिया, खते आणि उपकरणांमध्ये होणाऱ्या फसवणुकीपासून स्वतःचे संरक्षण करा.",
        
        "features_title": "मुख्य वैशिष्ट्ये",
        "features": [
            "📷 प्रतिमा अपलोड - मजकूर काढणे आणि विश्लेषणासाठी कृषी जाहिरातींच्या प्रतिमा अपलोड करा",
            "📝 मजकूर इनपुट - फसवणूक ओळखीसाठी थेट मजकूर इनपुट",
            "🔗 वेबसाइट यूआरएल - वेब स्क्रॅपिंगसह वेबसाइट्सचे विश्लेषण",
            "🌐 बहुभाषिक समर्थन - इंग्रजी, हिंदी आणि मराठीमध्ये कार्य करते",
            "📊 आत्मविश्वास स्कोरिंग - आत्मविश्वास टक्केवारीसह तपशीलवार विश्लेषण",
            "👤 वापरकर्ता प्रोफाइल - आपले स्कॅन आणि क्रियाकलाप इतिहास ट्रॅक करा",
            "🏛️ सरकारी साइट ओळख - .gov.in डोमेन स्वयंचलितपणे ओळखतो",
            "⚡ रिअल-टाइम विश्लेषण - त्वरित फसवणूक ओळख परिणाम"
        ]
    }
    
    # Save files
    with open(os.path.join(translations_dir, 'instructions_en.json'), 'w', encoding='utf-8') as f:
        json.dump(en_data, f, ensure_ascii=False, indent=2)
    
    with open(os.path.join(translations_dir, 'instructions_hi.json'), 'w', encoding='utf-8') as f:
        json.dump(hi_data, f, ensure_ascii=False, indent=2)
    
    with open(os.path.join(translations_dir, 'instructions_mr.json'), 'w', encoding='utf-8') as f:
        json.dump(mr_data, f, ensure_ascii=False, indent=2)
    
    print("✅ Translation files created successfully!")

# ---------------- ROUTES ----------------

# ---------------- HOME ----------------
@app.route("/")
def home():
    return redirect("/login-selector")

# ---------------- LOGIN SELECTOR ----------------
@app.route("/login-selector")
def login_selector():
    """Show login type selection page"""
    # If already logged in, redirect appropriately
    if 'user_id' in session:
        if session.get('account_type') == 'admin' or session.get('username') == 'admin':
            return redirect('/admin')
        else:
            return redirect('/instruction')
    
    return render_template("login_selector.html")

# ---------------- REGULAR LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    """Regular user login"""
    # If already logged in, redirect appropriately
    if "user_id" in session:
        if session.get('account_type') == 'admin' or session.get('username') == 'admin':
            return redirect("/admin")
        else:
            return redirect("/language")
    
    # If GET request, show regular login
    if request.method == "GET":
        return render_template("login.html")
    
    # POST request handling
    identifier = request.form.get("identifier", "").strip()
    password = request.form.get("password", "").strip()

    if not identifier or not password:
        flash("Please enter both username/email/mobile and password", "error")
        return render_template("login.html")

    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Check if user exists with given identifier and password
        c.execute("""
            SELECT * FROM users 
            WHERE (username = ? OR email = ? OR mobile = ?) AND password = ?
        """, (identifier, identifier, identifier, password))
        
        user = c.fetchone()
        conn.close()

        if user:
            # Check if trying to login as admin through regular login
            account_type = user[10] if len(user) > 10 else 'standard'
            if account_type == 'admin' or user[1] == 'admin':
                flash("Please use Admin Login for administrator access", "warning")
                return redirect("/admin-login")
            
            # Store user info in session
            session["user_id"] = user[0]
            session["username"] = user[1]
            session["email"] = user[2]
            session["mobile"] = user[3]
            session["user"] = user[1]
            session["account_type"] = account_type
            
            # Log activity
            log_user_activity(user[0], 'User Login', 'Logged into the system', 'auth')
            
            flash(f"Welcome back, {user[1]}!", "success")
            return redirect("/language")
        else:
            flash("Invalid username/email/mobile or password", "error")
            return render_template("login.html")
            
    except Exception as e:
        flash(f"Login error: {str(e)}", "error")
        return render_template("login.html")

# ---------------- ADMIN LOGIN ----------------
@app.route("/admin-login", methods=["GET", "POST"])
def admin_login():
    """Admin-specific login route"""
    # If already logged in as admin, redirect to admin panel
    if 'user_id' in session:
        if session.get('account_type') == 'admin' or session.get('username') == 'admin':
            return redirect('/admin')
    
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        
        if not username or not password:
            flash("Please enter both username and password", "error")
            return render_template("admin_login.html")
        
        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            
            # Check if user exists and is admin
            c.execute("""
                SELECT * FROM users 
                WHERE username = ? AND password = ? 
                AND (account_type = 'admin' OR username = 'admin')
            """, (username, password))
            
            user = c.fetchone()
            conn.close()
            
            if user:
                # Store user info in session
                session["user_id"] = user[0]
                session["username"] = user[1]
                session["email"] = user[2]
                session["mobile"] = user[3]
                session["user"] = user[1]
                session["account_type"] = user[10] if len(user) > 10 else 'standard'
                
                # Log activity
                log_user_activity(user[0], 'Admin Login', 'Logged into admin panel', 'auth')
                
                flash(f"Welcome, Administrator {user[1]}!", "success")
                return redirect("/admin")
            else:
                # Check if user exists but not admin
                conn = sqlite3.connect("users.db")
                c = conn.cursor()
                c.execute("SELECT username FROM users WHERE username = ? AND password = ?", 
                         (username, password))
                regular_user = c.fetchone()
                conn.close()
                
                if regular_user:
                    flash("This account does not have admin privileges. Please use regular login.", "error")
                else:
                    flash("Invalid admin credentials", "error")
                
                return render_template("admin_login.html")
                
        except Exception as e:
            flash(f"Login error: {str(e)}", "error")
            return render_template("admin_login.html")
    
    return render_template("admin_login.html")

# ---------------- REGISTER ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # Validation
        if not all([username, email, mobile, password]):
            flash("All fields are required!", "error")
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match!", "error")
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters!", "error")
            return render_template("register.html")

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()
            c.execute(
                "INSERT INTO users(username, email, mobile, password) VALUES (?, ?, ?, ?)",
                (username, email, mobile, password)
            )
            
            # Update the new user with fullname
            c.execute("UPDATE users SET fullname = ? WHERE username = ?", (username, username))
            
            conn.commit()
            conn.close()
            
            flash("Registration successful! Please login.", "success")
            return redirect("/login-selector")
        except sqlite3.IntegrityError as e:
            error_msg = str(e)
            if "username" in error_msg:
                flash("Username already exists!", "error")
            elif "email" in error_msg:
                flash("Email already exists!", "error")
            elif "mobile" in error_msg:
                flash("Mobile number already exists!", "error")
            else:
                flash("User already exists!", "error")
            return render_template("register.html")
        except Exception as e:
            flash(f"Registration failed: {str(e)}", "error")
            return render_template("register.html")
    
    return render_template("register.html")

# ---------------- FORGOT PASSWORD ROUTES ----------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Step 1: Request password reset"""
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        
        if not email:
            flash("Please enter your email address", "error")
            return render_template("forgot_password.html")
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        
        if user:
            user_id, username = user
            
            # Generate secure token
            reset_token = secrets.token_urlsafe(32)
            expiry_time = datetime.now() + timedelta(hours=1)  # Token valid for 1 hour
            
            # Store token in database
            c.execute('''
                UPDATE users 
                SET reset_token = ?, reset_token_expiry = ?
                WHERE id = ?
            ''', (reset_token, expiry_time, user_id))
            conn.commit()
            conn.close()
            
            # Create reset link
            reset_link = url_for('reset_password', token=reset_token, _external=True)
            
            # Send reset email (simplified for development)
            if send_reset_email(email, reset_link, username):
                flash("✅ Password reset link has been sent to your email! Check your email inbox.", "success")
                print(f"📧 Password reset link generated: {reset_link}")
            else:
                flash("❌ Error sending email. Please try again later.", "error")
            
            return redirect("/login-selector")
        else:
            flash("❌ No account found with that email address", "error")
    
    return render_template("forgot_password.html")
    
@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Step 2: Reset password with token"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Check if token is valid and not expired
    c.execute('''
        SELECT id, username, reset_token_expiry 
        FROM users 
        WHERE reset_token = ? AND reset_token_expiry > datetime('now')
    ''', (token,))
    
    user = c.fetchone()
    
    if not user:
        flash("❌ Invalid or expired reset link. Please request a new one.", "error")
        return redirect("/forgot-password")
    
    user_id, username, expiry = user
    
    if request.method == "POST":
        new_password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()
        
        # Validation
        if not new_password or not confirm_password:
            flash("❌ Please fill in all fields", "error")
        elif new_password != confirm_password:
            flash("❌ Passwords do not match", "error")
        elif len(new_password) < 6:
            flash("❌ Password must be at least 6 characters", "error")
        else:
            # Update password and clear reset token
            c.execute('''
                UPDATE users 
                SET password = ?, reset_token = NULL, reset_token_expiry = NULL
                WHERE id = ?
            ''', (new_password, user_id))
            conn.commit()
            conn.close()
            
            # Log activity
            log_user_activity(user_id, 'Password Reset', 'Password reset successful', 'auth')
            
            flash("✅ Password reset successful! You can now login with your new password.", "success")
            return redirect("/login-selector")
    
    conn.close()
    return render_template("reset_password.html", token=token, username=username)

# ---------------- LANGUAGE ----------------
@app.route("/language", methods=["GET", "POST"])
@login_required
def language():
    if request.method == "POST":
        lang = request.form.get("lang", "en")
        session["lang"] = lang
        
        # Flash message in selected language
        lang_messages = {
            "en": "Language set to English",
            "hi": "भाषा हिंदी में सेट की गई",
            "mr": "भाषा मराठी मध्ये सेट केली"
        }
        flash(lang_messages.get(lang, "Language updated"), "success")
        return redirect("/instruction")
    
    return render_template("language.html")

# ---------------- SET LANGUAGE ----------------
@app.route("/set_language/<lang>")
def set_language(lang):
    """Set user's preferred language from any page"""
    if lang in ['en', 'hi', 'mr']:
        session['lang'] = lang
        
        # Update in database if user is logged in
        if 'user_id' in session:
            try:
                conn = sqlite3.connect("users.db")
                c = conn.cursor()
                c.execute("UPDATE users SET language = ? WHERE id = ?", (lang, session['user_id']))
                conn.commit()
                conn.close()
                
                # Log activity
                log_user_activity(session['user_id'], 'Language Changed', f'Changed language to {lang}', 'settings')
            except:
                pass
        
        flash_message = {
            'en': 'Language changed to English',
            'hi': 'भाषा हिंदी में बदली गई',
            'mr': 'भाषा मराठी मध्ये बदलली'
        }
        flash(flash_message.get(lang, 'Language changed'), 'success')
    
    # Redirect back to instruction page
    return redirect('/instruction')

# ---------------- INSTRUCTION ----------------
@app.route("/instruction")
@login_required
def instruction():
    # Get selected language from session
    lang = session.get("lang", "en")
    
    # Load instructions in selected language
    instructions = {}
    try:
        file_path = os.path.join('static/languages', f'instructions_{lang}.json')
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                instructions = json.load(f)
        else:
            # Fallback to English
            file_path = os.path.join('static/languages', 'instructions_en.json')
            if os.path.exists(file_path):
                with open(file_path, 'r', encoding='utf-8') as f:
                    instructions = json.load(f)
            else:
                # Create translation files if they don't exist
                create_translation_files()
                with open(os.path.join('static/languages', 'instructions_en.json'), 'r', encoding='utf-8') as f:
                    instructions = json.load(f)
    except Exception as e:
        print(f"Error loading instructions: {e}")
        # Create default instructions structure
        instructions = {
            "title": "AgriGuard - User Guide",
            "welcome": "Welcome to AgriGuard",
            "subtitle": "Your Agricultural Fraud Detection System",
            "introduction": "AgriGuard helps you detect fraudulent agricultural advertisements.",
            "features_title": "Key Features",
            "features": ["Image Upload", "Text Input", "Website Analysis"]
        }
    
    # Get user info for display
    user_info = {
        "username": session.get("username", "User"),
        "lang": lang
    }
    
    return render_template("instruction.html", 
                          instructions=instructions,
                          language=lang,
                          user=user_info)

# ---------------- PLATFORM SELECTION ----------------
@app.route("/platform")
@login_required
def platform():
    return render_template("platform.html")

# ---------------- PROFILE ----------------
@app.route("/profile")
@login_required
def profile():
    # Get complete user profile
    user = get_user_full_profile(session["user_id"])
    if not user:
        flash("User profile not found", "error")
        return redirect("/login-selector")
    
    # Get user statistics
    stats = {
        'total_scans': get_total_scans(session["user_id"]),
        'fraud_detected': get_fraud_detected(session["user_id"]),
        'genuine_ads': get_genuine_ads(session["user_id"]),
        'accuracy_rate': get_accuracy_rate(session["user_id"])
    }
    
    # Get recent activity
    recent_activity = get_recent_activity(session["user_id"], limit=5)
    
    # Get recent scans
    recent_scans = get_recent_scans(session["user_id"], limit=5)
    
    return render_template("profile.html", 
                         user=user, 
                         stats=stats, 
                         recent_activity=recent_activity,
                         recent_scans=recent_scans)

# ---------------- DETECT ROUTE ----------------
@app.route("/detect", methods=["GET", "POST"])
@login_required
def detect():
    result = ""
    confidence = 0
    content = ""
    highlighted_content = ""
    found_keywords = []
    ml_explanation = []
    detection_method = "Rule-Based"
    
    if request.method == "POST":
        print("="*60)
        print("DEBUG: DETECT ROUTE - FORM SUBMITTED")
        print("="*60)
        
        # Get ALL possible data
        image_file = request.files.get('image')
        text_input = request.form.get('text', '').strip()
        link_input = request.form.get('link', '').strip()
        
        # Debug print everything
        print(f"📸 Image file exists: {'YES' if image_file else 'NO'}")
        if image_file:
            print(f"📸 Image filename: '{image_file.filename}'")
            print(f"📸 Image file not empty: {image_file.filename != ''}")
        
        print(f"📝 Text input: '{text_input}'")
        print(f"📝 Text length: {len(text_input)}")
        
        print(f"🔗 Link input: '{link_input}'")
        print("="*60)
        
        # DECISION LOGIC: Determine which input was actually used
        input_type = None
        
        # 1. Check if IMAGE was uploaded (has file and filename not empty)
        if image_file and hasattr(image_file, 'filename') and image_file.filename != '':
            input_type = 'image'
            print("✅ Detected: IMAGE input")
        
        # 2. Check if TEXT was entered (has content and reasonable length)
        elif text_input and len(text_input) >= 3:
            input_type = 'text'
            print("✅ Detected: TEXT input")
        
        # 3. Check if LINK was entered
        elif link_input:
            input_type = 'link'
            print("✅ Detected: LINK input")
            
            # ====== IMMEDIATE GOVERNMENT DOMAIN CHECK ======
            # Check for .gov.in domains BEFORE any processing
            url_lower = link_input.lower()
            if '.gov.in' in url_lower or '.nic.in' in url_lower:
                print("🎯 Government domain detected - Returning 98% genuine")
                result = "✅ GENUINE - Government Website"
                confidence = 98.5
                highlighted_content = f"URL: {link_input}\n\nGovernment domain detected (.gov.in/.nic.in)"
                found_keywords = []
                ml_explanation = []
                detection_method = "Rule-Based (Government Domain)"
                
                # Log to database
                log_scan_with_method(
                    session["user_id"],
                    "url",
                    link_input,
                    result,
                    confidence,
                    detection_method
                )
                
                flash("✅ Government website detected - Legitimate source!", "success")
                
                # Return result immediately, skip further processing
                return render_template("detect.html", 
                                     result=result,
                                     confidence=confidence,
                                     content=link_input,
                                     highlighted_content=highlighted_content,
                                     found_keywords=found_keywords,
                                     ml_explanation=ml_explanation,
                                     detection_method=detection_method,
                                     ml_available=ML_AVAILABLE)
        
        print(f"📋 Selected input type: {input_type}")
        print("="*60)
        
        # Now process based on detected input type
        if input_type == 'image':
            print("🔄 Processing IMAGE...")
            
            # Check file type
            allowed_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp'}
            if hasattr(image_file, 'filename'):
                file_ext = os.path.splitext(image_file.filename.lower())[1]
                if file_ext not in allowed_extensions:
                    flash("❌ Please upload a valid image file (PNG, JPG, JPEG, GIF, BMP)", "error")
                    return render_template("detect.html")
            
            # Extract text from image
            try:
                content = extract_text_from_image(image_file)
                print(f"📄 OCR extracted {len(content)} characters")
                print(f"📄 First 100 chars: {content[:100]}")
                
                if not content or content.startswith("OCR Error"):
                    flash("❌ Could not extract text from image. Please try a clearer image.", "error")
                    return render_template("detect.html")
                
                # Analyze the content with ML if available
                if ML_AVAILABLE:
                    result, confidence, found_keywords, ml_explanation = enhanced_check_fraud_with_ml(content)
                    detection_method = "AI + Rule-Based"
                else:
                    result, confidence, found_keywords = enhanced_check_fraud(content)
                    ml_explanation = []
                    detection_method = "Rule-Based"
                
                highlighted_content = highlight_keywords(content)
                
                flash("✅ Image processed successfully! Fraud analysis completed.", "success")
                
                # Log to database
                log_scan_with_method(
                    session["user_id"],
                    "image",
                    content,
                    result,
                    confidence,
                    detection_method
                )
                    
            except Exception as e:
                flash(f"❌ Error processing image: {str(e)}", "error")
                return render_template("detect.html")
        
        elif input_type == 'text':
            print("🔄 Processing TEXT...")
            
            if len(text_input) < 5:
                flash("❌ Please enter at least 5 characters of text", "error")
                return render_template("detect.html")
            
            content = text_input
            
            # Analyze the content with ML if available
            if ML_AVAILABLE:
                result, confidence, found_keywords, ml_explanation = enhanced_check_fraud_with_ml(content)
                detection_method = "AI + Rule-Based"
            else:
                result, confidence, found_keywords = enhanced_check_fraud(content)
                ml_explanation = []
                detection_method = "Rule-Based"
            
            highlighted_content = highlight_keywords(content)
            
            flash("✅ Text analyzed successfully! Fraud detection completed.", "success")
            
            # Log to database
            log_scan_with_method(
                session["user_id"],
                "text",
                content,
                result,
                confidence,
                detection_method
            )
        
        elif input_type == 'link':
            print("🔄 Processing LINK...")
            
            if not is_valid_url(link_input):
                flash("❌ Invalid URL. Please enter a valid URL starting with http:// or https://", "error")
                return render_template("detect.html")
            
            flash("🌐 Fetching website content... Please wait.", "info")
            
            try:
                website_content = fetch_website_content(link_input)
                print(f"🌐 Fetched {len(website_content)} characters")
                
                if website_content.startswith("Error"):
                    flash(f"❌ Could not fetch website: {website_content}", "error")
                    content = f"URL: {link_input}\n\nError: {website_content}"
                else:
                    flash("✅ Website content fetched successfully!", "success")
                    content = f"URL: {link_input}\n\n{website_content}"
                
                # Analyze with URL context
                if ML_AVAILABLE:
                    result, confidence, found_keywords, ml_explanation = enhanced_check_fraud_with_ml(content, link_input)
                    detection_method = "AI + Rule-Based"
                else:
                    result, confidence, found_keywords = enhanced_check_fraud(content, link_input)
                    ml_explanation = []
                    detection_method = "Rule-Based"
                
                highlighted_content = highlight_keywords(content)
                
                # Log to database
                log_scan_with_method(
                    session["user_id"],
                    "url",
                    content,
                    result,
                    confidence,
                    detection_method
                )
                
                if confidence < 50:
                    flash("⚠️ Warning: This website shows potential risk indicators", "warning")
                    
            except Exception as e:
                flash(f"❌ Error analyzing website: {str(e)}", "error")
                return render_template("detect.html")
        
        else:
            flash("❌ Please provide input (upload image, enter text, or paste URL)", "error")
            print("❌ No valid input detected")
    
    # Always return the template with results
    return render_template("detect.html", 
                         result=result,
                         confidence=confidence,
                         content=content,
                         highlighted_content=highlighted_content,
                         found_keywords=found_keywords or [],
                         ml_explanation=ml_explanation,
                         detection_method=detection_method,
                         ml_available=ML_AVAILABLE)

# ---------------- CHECK FRAUD API ENDPOINT ----------------
@app.route("/check_fraud", methods=["POST"])
def check_fraud_api():
    """API endpoint for AJAX fraud checking"""
    if "user_id" not in session:
        return jsonify({"status": "error", "message": "Please login first"})
    
    text = request.form.get("text", "").strip()
    if not text:
        return jsonify({"status": "error", "message": "No text provided"})
    
    # Perform fraud detection
    if ML_AVAILABLE:
        result, confidence, found_keywords, ml_explanation = enhanced_check_fraud_with_ml(text)
    else:
        result, confidence, found_keywords = enhanced_check_fraud(text)
        ml_explanation = []
    
    # Determine result category
    result_lower = result.lower()
    if "genuine" in result_lower or "safe" in result_lower or "✅" in result:
        result_category = "genuine"
    elif "fraud" in result_lower or "risk" in result_lower or "🚨" in result:
        result_category = "fraud"
    else:
        result_category = "suspicious"
    
    # Prepare response
    response = {
        "status": "success",
        "result": result_category,
        "message": result,
        "confidence": confidence,
        "method": "AI + Rule-based Analysis" if ML_AVAILABLE else "Rule-based Analysis"
    }
    
    # Add recommendation
    if confidence >= 70:
        response["recommendation"] = "This content appears safe. You can proceed with caution."
    elif confidence >= 40:
        response["recommendation"] = "Exercise caution. Verify information through official sources."
    else:
        response["recommendation"] = "High risk detected. Avoid interacting with this content."
    
    return jsonify(response)

# ---------------- ACTIVITY HISTORY ----------------
@app.route("/activity-history")
@login_required
def activity_history():
    """Display complete activity history for the user"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Get user info
    c.execute("SELECT username, email FROM users WHERE id = ?", (session['user_id'],))
    user_data = c.fetchone()
    username = user_data[0] if user_data else "User"
    
    # Get all activity for the user
    c.execute("""
        SELECT action, details, type, timestamp 
        FROM user_activity 
        WHERE user_id = ? 
        ORDER BY timestamp DESC
    """, (session['user_id'],))
    
    activity_data = c.fetchall()
    
    # Convert to list of dictionaries
    activities = []
    for row in activity_data:
        activities.append({
            'action': row[0],
            'details': row[1],
            'type': row[2],
            'timestamp': row[3]
        })
    
    # Count activities by type
    c.execute("""
        SELECT type, COUNT(*) 
        FROM user_activity 
        WHERE user_id = ? 
        GROUP BY type
    """, (session['user_id'],))
    
    type_counts = dict(c.fetchall())
    
    conn.close()
    
    return render_template("activity_history.html", 
                         username=username,
                         activities=activities,
                         type_counts=type_counts,
                         total_activities=len(activities))

# ---------------- UPLOAD PROFILE PICTURE ----------------
@app.route("/upload_profile_pic", methods=["POST"])
@login_required
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        return jsonify({"success": False, "message": "No file selected"})
    
    file = request.files['profile_pic']
    if file.filename == '':
        return jsonify({"success": False, "message": "No file selected"})
    
    # Check if file is an image
    if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp')):
        return jsonify({"success": False, "message": "Invalid file type"})
    
    try:
        # Create uploads directory if it doesn't exist
        upload_folder = 'static/uploads/profile_pics'
        os.makedirs(upload_folder, exist_ok=True)
        
        # Generate secure filename
        filename = secure_filename(f"user_{session['user_id']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{file.filename.split('.')[-1]}")
        filepath = os.path.join(upload_folder, filename)
        
        # Save file
        file.save(filepath)
        
        # Update database
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("UPDATE users SET profile_pic = ? WHERE id = ?", (filename, session['user_id']))
        conn.commit()
        conn.close()
        
        # Log activity
        log_user_activity(session['user_id'], 'Profile Picture Updated', 'Uploaded new profile picture', 'profile')
        
        return jsonify({"success": True, "filename": filename})
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

# ---------------- UPDATE PREFERENCES ----------------
@app.route("/update_preferences", methods=["POST"])
@login_required
def update_preferences():
    try:
        data = request.get_json()
        email_notifications = data.get('email_notifications', False)
        language = data.get('language', 'en')
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Check what columns exist
        c.execute("PRAGMA table_info(users)")
        existing_columns = [col[1] for col in c.fetchall()]
        
        # Build update query
        update_fields = []
        update_values = []
        
        # Handle email_notifications
        if 'email_notifications' in existing_columns:
            update_fields.append("email_notifications = ?")
            update_values.append(1 if email_notifications else 0)
        elif 'notifications' in existing_columns:
            update_fields.append("notifications = ?")
            update_values.append(1 if email_notifications else 0)
        else:
            # Create the column if it doesn't exist
            try:
                c.execute("ALTER TABLE users ADD COLUMN email_notifications INTEGER DEFAULT 1")
                conn.commit()
                update_fields.append("email_notifications = ?")
                update_values.append(1 if email_notifications else 0)
                print("Created email_notifications column")
            except Exception as e:
                print(f"Could not create column: {e}")
        
        # Handle language
        if 'language' in existing_columns:
            update_fields.append("language = ?")
            update_values.append(language)
        
        # Only proceed if we have fields to update
        if update_fields:
            update_values.append(session['user_id'])
            update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            c.execute(update_query, update_values)
            conn.commit()
            
            # Update session
            session['language'] = language
            
            # Log activity
            log_user_activity(session['user_id'], 'Preferences Updated', 
                            f'Updated language to {language}', 'preferences')
        
        conn.close()
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

# ---------------- UPDATE PROFILE ----------------
@app.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    try:
        data = request.get_json()
        fullname = data.get('fullname', '').strip()
        email = data.get('email', '').strip()
        phone = data.get('phone', '').strip()
        location = data.get('location', '').strip()
        
        # Basic validation
        if not email:
            return jsonify({"success": False, "message": "Email is required"})
        
        # Use username if fullname is empty
        if not fullname:
            fullname = data.get('username', '').strip()
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Check what columns exist
        c.execute("PRAGMA table_info(users)")
        columns_info = c.fetchall()
        existing_columns = [col[1] for col in columns_info]
        
        # Check if email already exists (excluding current user)
        c.execute("SELECT id FROM users WHERE email = ? AND id != ?", (email, session['user_id']))
        existing = c.fetchone()
        if existing:
            conn.close()
            return jsonify({"success": False, "message": "Email already exists"})
        
        # Build dynamic update query based on existing columns
        update_fields = []
        update_values = []
        
        # Update username if fullname is different (use fullname as username)
        if fullname and 'username' in existing_columns:
            update_fields.append("username = ?")
            update_values.append(fullname)
        
        if email and 'email' in existing_columns:
            update_fields.append("email = ?")
            update_values.append(email)
        
        if phone:
            if 'mobile' in existing_columns:
                update_fields.append("mobile = ?")
                update_values.append(phone)
            elif 'phone' in existing_columns:
                update_fields.append("phone = ?")
                update_values.append(phone)
        
        if location and 'location' in existing_columns:
            update_fields.append("location = ?")
            update_values.append(location)
        
        # Add fullname if column exists
        if fullname and 'fullname' in existing_columns:
            update_fields.append("fullname = ?")
            update_values.append(fullname)
        
        # Add user_id to values
        update_values.append(session['user_id'])
        
        if update_fields:
            update_query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
            c.execute(update_query, update_values)
            conn.commit()
        
        conn.close()
        
        # Update session
        session['username'] = fullname
        session['email'] = email
        session['mobile'] = phone
        
        # Log activity
        log_user_activity(session['user_id'], 'Profile Updated', 'Updated profile information', 'profile')
        
        return jsonify({"success": True})
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

# ---------------- USER ACTIVITY ROUTE (FROM DATABASE.PY) ----------------
@app.route("/user/activity/<int:user_id>")
@login_required
def user_activity(user_id):
    """View user activity logs from agriguard database"""
    # Check if user is viewing their own activity
    if session['user_id'] != user_id:
        flash('You can only view your own activity', 'warning')
        return redirect(url_for('profile'))
    
    # Get activities from agriguard database
    activities = db_instance.get_user_activity(user_id)
    
    # Get user info from users database
    user = get_user_full_profile(user_id)
    
    return render_template("user_activity.html", 
                          activities=activities, 
                          user=user)

# ---------------- SUBMIT CONTACT FORM (AGRI DATABASE) ----------------
@app.route('/submit-contact', methods=['POST'])
def submit_contact():
    """Handle contact form submission"""
    name = request.form.get('name')
    email = request.form.get('email')
    subject = request.form.get('subject')
    message = request.form.get('message')
    phone = request.form.get('phone')
    
    # Save to agriguard database
    message_id = db_instance.add_contact_message(
        name=name,
        email=email,
        subject=subject,
        message=message,
        phone=phone
    )
    
    # Log activity if user is logged in
    if 'user_id' in session:
        db_instance.add_activity_log(
            user_id=session['user_id'],
            activity_type='contact_sent',
            description=f'Sent contact message #{message_id}',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
    
    flash('Your message has been sent successfully!', 'success')
    return redirect(url_for('contact'))

# ---------------- API ACTIVITY ENDPOINT ----------------
@app.route('/api/activity/<int:user_id>')
@login_required
def api_user_activity(user_id):
    """API endpoint for user activity (JSON response)"""
    # Check if user is accessing their own activity
    if session['user_id'] != user_id:
        return jsonify({
            'error': 'Unauthorized',
            'message': 'You can only view your own activity'
        }), 403
    
    activities = db_instance.get_user_activity(user_id)
    
    return jsonify({
        'user_id': user_id,
        'activities': activities,
        'count': len(activities)
    })

# ---------------- ADDITIONAL ROUTES ----------------
@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/contact")
def contact():
    return render_template("contact.html")

@app.route("/demo")
def demo():
    """Demo page for showing how the system works"""
    return render_template("demo.html")

# ---------------- LOGOUT ROUTES ----------------
@app.route("/logout")
def logout():
    username = session.get("username", "User")
    session.clear()
    flash(f"Goodbye, {username}! You have been logged out successfully.", "info")
    return redirect("/login-selector")

@app.route("/admin-logout")
def admin_logout():
    """Logout from admin panel"""
    if 'user_id' in session:
        username = session.get("username", "User")
        session.clear()
        flash(f"Admin {username} logged out successfully.", "info")
    return redirect("/login-selector")

# ---------------- OCR DEBUG ROUTE ----------------
@app.route("/ocr_debug", methods=["GET", "POST"])
@login_required
def ocr_debug():
    """Debug route to test OCR on images"""
    if request.method == "POST":
        if 'image' not in request.files:
            flash("No image file", "error")
            return redirect("/ocr_debug")
        
        image_file = request.files['image']
        if image_file.filename == '':
            flash("No selected file", "error")
            return redirect("/ocr_debug")
        
        # Save and process image
        with tempfile.NamedTemporaryFile(delete=False, suffix='.png') as tmp_file:
            image_path = tmp_file.name
            image_file.save(image_path)
        
        # Try different OCR settings
        img = Image.open(image_path)
        processed_img = preprocess_image(image_path)
        
        results = []
        
        # Test different configurations
        test_configs = [
            ("Default", r'--oem 3 --psm 3 -l eng'),
            ("Single block", r'--oem 3 --psm 6 -l eng'),
            ("Single line", r'--oem 3 --psm 7 -l eng'),
            ("Single word", r'--oem 3 --psm 8 -l eng'),
            ("Sparse text", r'--oem 3 --psm 11 -l eng'),
            ("Hindi", r'--oem 3 --psm 6 -l hin'),
            ("English+Hindi", r'--oem 3 --psm 6 -l eng+hin'),
        ]
        
        for name, config in test_configs:
            try:
                if processed_img:
                    text = pytesseract.image_to_string(processed_img, config=config)
                else:
                    text = pytesseract.image_to_string(img, config=config)
                results.append((name, text.strip()))
            except:
                results.append((name, "ERROR"))
        
        # Clean up
        os.unlink(image_path)
        
        return render_template("ocr_debug.html", results=results, image_name=image_file.filename)
    
    return render_template("ocr_debug.html", results=None, image_name=None)

# ---------------- ERROR HANDLERS ----------------
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# ---------------- CONTEXT PROCESSOR ----------------
@app.context_processor
def inject_user():
    """Inject user info into all templates"""
    is_admin = False
    if 'user_id' in session:
        is_admin = (session.get('account_type') == 'admin' or 
                   session.get('username') == 'admin')
    
    return dict(
        current_user=session.get("username"),
        current_lang=session.get("lang", "en"),
        is_logged_in="user_id" in session,
        is_admin=is_admin,
        current_path=request.path,
        ml_available=ML_AVAILABLE
   )

# ---------------- DATABASE COLUMNS ENSURE ----------------
def ensure_database_columns():
    """Ensure all required columns exist in the users table"""
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Get existing columns
    c.execute("PRAGMA table_info(users)")
    existing_columns = [col[1] for col in c.fetchall()]
    
    # Define columns we need
    columns_to_add = [
        ('fullname', 'TEXT'),
        ('mobile', 'TEXT'),
        ('location', 'TEXT'),
        ('profile_pic', 'TEXT'),
        ('language', 'TEXT'),
        ('email_notifications', 'INTEGER'),
        ('created_at', 'TIMESTAMP'),
        ('reset_token', 'TEXT'),
        ('reset_token_expiry', 'DATETIME')
    ]
    
    for column_name, column_type in columns_to_add:
        if column_name not in existing_columns:
            try:
                # Add the column
                if column_type == 'INTEGER':
                    c.execute(f"ALTER TABLE users ADD COLUMN {column_name} INTEGER DEFAULT 1")
                elif column_type == 'TEXT':
                    c.execute(f"ALTER TABLE users ADD COLUMN {column_name} TEXT")
                else:
                    c.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
                print(f"Added missing column: {column_name}")
            except Exception as e:
                print(f"Error adding column {column_name}: {e}")
    
    conn.commit()
    conn.close()

# ---------------- TEMPLATE FILTERS ----------------
@app.template_filter('format_datetime')
def format_datetime(value):
    """Format datetime for display"""
    if not value:
        return ""
    try:
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        return dt.strftime('%b %d, %Y %I:%M %p')
    except:
        return value

@app.template_filter('tojson')
def tojson_filter(value, indent=None):
    """Convert Python object to JSON string"""
    import json
    return json.dumps(value, indent=indent, default=str)

# ---------------- ADMIN ROUTES ----------------
@app.route("/admin")
@admin_required
def admin_dashboard():
    """Admin dashboard home"""
    import sqlite3
    from datetime import datetime, timedelta
    
    stats = {}
    
    # Get user statistics
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row  # This makes rows accessible by column name
    c = conn.cursor()
    
    # Total users
    c.execute("SELECT COUNT(*) FROM users")
    stats['total_users'] = c.fetchone()[0]
    
    # New users today
    today = datetime.now().strftime('%Y-%m-%d')
    c.execute("SELECT COUNT(*) FROM users WHERE DATE(created_at) = ?", (today,))
    stats['new_users_today'] = c.fetchone()[0]
    
    # Total scans
    c.execute("SELECT COUNT(*) FROM scans")
    stats['total_scans'] = c.fetchone()[0]
    
    # Fraud scans
    c.execute("SELECT COUNT(*) FROM scans WHERE result LIKE '%Fraud%' OR result LIKE '%Risk%'")
    stats['fraud_scans'] = c.fetchone()[0]
    
    # Recent activities
    c.execute("SELECT COUNT(*) FROM user_activity")
    stats['total_activities'] = c.fetchone()[0]
    
    # Get recent scans WITH COLUMN NAMES
    c.execute("""
        SELECT s.*, u.username 
        FROM scans s 
        LEFT JOIN users u ON s.user_id = u.id 
        ORDER BY s.created_at DESC 
        LIMIT 10
    """)
    
    recent_scans = []
    for row in c.fetchall():
        # Access by column name instead of index
        recent_scans.append({
            'id': row['id'],
            'user_id': row['user_id'],
            'username': row['username'] if row['username'] else f"User {row['user_id']}",
            'content_type': row['content_type'],
            'result': row['result'],
            'confidence': row['confidence'],
            'created_at': row['created_at']
        })
    
    conn.close()
    
    # Get system info
    stats['current_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    return render_template("admin_dashboard.html", 
                         stats=stats, 
                         recent_scans=recent_scans,
                         is_admin=True)

@app.route("/admin/users")
@admin_required
def admin_users():
    """View all users"""
    import sqlite3
    
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("""
        SELECT id, username, email, mobile, fullname, location, 
               account_type, created_at, profile_pic
        FROM users 
        ORDER BY created_at DESC
    """)
    
    users = []
    for row in c.fetchall():
        users.append(dict(row))
    
    conn.close()
    
    return render_template("admin_users.html", users=users, is_admin=True)

@app.route("/admin/scans")
@admin_required
def admin_scans():
    """View all scans"""
    import sqlite3
    
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("""
        SELECT s.*, u.username, u.email
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
    """)
    
    scans = []
    for row in c.fetchall():
        scans.append(dict(row))
    
    conn.close()
    
    return render_template("admin_scans.html", scans=scans, is_admin=True)

@app.route("/admin/activities")
@admin_required
def admin_activities():
    """View all activities"""
    import sqlite3
    
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("""
        SELECT a.*, u.username
        FROM user_activity a
        LEFT JOIN users u ON a.user_id = u.id
        ORDER BY a.timestamp DESC
        LIMIT 100
    """)
    
    activities = []
    for row in c.fetchall():
        activities.append(dict(row))
    
    conn.close()
    
    return render_template("admin_activities.html", activities=activities, is_admin=True)

@app.route("/admin/database-viewer")
@admin_required
def admin_database_viewer():
    """Interactive database viewer"""
    import sqlite3
    import json
    
    db_files = ['users.db', 'agriguard.db']
    databases = {}
    
    for db_file in db_files:
        try:
            conn = sqlite3.connect(db_file)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
            tables = [row[0] for row in cursor.fetchall()]
            
            db_tables = {}
            
            for table in tables:
                # Get row count
                cursor.execute(f"SELECT COUNT(*) as count FROM {table}")
                count = cursor.fetchone()['count']
                
                # Get sample data (first 20 rows)
                cursor.execute(f"SELECT * FROM {table} LIMIT 20")
                rows = [dict(row) for row in cursor.fetchall()]
                
                # Get column names
                if rows:
                    columns = list(rows[0].keys())
                else:
                    cursor.execute(f"PRAGMA table_info({table})")
                    columns = [row[1] for row in cursor.fetchall()]
                
                db_tables[table] = {
                    'columns': columns,
                    'row_count': count,
                    'data': rows
                }
            
            databases[db_file] = db_tables
            conn.close()
            
        except Exception as e:
            databases[db_file] = {'error': str(e)}
    
    return render_template("admin_database_viewer.html", 
                         databases=databases, 
                         is_admin=True)

@app.route("/admin/query", methods=["GET", "POST"])
@admin_required
def admin_query():
    """Execute SQL queries"""
    results = None
    error = None
    query = ""
    
    if request.method == "POST":
        query = request.form.get("query", "").strip()
        db_name = request.form.get("database", "users.db")
        
        if query and query.upper().startswith(('SELECT', 'PRAGMA', 'DESCRIBE')):
            try:
                import sqlite3
                
                conn = sqlite3.connect(db_name)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute(query)
                
                if query.upper().startswith('SELECT'):
                    rows = cursor.fetchall()
                    if rows:
                        results = {
                            'columns': list(rows[0].keys()),
                            'data': [dict(row) for row in rows],
                            'row_count': len(rows)
                        }
                    else:
                        results = {'message': 'Query executed successfully, no results returned.'}
                else:
                    results = {'message': 'Query executed successfully.'}
                
                conn.close()
                
            except Exception as e:
                error = str(e)
        else:
            error = "Only SELECT, PRAGMA, and DESCRIBE queries are allowed for security."
    
    return render_template("admin_query.html", 
                         results=results, 
                         error=error, 
                         query=query,
                         is_admin=True)

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    """Delete a user"""
    if user_id == 1:  # Prevent deleting admin
        flash("Cannot delete admin user", "error")
        return redirect(url_for('admin_users'))
    
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Delete user
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        # Also delete related scans and activities
        c.execute("DELETE FROM scans WHERE user_id = ?", (user_id,))
        c.execute("DELETE FROM user_activity WHERE user_id = ?", (user_id,))
        
        conn.commit()
        conn.close()
        
        flash(f"User #{user_id} deleted successfully", "success")
        
    except Exception as e:
        flash(f"Error deleting user: {str(e)}", "error")
    
    return redirect(url_for('admin_users'))

# ---------------- ADMIN ML TRAINING ----------------
@app.route("/admin/train-ml", methods=["GET", "POST"])
@admin_required
def train_ml_model():
    """Admin interface to train/retrain ML model"""
    
    if request.method == "POST":
        # Get training parameters
        use_sample_data = request.form.get('use_sample_data') == 'on'
        epochs = int(request.form.get('epochs', 10))
        
        # Train model
        try:
            if use_sample_data:
                # Use built-in sample data
                try:
                    from train_ml_model import train_model
                    model, vectorizer = train_model(epochs=epochs)
                    message = f"✅ Model trained with sample data for {epochs} epochs"
                    
                    # Update global ML detector
                    global ml_detector, ML_AVAILABLE
                    ml_detector = MLFraudDetector()
                    ML_AVAILABLE = True
                    
                except ImportError:
                    message = "❌ train_ml_model.py not found. Please create it first."
                    flash(message, "error")
                    return redirect(url_for('train_ml_model'))
            else:
                # TODO: Upload custom training data
                message = "⚠️ Custom data training coming soon"
            
            flash(message, "success")
            
        except Exception as e:
            flash(f"❌ Training failed: {str(e)}", "error")
    
    # Check if model exists
    model_exists = ML_AVAILABLE and ml_detector is not None
    
    return render_template("train_ml.html", 
                         model_exists=model_exists,
                         ml_available=ML_AVAILABLE,
                         is_admin=True)

# ---------------- DEBUG ROUTES ----------------
@app.route("/debug/db-status")
def debug_db_status():
    """Debug endpoint to check database status"""
    import os
    import sqlite3
    from datetime import datetime
    
    db_files = []
    db_info = []
    
    # Check all .db files
    for filename in ['users.db', 'agriguard.db']:
        file_exists = os.path.exists(filename)
        file_info = {
            'filename': filename,
            'exists': file_exists,
            'size': os.path.getsize(filename) if file_exists else 0,
            'tables': []
        }
        
        if file_exists:
            try:
                conn = sqlite3.connect(filename)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = cursor.fetchall()
                file_info['tables'] = [table[0] for table in tables]
                conn.close()
            except Exception as e:
                file_info['error'] = str(e)
        
        db_files.append(file_info)
    
    # Check recent activities
    recent_activities = []
    if os.path.exists('agriguard.db'):
        try:
            conn = sqlite3.connect('agriguard.db')
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM user_activity_agri ORDER BY created_at DESC LIMIT 5")
            columns = [description[0] for description in cursor.description]
            activities = cursor.fetchall()
            
            for activity in activities:
                recent_activities.append(dict(zip(columns, activity)))
            
            conn.close()
        except Exception as e:
            recent_activities = [{'error': str(e)}]
    
    # Check user count
    user_count = 0
    if os.path.exists('users.db'):
        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            conn.close()
        except:
            pass
    
    return render_template("debug_db.html", 
                         db_files=db_files,
                         recent_activities=recent_activities,
                         user_count=user_count,
                         timestamp=datetime.now())

@app.route("/debug/db-test")
def debug_db_test():
    """Test database insertion"""
    import sqlite3
    from datetime import datetime
    
    results = []
    
    # Test users.db
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        
        # Insert test scan
        c.execute("""
            INSERT INTO scans (user_id, content_type, content, result, confidence)
            VALUES (?, ?, ?, ?, ?)
        """, (1, "test", "Test content for database", "Test Result", 85.5))
        
        # Insert test activity
        c.execute("""
            INSERT INTO user_activity (user_id, action, details, type)
            VALUES (?, ?, ?, ?)
        """, (1, "Database Test", "Tested database insertion", "test"))
        
        conn.commit()
        
        # Verify insertion
        c.execute("SELECT COUNT(*) FROM scans")
        scan_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM user_activity")
        activity_count = c.fetchone()[0]
        
        conn.close()
        
        results.append({
            'database': 'users.db',
            'status': 'SUCCESS',
            'scan_count': scan_count,
            'activity_count': activity_count
        })
    except Exception as e:
        results.append({
            'database': 'users.db',
            'status': 'FAILED',
            'error': str(e)
        })
    
    # Test agriguard.db
    try:
        conn = sqlite3.connect("agriguard.db")
        c = conn.cursor()
        
        # Insert test activity
        c.execute("""
            INSERT INTO user_activity_agri (user_id, activity_type, description, ip_address)
            VALUES (?, ?, ?, ?)
        """, (1, "debug_test", "Debug test activity", "127.0.0.1"))
        
        # Insert test contact message
        c.execute("""
            INSERT INTO contact_messages (name, email, subject, message)
            VALUES (?, ?, ?, ?)
        """, ("Test User", "test@example.com", "Test Subject", "Test message content"))
        
        conn.commit()
        
        # Verify insertion
        c.execute("SELECT COUNT(*) FROM user_activity_agri")
        agri_activity_count = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM contact_messages")
        contact_count = c.fetchone()[0]
        
        conn.close()
        
        results.append({
            'database': 'agriguard.db',
            'status': 'SUCCESS',
            'activity_count': agri_activity_count,
            'contact_count': contact_count
        })
    except Exception as e:
        results.append({
            'database': 'agriguard.db',
            'status': 'FAILED',
            'error': str(e)
        })
    
    return render_template("debug_test.html", results=results, timestamp=datetime.now())

@app.route("/debug/db-view")
def debug_db_view():
    """View all database content"""
    import sqlite3
    
    databases = {}
    
    # Check users.db
    if os.path.exists('users.db'):
        conn = sqlite3.connect('users.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        users_data = []
        cursor.execute("SELECT * FROM users")
        for row in cursor.fetchall():
            users_data.append(dict(row))
        
        scans_data = []
        cursor.execute("SELECT * FROM scans")
        for row in cursor.fetchall():
            scans_data.append(dict(row))
        
        activity_data = []
        cursor.execute("SELECT * FROM user_activity")
        for row in cursor.fetchall():
            activity_data.append(dict(row))
        
        conn.close()
        
        databases['users.db'] = {
            'users': users_data,
            'scans': scans_data,
            'activity': activity_data
        }
    
    # Check agriguard.db
    if os.path.exists('agriguard.db'):
        conn = sqlite3.connect('agriguard.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        agri_activity = []
        cursor.execute("SELECT * FROM user_activity_agri")
        for row in cursor.fetchall():
            agri_activity.append(dict(row))
        
        contacts = []
        cursor.execute("SELECT * FROM contact_messages")
        for row in cursor.fetchall():
            contacts.append(dict(row))
        
        conn.close()
        
        databases['agriguard.db'] = {
            'agri_activity': agri_activity,
            'contacts': contacts
        }
    
    return render_template("debug_view.html", databases=databases)

@app.route("/admin/repair-databases")
@admin_required
def repair_databases():
    """Admin route to repair corrupted databases"""
    import os
    import sqlite3
    
    results = []
    
    for db_file in ['users.db', 'agriguard.db']:
        if os.path.exists(db_file):
            try:
                # Test if database is valid
                test_conn = sqlite3.connect(db_file)
                test_conn.execute("SELECT 1")
                test_conn.close()
                
                results.append({
                    'file': db_file,
                    'status': '✅ Valid',
                    'action': 'No action needed'
                })
                
            except sqlite3.DatabaseError:
                # Database is corrupted
                backup_file = f"{db_file}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                try:
                    # Create backup of corrupted file
                    import shutil
                    shutil.copy2(db_file, backup_file)
                    
                    # Delete corrupted file
                    os.remove(db_file)
                    
                    # Recreate database
                    if db_file == 'users.db':
                        create_database_from_scratch()
                    else:
                        from database import db_instance
                        db_instance.init_database()
                    
                    results.append({
                        'file': db_file,
                        'status': '🔄 Repaired',
                        'action': f'Backup saved as {backup_file}, database recreated'
                    })
                    
                except Exception as e:
                    results.append({
                        'file': db_file,
                        'status': '❌ Repair failed',
                        'action': str(e)
                    })
        else:
            results.append({
                'file': db_file,
                'status': '📁 Not found',
                'action': 'Will be created when needed'
            })
    
    return render_template("repair_results.html", results=results)

@app.route("/admin/search", methods=["GET", "POST"])
@admin_required
def db_search():
    """Search across all databases"""
    results = []
    
    if request.method == "POST":
        search_term = request.form.get('search_term', '').strip()
        if search_term:
            import sqlite3
            
            # Search in users.db
            conn = sqlite3.connect('users.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Search in users table
            cursor.execute("""
                SELECT 'users' as table_name, id, username, email, mobile, created_at
                FROM users 
                WHERE username LIKE ? OR email LIKE ? OR mobile LIKE ? OR fullname LIKE ?
            """, [f"%{search_term}%"] * 4)
            
            for row in cursor.fetchall():
                results.append({
                    'database': 'users.db',
                    'table': 'users',
                    'data': dict(row)
                })
            
            # Search in scans table
            cursor.execute("""
                SELECT 'scans' as table_name, s.*, u.username
                FROM scans s
                LEFT JOIN users u ON s.user_id = u.id
                WHERE content LIKE ? OR result LIKE ?
            """, [f"%{search_term}%", f"%{search_term}%"])
            
            for row in cursor.fetchall():
                results.append({
                    'database': 'users.db',
                    'table': 'scans',
                    'data': dict(row)
                })
            
            conn.close()
            
            # Search in agriguard.db
            conn = sqlite3.connect('agriguard.db')
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT 'contact_messages' as table_name, *
                FROM contact_messages
                WHERE name LIKE ? OR email LIKE ? OR subject LIKE ? OR message LIKE ?
            """, [f"%{search_term}%"] * 4)
            
            for row in cursor.fetchall():
                results.append({
                    'database': 'agriguard.db',
                    'table': 'contact_messages',
                    'data': dict(row)
                })
            
            conn.close()
    
    return render_template("db_search.html", results=results, search_term=request.form.get('search_term', ''))

# ---------------- API ENDPOINTS ----------------
@app.route("/api/db/users")
@admin_required
def api_get_users():
    """API to get all users (JSON format)"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, email, mobile, fullname, location, 
               created_at, account_type
        FROM users
        ORDER BY created_at DESC
    """)
    
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        "count": len(users),
        "users": users
    })

@app.route("/api/db/scans")
@admin_required
def api_get_scans():
    """API to get all scans"""
    import sqlite3
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT s.*, u.username, u.email
        FROM scans s
        LEFT JOIN users u ON s.user_id = u.id
        ORDER BY s.created_at DESC
        LIMIT 100
    """)
    
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify({
        "count": len(scans),
        "scans": scans
    })

@app.route("/api/db/stats")
def api_db_stats():
    """API to get database statistics"""
    import sqlite3
    import os
    
    stats = {}
    
    for db_file in ['users.db', 'agriguard.db']:
        if os.path.exists(db_file):
            stats[db_file] = {
                'size_bytes': os.path.getsize(db_file),
                'size_mb': round(os.path.getsize(db_file) / (1024 * 1024), 2)
            }
            
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            table_stats = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                count = cursor.fetchone()[0]
                table_stats[table] = count
            
            stats[db_file]['tables'] = table_stats
            conn.close()
    
    return jsonify(stats)


def _get_mysql_tables(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute("SHOW TABLES")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    return tables


def init_database_safely():
    """Initialize MySQL schemas and tables safely without dropping existing data."""
    print("=" * 50)
    print("CHECKING DATABASE...")
    print("=" * 50)
    print("Ensuring MySQL schema and tables for user data...")
    create_database_from_scratch()
    verify_and_repair_database()
    create_admin_user()
    print("=" * 50 + "\n")


def verify_databases():
    """Verify all MySQL schemas are working properly."""
    print("\n" + "=" * 50)
    print("VERIFYING DATABASES...")
    print("=" * 50)

    databases = [
        ("users.db", [
            ("users", "SELECT COUNT(*) FROM users"),
            ("scans", "SELECT COUNT(*) FROM scans"),
            ("user_activity", "SELECT COUNT(*) FROM user_activity")
        ]),
        ("agriguard.db", [
            ("user_activity_agri", "SELECT COUNT(*) FROM user_activity_agri"),
            ("contact_messages", "SELECT COUNT(*) FROM contact_messages")
        ])
    ]

    for db_file, tables in databases:
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()[0]
            print(f"MySQL {db_file}: {version}")

            existing_tables = _get_mysql_tables(db_file)
            print(f"   Tables: {existing_tables}")

            for table_name, count_query in tables:
                if table_name in existing_tables:
                    cursor.execute(count_query)
                    count = cursor.fetchone()[0]
                    print(f"   {table_name}: {count} records")

            conn.close()
        except sqlite3.DatabaseError as error:
            print(f"Database verification failed for {db_file}: {error}")
            if db_file == "users.db":
                create_database_from_scratch()
                verify_and_repair_database()
            else:
                db_instance.init_database()

    print("=" * 50 + "\n")


def _mysql_admin_query():
    """Execute safe read-only SQL queries against MySQL."""
    results = None
    error = None
    query = ""

    if request.method == "POST":
        query = request.form.get("query", "").strip()
        db_name = request.form.get("database", "users.db")

        if query and query.upper().startswith(("SELECT", "SHOW", "PRAGMA", "DESCRIBE")):
            try:
                conn = sqlite3.connect(db_name)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query)

                if query.upper().startswith(("SELECT", "SHOW", "DESCRIBE", "PRAGMA")):
                    rows = cursor.fetchall()
                    if rows:
                        first_row = rows[0]
                        columns = list(first_row.keys()) if hasattr(first_row, "keys") else []
                        results = {
                            "columns": columns,
                            "data": [dict(row) for row in rows],
                            "row_count": len(rows)
                        }
                    else:
                        results = {"message": "Query executed successfully, no results returned."}
                else:
                    results = {"message": "Query executed successfully."}

                conn.close()
            except Exception as exc:
                error = str(exc)
        else:
            error = "Only SELECT, SHOW, PRAGMA, and DESCRIBE queries are allowed for security."

    return render_template(
        "admin_query.html",
        results=results,
        error=error,
        query=query,
        is_admin=True
    )


def _mysql_debug_db_status():
    """Debug endpoint to check MySQL schema status."""
    db_files = []

    for filename in DATABASE_ALIASES:
        file_info = {
            "filename": filename,
            "exists": False,
            "size": 0,
            "tables": []
        }

        try:
            file_info["exists"] = mysql_connection_available(filename)
            file_info["engine"] = "MySQL"
            file_info["tables"] = _get_mysql_tables(filename)
        except Exception as exc:
            file_info["error"] = str(exc)

        db_files.append(file_info)

    recent_activities = []
    try:
        conn = sqlite3.connect("agriguard.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_activity_agri ORDER BY created_at DESC LIMIT 5")
        columns = [description[0] for description in cursor.description]
        for activity in cursor.fetchall():
            recent_activities.append(dict(zip(columns, activity)))
        conn.close()
    except Exception as exc:
        recent_activities = [{"error": str(exc)}]

    user_count = 0
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        conn.close()
    except Exception:
        pass

    return render_template(
        "debug_db.html",
        db_files=db_files,
        recent_activities=recent_activities,
        user_count=user_count,
        timestamp=datetime.now()
    )


def _mysql_debug_db_view():
    """View all database content from MySQL."""
    databases = {}

    try:
        conn = sqlite3.connect("users.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users")
        users_data = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM scans")
        scans_data = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM user_activity")
        activity_data = [dict(row) for row in cursor.fetchall()]

        conn.close()
        databases["users.db"] = {
            "users": users_data,
            "scans": scans_data,
            "activity": activity_data
        }
    except Exception as exc:
        databases["users.db"] = {"error": str(exc)}

    try:
        conn = sqlite3.connect("agriguard.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM user_activity_agri")
        agri_activity = [dict(row) for row in cursor.fetchall()]

        cursor.execute("SELECT * FROM contact_messages")
        contacts = [dict(row) for row in cursor.fetchall()]

        conn.close()
        databases["agriguard.db"] = {
            "agri_activity": agri_activity,
            "contacts": contacts
        }
    except Exception as exc:
        databases["agriguard.db"] = {"error": str(exc)}

    return render_template("debug_view.html", databases=databases)


def _mysql_repair_databases():
    """Validate or re-initialize MySQL schemas."""
    results = []

    for db_file in DATABASE_ALIASES:
        try:
            test_conn = sqlite3.connect(db_file)
            test_conn.execute("SELECT 1")
            test_conn.close()
            results.append({
                "file": db_file,
                "status": "Valid",
                "action": "Connection successful"
            })
        except sqlite3.DatabaseError:
            try:
                if db_file == "users.db":
                    create_database_from_scratch()
                    verify_and_repair_database()
                else:
                    db_instance.init_database()

                results.append({
                    "file": db_file,
                    "status": "Re-initialized",
                    "action": "Schema and tables recreated if missing"
                })
            except Exception as exc:
                results.append({
                    "file": db_file,
                    "status": "Repair failed",
                    "action": str(exc)
                })

    return render_template("repair_results.html", results=results)


def _mysql_api_db_stats():
    """API to get MySQL schema statistics."""
    stats = {}

    for db_file in DATABASE_ALIASES:
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            tables = _get_mysql_tables(db_file)
            table_stats = {}

            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                table_stats[table] = cursor.fetchone()[0]

            stats[db_file] = {
                "engine": "MySQL",
                "available": True,
                "tables": table_stats
            }
            conn.close()
        except Exception as exc:
            stats[db_file] = {
                "engine": "MySQL",
                "available": False,
                "error": str(exc)
            }

    return jsonify(stats)


app.view_functions["admin_query"] = admin_required(_mysql_admin_query)
app.view_functions["debug_db_status"] = _mysql_debug_db_status
app.view_functions["debug_db_view"] = _mysql_debug_db_view
app.view_functions["repair_databases"] = admin_required(_mysql_repair_databases)
app.view_functions["api_db_stats"] = _mysql_api_db_stats

# ---------------- RUN ----------------
if __name__ == "__main__":
    print("="*60)
    print("STARTING AGRIGUARD FRAUD DETECTION SYSTEM")
    print("="*60)
    
    try:
        # Step 1: Initialize database safely (won't drop existing data)
        init_database_safely()
        
        # Step 2: Verify databases
        verify_databases()
        
        # Step 3: Initialize agriguard database
        print("Initializing AgriGuard database...")
        db_instance.init_database()
        
        # Step 4: Create translation files if needed
        create_translation_files()
        
        # Step 5: Ensure database columns
        ensure_database_columns()
        
        print(f"\n✅ ML Model Available: {ML_AVAILABLE}")
        print("🌐 Starting Flask server...")
        print("="*60 + "\n")
        
        # Run the app
        app.run(
            debug=True,
            host='0.0.0.0',
            port=5000
        )
        
    except Exception as e:
        print(f"\n❌ Fatal error during startup: {e}")
        import traceback
        traceback.print_exc()
        print("\nTroubleshooting steps:")
        print("1. Delete users.db and agriguard.db files")
        print("2. Restart the application")
        print("3. Check file permissions")
        input("\nPress Enter to exit...")
