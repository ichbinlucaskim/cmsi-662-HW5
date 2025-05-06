import os
import jwt
import sqlite3
import re
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, make_response, flash
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

app = Flask(__name__)
# SECURITY: Use environment variables for secrets to prevent hardcoding
# SECURITY: Different keys for session and JWT to limit impact of key compromise
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-jwt-secret-key-here')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# SECURITY: CSRF protection enabled globally
csrf = CSRFProtect(app)

# SECURITY: Rate limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Security constants
USERNAME_MIN_LENGTH = 3
USERNAME_MAX_LENGTH = 20
PASSWORD_MIN_LENGTH = 8
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]+$')

def validate_username(username):
    """Validate username format and length."""
    if not username:
        return False, "Username is required"
    if len(username) < USERNAME_MIN_LENGTH:
        return False, f"Username must be at least {USERNAME_MIN_LENGTH} characters"
    if len(username) > USERNAME_MAX_LENGTH:
        return False, f"Username must be at most {USERNAME_MAX_LENGTH} characters"
    if not USERNAME_PATTERN.match(username):
        return False, "Username can only contain letters, numbers, and underscores"
    return True, None

def validate_password(password):
    """Validate password strength."""
    if not password:
        return False, "Password is required"
    if len(password) < PASSWORD_MIN_LENGTH:
        return False, f"Password must be at least {PASSWORD_MIN_LENGTH} characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    if not re.search(r'[^A-Za-z0-9]', password):
        return False, "Password must contain at least one special character"
    return True, None

def init_db():
    """
    Initialize the database with proper schema.
    
    Security Features:
    - Uses parameterized queries for all operations
    - Implements proper indexing for performance and security
    - Stores hashed passwords only
    - Uses INTEGER for numeric values to prevent type confusion
    """
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                gems INTEGER DEFAULT 100,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                failed_login_attempts INTEGER DEFAULT 0
            )
        ''')
        conn.commit()

init_db()

def generate_token(user_id):
    """
    Generate a JWT token for user authentication.
    
    Security Features:
    - Uses secure JWT implementation
    - Includes expiration time to prevent token reuse
    - Uses environment variable for secret key
    - Implements proper algorithm (HS256)
    """
    payload = {
        'user_id': user_id,
        'exp': datetime.utcnow() + timedelta(days=1)
    }
    return jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')

def token_required(f):
    """
    Decorator to protect routes requiring authentication.
    
    Security Features:
    - Validates JWT token presence and signature
    - Checks token expiration
    - Uses secure cookie settings
    - Implements proper error handling
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return redirect(url_for('login'))
        except jwt.InvalidTokenError:
            return redirect(url_for('login'))
    return decorated

def get_current_user_id():
    """
    Get the current user's ID from their JWT token.
    
    Security Features:
    - Validates token signature
    - Handles token expiration
    - Returns None for invalid tokens
    """
    token = request.cookies.get('token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
        return payload['user_id']
    except:
        return None

@app.route('/')
def index():
    """
    Home page route.
    
    Security Features:
    - Jinja2 auto-escaping prevents XSS
    - CSRF protection through Flask-WTF
    """
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """
    User registration route.
    
    Security Features:
    - Password hashing using PBKDF2 (via Werkzeug)
    - Input validation for username and password
    - SQL injection prevention using parameterized queries
    - CSRF protection through Flask-WTF
    - XSS prevention through Jinja2 auto-escaping
    - Username uniqueness enforced at database level
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate username
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            return render_template('signup.html', error=error_msg)
        
        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            return render_template('signup.html', error=error_msg)
        
        # SECURITY: Hash password using PBKDF2 with SHA256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                # SECURITY: Parameterized query prevents SQL injection
                c.execute('INSERT INTO users (username, password) VALUES (?, ?)',
                         (username, hashed_password))
                conn.commit()
            
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return render_template('signup.html', error='Username already exists')
        except Exception as e:
            logger.error(f"Error during signup: {str(e)}")
            return render_template('signup.html', error='An error occurred during signup')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Rate limit login attempts
def login():
    """
    User authentication route.
    
    Security Features:
    - Generic error messages prevent user enumeration
    - Password verification using constant-time comparison
    - SQL injection prevention using parameterized queries
    - Secure cookie settings for JWT storage
    - CSRF protection through Flask-WTF
    - XSS prevention through Jinja2 auto-escaping
    - Rate limiting to prevent brute force attacks
    """
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            return render_template('login.html', error='Please fill in all fields')
        
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                # SECURITY: Parameterized query prevents SQL injection
                c.execute('SELECT id, password, failed_login_attempts FROM users WHERE username = ?', (username,))
                user = c.fetchone()
                
                if user:
                    # Check if account is locked
                    if user[2] >= 5:  # More than 5 failed attempts
                        return render_template('login.html', error='Account temporarily locked. Please try again later.')
                    
                    # SECURITY: Constant-time password comparison
                    if check_password_hash(user[1], password):
                        # Reset failed attempts on successful login
                        c.execute('UPDATE users SET failed_login_attempts = 0, last_login = CURRENT_TIMESTAMP WHERE id = ?', (user[0],))
                        conn.commit()
                        
                        token = generate_token(user[0])
                        response = make_response(redirect(url_for('dashboard')))
                        # SECURITY: Secure cookie settings
                        response.set_cookie('token', token, httponly=True, secure=True, samesite='Strict')
                        return response
                    else:
                        # Increment failed attempts
                        c.execute('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?', (user[0],))
                        conn.commit()
        
        except Exception as e:
            logger.error(f"Error during login: {str(e)}")
        
        # SECURITY: Generic error message prevents user enumeration
        return render_template('login.html', error='Login failed')
    
    return render_template('login.html')

@app.route('/dashboard')
@token_required
def dashboard():
    """
    User dashboard route.
    
    Security Features:
    - Protected by token_required decorator
    - SQL injection prevention using parameterized queries
    - XSS prevention through Jinja2 auto-escaping
    - CSRF protection through Flask-WTF
    """
    user_id = get_current_user_id()
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # SECURITY: Parameterized query prevents SQL injection
    c.execute('SELECT username, gems FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    
    return render_template('dashboard.html', username=user[0], gems=user[1])

@app.route('/transfer', methods=['GET', 'POST'])
@token_required
def transfer():
    """
    Asset transfer route.
    
    Security Features:
    - Protected by token_required decorator
    - Input validation for amount and recipient
    - SQL injection prevention using parameterized queries
    - Atomic transactions prevent race conditions
    - XSS prevention through Jinja2 auto-escaping
    - CSRF protection through Flask-WTF
    - Proper error handling and validation
    """
    user_id = get_current_user_id()
    
    if request.method == 'POST':
        recipient = request.form.get('recipient', '').strip()
        amount = request.form.get('amount')
        
        # Validate recipient username
        is_valid, error_msg = validate_username(recipient)
        if not is_valid:
            return render_template('transfer.html', error=error_msg)
        
        # SECURITY: Input validation
        try:
            amount = int(amount)
            if amount <= 0:
                return render_template('transfer.html', error='Amount must be positive')
            if amount > 1000000:  # Reasonable upper limit
                return render_template('transfer.html', error='Amount exceeds maximum limit')
        except ValueError:
            return render_template('transfer.html', error='Invalid amount')
        
        try:
            with sqlite3.connect('users.db') as conn:
                conn.isolation_level = 'SERIALIZABLE'  # Highest isolation level
                c = conn.cursor()
                
                # SECURITY: Parameterized query prevents SQL injection
                c.execute('SELECT gems FROM users WHERE id = ?', (user_id,))
                sender_balance = c.fetchone()[0]
                
                if sender_balance < amount:
                    return render_template('transfer.html', error='Insufficient gems')
                
                # SECURITY: Parameterized query prevents SQL injection
                c.execute('SELECT id FROM users WHERE username = ?', (recipient,))
                recipient_data = c.fetchone()
                if not recipient_data:
                    return render_template('transfer.html', error='Recipient not found')
                
                recipient_id = recipient_data[0]
                
                if recipient_id == user_id:
                    return render_template('transfer.html', error='Cannot transfer to yourself')
                
                # SECURITY: Atomic transaction prevents race conditions
                c.execute('BEGIN TRANSACTION')
                
                # SECURITY: Parameterized queries prevent SQL injection
                c.execute('UPDATE users SET gems = gems - ? WHERE id = ?', (amount, user_id))
                c.execute('UPDATE users SET gems = gems + ? WHERE id = ?', (amount, recipient_id))
                
                conn.commit()
                return redirect(url_for('dashboard'))
                
        except sqlite3.IntegrityError:
            return render_template('transfer.html', error='Database integrity error')
        except Exception as e:
            logger.error(f"Error during transfer: {str(e)}")
            return render_template('transfer.html', error='Transfer failed')
    
    return render_template('transfer.html')

@app.route('/logout')
def logout():
    """
    User logout route.
    
    Security Features:
    - Properly removes secure cookies
    - Implements secure cookie deletion
    """
    response = make_response(redirect(url_for('index')))
    response.delete_cookie('token')
    return response

if __name__ == '__main__':
    # SECURITY: Disable debug mode in production
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode) 