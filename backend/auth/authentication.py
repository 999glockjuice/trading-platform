"""
Authentication Module for Professional Trading Platform
Handles user registration, login, and account management
UPDATED: Uses passlib instead of bcrypt for Termux compatibility
"""

import sqlite3
import jwt
import re
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import os

# Use passlib for password hashing (Termux compatible)
from passlib.hash import pbkdf2_sha256

# Database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                       'data', 'databases', 'users.db')

# JWT configuration
SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-key-for-mobile-trading')
JWT_ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass

class UserManager:
    """Manages user authentication and account operations"""
    
    def __init__(self):
        self._init_database()
    
    def _init_database(self):
        """Initialize the users database with required tables"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                account_type TEXT NOT NULL CHECK(account_type IN ('demo', 'live')),
                balance DECIMAL(15, 2) DEFAULT 0.00,
                demo_balance DECIMAL(15, 2) DEFAULT 500000.00,
                live_balance DECIMAL(15, 2) DEFAULT 20.00,
                is_email_verified BOOLEAN DEFAULT FALSE,
                is_kyc_verified BOOLEAN DEFAULT FALSE,
                two_factor_enabled BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                status TEXT DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'deleted'))
            )
        ''')
        
        # Email verification tokens
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verification_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Password reset tokens
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Login attempts (for security)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                ip_address TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                successful BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def _validate_password(self, password: str) -> Tuple[bool, str]:
        """Validate password strength"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r'[0-9]', password):
            return False, "Password must contain at least one number"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid"
    
    def _hash_password(self, password: str) -> str:
        """Hash password using pbkdf2_sha256 (Termux compatible)"""
        return pbkdf2_sha256.hash(password)
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash using passlib"""
        return pbkdf2_sha256.verify(password, hashed)
    
    def _create_tokens(self, user_id: int, email: str) -> Dict[str, str]:
        """Create JWT access and refresh tokens"""
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        
        access_token_payload = {
            'sub': email,
            'user_id': user_id,
            'type': 'access',
            'exp': datetime.utcnow() + access_token_expires
        }
        
        refresh_token_payload = {
            'sub': email,
            'user_id': user_id,
            'type': 'refresh',
            'exp': datetime.utcnow() + refresh_token_expires
        }
        
        access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
        refresh_token = jwt.encode(refresh_token_payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'bearer',
            'expires_in': ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }
    
    def register_user(self, email: str, username: str, password: str, 
                     account_type: str = 'demo') -> Dict:
        """
        Register a new user
        
        Args:
            email: User email
            username: Username
            password: Password
            account_type: 'demo' or 'live'
        
        Returns:
            Dictionary with user info and tokens
        """
        # Validate inputs
        if not self._validate_email(email):
            raise AuthenticationError("Invalid email format")
        
        is_valid, message = self._validate_password(password)
        if not is_valid:
            raise AuthenticationError(message)
        
        if account_type not in ['demo', 'live']:
            raise AuthenticationError("Account type must be 'demo' or 'live'")
        
        # Set initial balances
        demo_balance = 500000.00 if account_type == 'demo' else 0.00
        live_balance = 20.00 if account_type == 'live' else 0.00
        
        # Hash password
        password_hash = self._hash_password(password)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if email or username exists
            cursor.execute('SELECT id FROM users WHERE email = ? OR username = ?', 
                          (email, username))
            if cursor.fetchone():
                raise AuthenticationError("Email or username already exists")
            
            # Insert new user
            cursor.execute('''
                INSERT INTO users 
                (email, username, password_hash, account_type, demo_balance, live_balance)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (email, username, password_hash, account_type, demo_balance, live_balance))
            
            user_id = cursor.lastrowid
            
            # Create tokens
            tokens = self._create_tokens(user_id, email)
            
            # Update last login
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                          (datetime.now(), user_id))
            
            conn.commit()
            
            # Get user data
            cursor.execute('''
                SELECT id, email, username, account_type, demo_balance, live_balance,
                       is_email_verified, is_kyc_verified, created_at
                FROM users WHERE id = ?
            ''', (user_id,))
            
            user_data = cursor.fetchone()
            columns = [desc[0] for desc in cursor.description]
            user_dict = dict(zip(columns, user_data))
            
            conn.close()
            
            return {
                'user': user_dict,
                'tokens': tokens,
                'message': 'Registration successful'
            }
            
        except sqlite3.Error as e:
            raise AuthenticationError(f"Database error: {str(e)}")
    
    def login_user(self, email: str, password: str) -> Dict:
        """
        Authenticate user and return tokens
        
        Args:
            email: User email
            password: Plain text password
        
        Returns:
            Dictionary with user info and tokens
        """
        # Record login attempt
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        try:
            # Get user by email
            cursor.execute('''
                SELECT id, email, username, password_hash, account_type, 
                       demo_balance, live_balance, status, is_email_verified
                FROM users WHERE email = ?
            ''', (email,))
            
            user_data = cursor.fetchone()
            
            if not user_data:
                cursor.execute('''
                    INSERT INTO login_attempts (email, successful)
                    VALUES (?, ?)
                ''', (email, False))
                conn.commit()
                raise AuthenticationError("Invalid email or password")
            
            # Check account status
            if user_data[7] != 'active':  # status field
                raise AuthenticationError(f"Account is {user_data[7]}")
            
            # Verify password
            if not self._verify_password(password, user_data[3]):  # password_hash field
                cursor.execute('''
                    INSERT INTO login_attempts (email, successful)
                    VALUES (?, ?)
                ''', (email, False))
                conn.commit()
                raise AuthenticationError("Invalid email or password")
            
            user_id = user_data[0]
            
            # Create tokens
            tokens = self._create_tokens(user_id, email)
            
            # Update last login
            cursor.execute('UPDATE users SET last_login = ? WHERE id = ?', 
                          (datetime.now(), user_id))
            
            # Record successful login
            cursor.execute('''
                INSERT INTO login_attempts (email, successful)
                VALUES (?, ?)
            ''', (email, True))
            
            conn.commit()
            
            # Prepare user data
            columns = ['id', 'email', 'username', 'password_hash', 'account_type',
                      'demo_balance', 'live_balance', 'status', 'is_email_verified']
            user_dict = dict(zip(columns, user_data))
            
            # Remove sensitive data
            del user_dict['password_hash']
            
            return {
                'user': user_dict,
                'tokens': tokens,
                'message': 'Login successful'
            }
            
        finally:
            conn.close()
    
    def verify_token(self, token: str) -> Dict:
        """Verify JWT token and return user data"""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get('type') != 'access':
                raise AuthenticationError("Invalid token type")
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, email, username, account_type, demo_balance, live_balance,
                       is_email_verified, is_kyc_verified, status
                FROM users WHERE email = ? AND status = 'active'
            ''', (payload['sub'],))
            
            user_data = cursor.fetchone()
            conn.close()
            
            if not user_data:
                raise AuthenticationError("User not found or inactive")
            
            columns = ['id', 'email', 'username', 'account_type', 'demo_balance',
                      'live_balance', 'is_email_verified', 'is_kyc_verified', 'status']
            user_dict = dict(zip(columns, user_data))
            
            return {
                'valid': True,
                'user': user_dict,
                'expires': payload['exp']
            }
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid token")
    
    def refresh_token(self, refresh_token: str) -> Dict:
        """Refresh access token using refresh token"""
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get('type') != 'refresh':
                raise AuthenticationError("Invalid refresh token")
            
            # Create new access token
            access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
            access_token_payload = {
                'sub': payload['sub'],
                'user_id': payload['user_id'],
                'type': 'access',
                'exp': datetime.utcnow() + access_token_expires
            }
            
            access_token = jwt.encode(access_token_payload, SECRET_KEY, algorithm=JWT_ALGORITHM)
            
            return {
                'access_token': access_token,
                'token_type': 'bearer',
                'expires_in': ACCESS_TOKEN_EXPIRE_MINUTES * 60
            }
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Refresh token has expired")
        except jwt.InvalidTokenError:
            raise AuthenticationError("Invalid refresh token")
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user information by ID"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, email, username, account_type, demo_balance, live_balance,
                       is_email_verified, is_kyc_verified, created_at, last_login
                FROM users WHERE id = ? AND status = 'active'
            ''', (user_id,))
            
            user_data = cursor.fetchone()
            conn.close()
            
            if user_data:
                columns = [desc[0] for desc in cursor.description]
                return dict(zip(columns, user_data))
            
            return None
            
        except sqlite3.Error:
            return None
    
    def update_user_balance(self, user_id: int, account_type: str, 
                           amount: float, operation: str = 'add') -> bool:
        """
        Update user balance
        
        Args:
            user_id: User ID
            account_type: 'demo' or 'live'
            amount: Amount to update
            operation: 'add' or 'subtract'
        
        Returns:
            Success status
        """
        if account_type not in ['demo', 'live']:
            return False
        
        column = f'{account_type}_balance'
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            if operation == 'add':
                cursor.execute(f'''
                    UPDATE users 
                    SET {column} = {column} + ? 
                    WHERE id = ? AND status = 'active'
                ''', (amount, user_id))
            elif operation == 'subtract':
                # Check if sufficient balance
                cursor.execute(f'SELECT {column} FROM users WHERE id = ?', (user_id,))
                current_balance = cursor.fetchone()[0]
                
                if current_balance < amount:
                    conn.close()
                    return False
                
                cursor.execute(f'''
                    UPDATE users 
                    SET {column} = {column} - ? 
                    WHERE id = ? AND status = 'active'
                ''', (amount, user_id))
            else:
                conn.close()
                return False
            
            conn.commit()
            conn.close()
            return cursor.rowcount > 0
            
        except sqlite3.Error:
            return False

# Singleton instance
user_manager = UserManager()

# Flask Blueprint registration (will be used in app.py)
def create_auth_blueprint():
    """Create Flask Blueprint for authentication endpoints"""
    from flask import Blueprint, request, jsonify
    
    auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')
    
    @auth_bp.route('/register', methods=['POST'])
    def register():
        """Register new user"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            email = data.get('email', '').strip().lower()
            username = data.get('username', '').strip()
            password = data.get('password', '')
            account_type = data.get('account_type', 'demo')
            
            if not all([email, username, password]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            result = user_manager.register_user(email, username, password, account_type)
            return jsonify(result), 201
            
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @auth_bp.route('/login', methods=['POST'])
    def login():
        """User login"""
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({'error': 'No data provided'}), 400
            
            email = data.get('email', '').strip().lower()
            password = data.get('password', '')
            
            if not all([email, password]):
                return jsonify({'error': 'Missing email or password'}), 400
            
            result = user_manager.login_user(email, password)
            return jsonify(result), 200
            
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @auth_bp.route('/verify', methods=['POST'])
    def verify():
        """Verify JWT token"""
        try:
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Invalid authorization header'}), 401
            
            token = auth_header.split(' ')[1]
            result = user_manager.verify_token(token)
            return jsonify(result), 200
            
        except AuthenticationError as e:
            return jsonify({'error': str(e), 'valid': False}), 401
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @auth_bp.route('/refresh', methods=['POST'])
    def refresh():
        """Refresh access token"""
        try:
            data = request.get_json()
            refresh_token = data.get('refresh_token', '')
            
            if not refresh_token:
                return jsonify({'error': 'Refresh token required'}), 400
            
            result = user_manager.refresh_token(refresh_token)
            return jsonify(result), 200
            
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @auth_bp.route('/user/<int:user_id>', methods=['GET'])
    def get_user(user_id):
        """Get user information (protected)"""
        try:
            # Verify token first
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Unauthorized'}), 401
            
            token = auth_header.split(' ')[1]
            token_data = user_manager.verify_token(token)
            
            # Check if user is requesting their own data or is admin
            if token_data['user']['id'] != user_id:
                # In production, add admin check here
                return jsonify({'error': 'Forbidden'}), 403
            
            user_data = user_manager.get_user_by_id(user_id)
            
            if not user_data:
                return jsonify({'error': 'User not found'}), 404
            
            return jsonify({'user': user_data}), 200
            
        except AuthenticationError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    return auth_bp

if __name__ == '__main__':
    # Test the authentication system
    print("Testing Authentication System...")
    
    # Initialize database
    manager = UserManager()
    
    # Test registration
    try:
        result = manager.register_user(
            email="test@example.com",
            username="testuser",
            password="Test123!@#",
            account_type="demo"
        )
        print("Registration test: PASSED")
        print(f"User ID: {result['user']['id']}")
        print(f"Demo Balance: ${result['user']['demo_balance']:,.2f}")
        
        # Test login
        login_result = manager.login_user("test@example.com", "Test123!@#")
        print("\nLogin test: PASSED")
        print(f"Access Token: {login_result['tokens']['access_token'][:50]}...")
        
        # Test token verification
        token_data = manager.verify_token(login_result['tokens']['access_token'])
        print("\nToken verification test: PASSED")
        print(f"User email: {token_data['user']['email']}")
        
    except AuthenticationError as e:
        print(f"Test failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
