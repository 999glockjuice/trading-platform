"""
Password Reset Module for Trading Platform
Handles secure password reset functionality
"""

import sqlite3
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import os
import threading

# Database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                       'data', 'databases', 'users.db')

# Password reset token expiry (1 hour)
RESET_TOKEN_EXPIRE_HOURS = 1

# Maximum reset attempts per hour
MAX_RESET_ATTEMPTS = 3

class PasswordResetError(Exception):
    """Custom exception for password reset errors"""
    pass

class PasswordResetManager:
    """Manages password reset operations"""
    
    def __init__(self):
        self._init_reset_tables()
    
    def _init_reset_tables(self):
        """Initialize password reset tables"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Password reset requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                reset_token TEXT UNIQUE NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                used_at TIMESTAMP,
                is_used BOOLEAN DEFAULT FALSE,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Password reset attempts (for rate limiting)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reset_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                successful BOOLEAN DEFAULT FALSE
            )
        ''')
        
        # Password history (store last N passwords)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                password_hash TEXT NOT NULL,
                changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create indexes for performance
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reset_token 
            ON password_resets(reset_token)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reset_user 
            ON password_resets(user_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_reset_attempts_email 
            ON reset_attempts(email)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_password_history_user 
            ON password_history(user_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def _hash_token(self, token: str) -> str:
        """Create a secure hash of the reset token"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _can_request_reset(self, email: str, ip_address: str = None) -> Tuple[bool, str]:
        """
        Check if password reset can be requested (rate limiting)
        
        Args:
            email: User email
            ip_address: Client IP address
        
        Returns:
            Tuple of (can_request, reason)
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check recent attempts for this email
            one_hour_ago = datetime.now() - timedelta(hours=1)
            cursor.execute('''
                SELECT COUNT(*) FROM reset_attempts 
                WHERE email = ? AND attempt_time > ?
            ''', (email, one_hour_ago))
            
            recent_attempts = cursor.fetchone()[0]
            
            # Check recent attempts from this IP
            if ip_address:
                cursor.execute('''
                    SELECT COUNT(*) FROM reset_attempts 
                    WHERE ip_address = ? AND attempt_time > ?
                ''', (ip_address, one_hour_ago))
                
                ip_attempts = cursor.fetchone()[0]
                
                # Limit per IP as well
                if ip_attempts >= MAX_RESET_ATTEMPTS * 2:
                    conn.close()
                    return False, "Too many reset attempts from this IP address"
            
            conn.close()
            
            if recent_attempts >= MAX_RESET_ATTEMPTS:
                return False, "Too many reset attempts. Please try again later."
            
            return True, "Reset can be requested"
            
        except sqlite3.Error:
            return False, "Internal error checking reset limits"
    
    def _record_reset_attempt(self, email: str, successful: bool, 
                            ip_address: str = None, user_agent: str = None):
        """Record a password reset attempt"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO reset_attempts 
                (email, ip_address, user_agent, successful)
                VALUES (?, ?, ?, ?)
            ''', (email, ip_address, user_agent, successful))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error:
            pass  # Silent fail for logging errors
    
    def request_password_reset(self, email: str, ip_address: str = None, 
                              user_agent: str = None) -> Dict:
        """
        Request a password reset for a user
        
        Args:
            email: User email
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Reset request details
        """
        # Check rate limits
        can_request, reason = self._can_request_reset(email, ip_address)
        if not can_request:
            self._record_reset_attempt(email, False, ip_address, user_agent)
            raise PasswordResetError(reason)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Find user by email
            cursor.execute('''
                SELECT id, username, email FROM users 
                WHERE email = ? AND status = 'active'
            ''', (email,))
            
            user = cursor.fetchone()
            
            if not user:
                # Don't reveal if user exists or not
                self._record_reset_attempt(email, False, ip_address, user_agent)
                conn.close()
                
                # Return success even if user doesn't exist (security best practice)
                return {
                    'success': True,
                    'message': 'If an account exists with this email, a reset link has been sent',
                    'email_sent': False  # Actually not sent, but don't reveal
                }
            
            user_id, username, user_email = user
            
            # Invalidate any existing reset tokens for this user
            cursor.execute('''
                UPDATE password_resets 
                SET is_used = TRUE 
                WHERE user_id = ? AND is_used = FALSE
            ''', (user_id,))
            
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            token_hash = self._hash_token(reset_token)
            
            # Calculate expiry time
            expires_at = datetime.now() + timedelta(hours=RESET_TOKEN_EXPIRE_HOURS)
            
            # Store reset request
            cursor.execute('''
                INSERT INTO password_resets 
                (user_id, reset_token, token_hash, expires_at, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, reset_token, token_hash, expires_at, ip_address, user_agent))
            
            conn.commit()
            conn.close()
            
            # Record successful attempt
            self._record_reset_attempt(email, True, ip_address, user_agent)
            
            # In production, send reset email here
            # For now, we'll return the token for testing
            # In production, NEVER return the token in response
            
            reset_url = f"https://yourplatform.com/reset-password?token={reset_token}"
            
            # Log reset request for development
            if os.environ.get('ENVIRONMENT') == 'development':
                print(f"\n{'='*60}")
                print("🔐 PASSWORD RESET REQUEST (Development Mode)")
                print(f"User: {username} ({user_email})")
                print(f"Reset Token: {reset_token}")
                print(f"Reset URL: {reset_url}")
                print(f"Expires at: {expires_at}")
                print(f"{'='*60}\n")
                
                # Save to log file
                reset_log_path = os.path.join(os.path.dirname(DB_PATH), '..', 'logs', 'reset_log.txt')
                os.makedirs(os.path.dirname(reset_log_path), exist_ok=True)
                
                with open(reset_log_path, 'a') as f:
                    f.write(f"\n{'='*60}\n")
                    f.write(f"Time: {datetime.now()}\n")
                    f.write(f"User: {username} ({user_email})\n")
                    f.write(f"Token: {reset_token}\n")
                    f.write(f"URL: {reset_url}\n")
                    f.write(f"Expires: {expires_at}\n")
                    f.write(f"{'='*60}\n")
            
            return {
                'success': True,
                'message': 'If an account exists with this email, a reset link has been sent',
                'email_sent': True,
                'token': reset_token,  # Only in development!
                'expires_at': expires_at.isoformat()
            }
            
        except sqlite3.Error as e:
            self._record_reset_attempt(email, False, ip_address, user_agent)
            raise PasswordResetError(f"Database error: {str(e)}")
    
    def validate_reset_token(self, token: str) -> Tuple[bool, Optional[Dict]]:
        """
        Validate a password reset token
        
        Args:
            token: Reset token to validate
        
        Returns:
            Tuple of (is_valid, token_data)
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Find reset request by token
            cursor.execute('''
                SELECT pr.id, pr.user_id, pr.expires_at, pr.is_used, pr.used_at,
                       u.email, u.username
                FROM password_resets pr
                JOIN users u ON pr.user_id = u.id
                WHERE pr.reset_token = ? AND u.status = 'active'
            ''', (token,))
            
            reset_request = cursor.fetchone()
            
            if not reset_request:
                conn.close()
                return False, {'error': 'Invalid reset token'}
            
            (reset_id, user_id, expires_at, is_used, used_at, 
             email, username) = reset_request
            
            # Check if already used
            if is_used:
                conn.close()
                return False, {'error': 'Reset token already used'}
            
            # Check if expired
            if datetime.now() > datetime.fromisoformat(expires_at):
                conn.close()
                return False, {'error': 'Reset token has expired'}
            
            conn.close()
            
            return True, {
                'reset_id': reset_id,
                'user_id': user_id,
                'email': email,
                'username': username,
                'expires_at': expires_at
            }
            
        except sqlite3.Error:
            return False, {'error': 'Database error validating token'}
    
    def _check_password_history(self, user_id: int, new_password_hash: str) -> bool:
        """
        Check if new password is in recent history
        
        Args:
            user_id: User ID
            new_password_hash: Hash of new password
        
        Returns:
            True if password is not in recent history
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check last 5 passwords
            cursor.execute('''
                SELECT password_hash FROM password_history 
                WHERE user_id = ? 
                ORDER BY changed_at DESC 
                LIMIT 5
            ''', (user_id,))
            
            recent_passwords = [row[0] for row in cursor.fetchall()]
            conn.close()
            
            return new_password_hash not in recent_passwords
            
        except sqlite3.Error:
            return True  # If we can't check, allow the password change
    
    def _add_to_password_history(self, user_id: int, password_hash: str):
        """Add password to history"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO password_history (user_id, password_hash)
                VALUES (?, ?)
            ''', (user_id, password_hash))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error:
            pass  # Silent fail
    
    def reset_password(self, token: str, new_password: str, 
                      ip_address: str = None, user_agent: str = None) -> Dict:
        """
        Reset password using valid token
        
        Args:
            token: Valid reset token
            new_password: New password
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Reset operation result
        """
        from .authentication import UserManager
        
        # Validate token
        is_valid, token_data = self.validate_reset_token(token)
        
        if not is_valid:
            return {'success': False, 'error': token_data['error']}
        
        user_id = token_data['user_id']
        email = token_data['email']
        
        # Validate new password
        user_manager = UserManager()
        is_valid, message = user_manager._validate_password(new_password)
        
        if not is_valid:
            return {'success': False, 'error': message}
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Hash new password
            new_password_hash = user_manager._hash_password(new_password)
            
            # Check password history
            if not self._check_password_history(user_id, new_password_hash):
                conn.close()
                return {
                    'success': False, 
                    'error': 'Cannot reuse recent passwords'
                }
            
            # Update user password
            cursor.execute('''
                UPDATE users 
                SET password_hash = ?, last_login = ?
                WHERE id = ? AND status = 'active'
            ''', (new_password_hash, datetime.now(), user_id))
            
            # Mark reset token as used
            cursor.execute('''
                UPDATE password_resets 
                SET is_used = TRUE, used_at = ?
                WHERE reset_token = ?
            ''', (datetime.now(), token))
            
            # Add to password history
            self._add_to_password_history(user_id, new_password_hash)
            
            # Invalidate all user sessions (security measure)
            from .session_manager import session_manager
            session_manager.invalidate_all_user_sessions(
                user_id, 
                reason="password_reset"
            )
            
            # Record security event
            cursor.execute('''
                INSERT INTO security_logs (user_id, action, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, 'password_reset', ip_address, user_agent, 
                  'Password reset via email'))
            
            conn.commit()
            conn.close()
            
            # Record successful reset attempt
            self._record_reset_attempt(email, True, ip_address, user_agent)
            
            return {
                'success': True,
                'message': 'Password reset successful',
                'user_id': user_id,
                'email': email,
                'reset_at': datetime.now().isoformat()
            }
            
        except sqlite3.Error as e:
            return {'success': False, 'error': f'Database error: {str(e)}'}
    
    def cleanup_expired_resets(self) -> int:
        """
        Clean up expired password reset requests
        
        Returns:
            Number of records cleaned
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Mark expired resets as used
            cursor.execute('''
                UPDATE password_resets 
                SET is_used = TRUE 
                WHERE expires_at <= ? AND is_used = FALSE
            ''', (datetime.now(),))
            
            cleaned_count = cursor.rowcount
            
            # Clean up old reset attempts (older than 30 days)
            thirty_days_ago = datetime.now() - timedelta(days=30)
            cursor.execute('''
                DELETE FROM reset_attempts 
                WHERE attempt_time <= ?
            ''', (thirty_days_ago,))
            
            # Clean up old password history (older than 1 year)
            one_year_ago = datetime.now() - timedelta(days=365)
            cursor.execute('''
                DELETE FROM password_history 
                WHERE changed_at <= ?
            ''', (one_year_ago,))
            
            conn.commit()
            conn.close()
            
            return cleaned_count
            
        except sqlite3.Error:
            return 0

# Singleton instance
password_reset_manager = PasswordResetManager()

# Flask Blueprint for password reset endpoints
def create_password_reset_blueprint():
    """Create Flask Blueprint for password reset"""
    from flask import Blueprint, request, jsonify
    
    reset_bp = Blueprint('password_reset', __name__, url_prefix='/api/password')
    
    @reset_bp.route('/reset/request', methods=['POST'])
    def request_reset():
        """Request password reset"""
        try:
            data = request.get_json()
            email = data.get('email', '').strip().lower()
            
            if not email:
                return jsonify({'error': 'Email is required'}), 400
            
            # Get client info
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = password_reset_manager.request_password_reset(
                email, ip_address, user_agent
            )
            
            return jsonify(result), 200
            
        except PasswordResetError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @reset_bp.route('/reset/validate', methods=['POST'])
    def validate_token():
        """Validate reset token"""
        try:
            data = request.get_json()
            token = data.get('token', '').strip()
            
            if not token:
                return jsonify({'error': 'Reset token required'}), 400
            
            is_valid, token_data = password_reset_manager.validate_reset_token(token)
            
            if is_valid:
                return jsonify({
                    'valid': True,
                    'email': token_data['email'],
                    'expires_at': token_data['expires_at']
                }), 200
            else:
                return jsonify({
                    'valid': False,
                    'error': token_data['error']
                }), 400
            
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @reset_bp.route('/reset/confirm', methods=['POST'])
    def confirm_reset():
        """Confirm password reset with token"""
        try:
            data = request.get_json()
            token = data.get('token', '').strip()
            new_password = data.get('new_password', '')
            
            if not token or not new_password:
                return jsonify({'error': 'Token and new password required'}), 400
            
            # Get client info
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = password_reset_manager.reset_password(
                token, new_password, ip_address, user_agent
            )
            
            if result['success']:
                return jsonify(result), 200
            else:
                return jsonify(result), 400
            
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    return reset_bp

if __name__ == '__main__':
    # Test the password reset system
    print("Testing Password Reset System...")
    
    manager = PasswordResetManager()
    
    try:
        # Test reset request
        result = manager.request_password_reset(
            email="test@example.com",
            ip_address="192.168.1.100",
            user_agent="Test Browser"
        )
        
        print("Reset request test:")
        print(f"Success: {result['success']}")
        print(f"Message: {result['message']}")
        
        if 'token' in result:
            print(f"Token (dev): {result['token'][:50]}...")
        
        # Test token validation (with fake token)
        is_valid, token_data = manager.validate_reset_token("fake_token")
        print(f"\nToken validation (fake): {'Invalid as expected' if not is_valid else 'UNEXPECTED VALID'}")
        
        # Cleanup
        cleaned = manager.cleanup_expired_resets()
        print(f"\nCleaned up {cleaned} expired reset requests")
        
    except PasswordResetError as e:
        print(f"Test failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    print("\nPassword reset test completed")
