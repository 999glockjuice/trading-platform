"""
Session Manager for Trading Platform
Handles user sessions, token validation, and security
"""

import sqlite3
import jwt
from datetime import datetime, timedelta
from typing import Dict, Optional
import os
from .authentication import SECRET_KEY, JWT_ALGORITHM, DB_PATH

class SessionManager:
    """Manages user sessions and token operations"""
    
    def __init__(self):
        self._init_session_tables()
    
    def _init_session_tables(self):
        """Initialize session-related database tables"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Active sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_active BOOLEAN DEFAULT TRUE,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Token blacklist (for logout)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS token_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token TEXT UNIQUE NOT NULL,
                blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                reason TEXT
            )
        ''')
        
        # Security logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                details TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def create_session(self, user_id: int, ip_address: str = None, 
                      user_agent: str = None) -> Dict:
        """
        Create a new session for user
        
        Args:
            user_id: User ID
            ip_address: Client IP address
            user_agent: Client user agent
        
        Returns:
            Session token and details
        """
        # Generate session token
        session_token = jwt.encode({
            'user_id': user_id,
            'created': datetime.utcnow().isoformat(),
            'type': 'session'
        }, SECRET_KEY, algorithm=JWT_ALGORITHM)
        
        # Session expires in 7 days
        expires_at = datetime.utcnow() + timedelta(days=7)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Insert session
            cursor.execute('''
                INSERT INTO sessions 
                (user_id, session_token, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, session_token, ip_address, user_agent, expires_at))
            
            # Log security event
            cursor.execute('''
                INSERT INTO security_logs (user_id, action, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, 'session_create', ip_address, user_agent, 'New session created'))
            
            conn.commit()
            conn.close()
            
            return {
                'session_token': session_token,
                'expires_at': expires_at.isoformat(),
                'user_id': user_id
            }
            
        except sqlite3.Error as e:
            raise Exception(f"Failed to create session: {str(e)}")
    
    def validate_session(self, session_token: str, update_activity: bool = True) -> Optional[Dict]:
        """
        Validate session token
        
        Args:
            session_token: Session token to validate
            update_activity: Whether to update last activity timestamp
        
        Returns:
            Session data if valid, None otherwise
        """
        try:
            # First check if token is blacklisted
            if self._is_token_blacklisted(session_token):
                return None
            
            # Decode token
            payload = jwt.decode(session_token, SECRET_KEY, algorithms=[JWT_ALGORITHM])
            
            if payload.get('type') != 'session':
                return None
            
            user_id = payload.get('user_id')
            
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check session in database
            cursor.execute('''
                SELECT id, user_id, ip_address, user_agent, created_at, 
                       expires_at, is_active, last_activity
                FROM sessions 
                WHERE session_token = ? AND is_active = TRUE AND expires_at > ?
            ''', (session_token, datetime.utcnow()))
            
            session_data = cursor.fetchone()
            
            if not session_data:
                conn.close()
                return None
            
            # Update last activity if requested
            if update_activity:
                cursor.execute('''
                    UPDATE sessions 
                    SET last_activity = ? 
                    WHERE session_token = ?
                ''', (datetime.utcnow(), session_token))
                
                conn.commit()
            
            conn.close()
            
            # Prepare session info
            columns = ['id', 'user_id', 'ip_address', 'user_agent', 'created_at',
                      'expires_at', 'is_active', 'last_activity']
            session_dict = dict(zip(columns, session_data))
            
            return session_dict
            
        except jwt.InvalidTokenError:
            return None
        except Exception:
            return None
    
    def invalidate_session(self, session_token: str, reason: str = "user_logout") -> bool:
        """
        Invalidate a session (logout)
        
        Args:
            session_token: Session token to invalidate
            reason: Reason for invalidation
        
        Returns:
            Success status
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get session info before deleting
            cursor.execute('SELECT user_id FROM sessions WHERE session_token = ?', 
                          (session_token,))
            session = cursor.fetchone()
            
            if session:
                user_id = session[0]
                
                # Deactivate session
                cursor.execute('''
                    UPDATE sessions 
                    SET is_active = FALSE 
                    WHERE session_token = ?
                ''', (session_token,))
                
                # Add to blacklist
                expires_at = datetime.utcnow() + timedelta(days=30)  # Keep in blacklist for 30 days
                cursor.execute('''
                    INSERT INTO token_blacklist (token, expires_at, reason)
                    VALUES (?, ?, ?)
                ''', (session_token, expires_at, reason))
                
                # Log security event
                cursor.execute('''
                    INSERT INTO security_logs (user_id, action, details)
                    VALUES (?, ?, ?)
                ''', (user_id, 'session_invalidate', f'Session invalidated: {reason}'))
                
                conn.commit()
                conn.close()
                return True
            
            conn.close()
            return False
            
        except sqlite3.Error:
            return False
    
    def invalidate_all_user_sessions(self, user_id: int, reason: str = "security_update") -> bool:
        """
        Invalidate all sessions for a user
        
        Args:
            user_id: User ID
            reason: Reason for invalidation
        
        Returns:
            Success status
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get all active session tokens for user
            cursor.execute('''
                SELECT session_token FROM sessions 
                WHERE user_id = ? AND is_active = TRUE
            ''', (user_id,))
            
            sessions = cursor.fetchall()
            
            # Invalidate each session
            for (session_token,) in sessions:
                expires_at = datetime.utcnow() + timedelta(days=30)
                cursor.execute('''
                    INSERT OR IGNORE INTO token_blacklist (token, expires_at, reason)
                    VALUES (?, ?, ?)
                ''', (session_token, expires_at, reason))
            
            # Deactivate all sessions
            cursor.execute('''
                UPDATE sessions 
                SET is_active = FALSE 
                WHERE user_id = ?
            ''', (user_id,))
            
            # Log security event
            cursor.execute('''
                INSERT INTO security_logs (user_id, action, details)
                VALUES (?, ?, ?)
            ''', (user_id, 'all_sessions_invalidate', 
                  f'All sessions invalidated: {reason}'))
            
            conn.commit()
            conn.close()
            return True
            
        except sqlite3.Error:
            return False
    
    def get_active_sessions(self, user_id: int) -> list:
        """
        Get all active sessions for a user
        
        Args:
            user_id: User ID
        
        Returns:
            List of active sessions
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, session_token, ip_address, user_agent, 
                       created_at, expires_at, last_activity
                FROM sessions 
                WHERE user_id = ? AND is_active = TRUE AND expires_at > ?
                ORDER BY last_activity DESC
            ''', (user_id, datetime.utcnow()))
            
            sessions = cursor.fetchall()
            conn.close()
            
            columns = ['id', 'session_token', 'ip_address', 'user_agent',
                      'created_at', 'expires_at', 'last_activity']
            
            return [dict(zip(columns, session)) for session in sessions]
            
        except sqlite3.Error:
            return []
    
    def cleanup_expired_sessions(self) -> int:
        """
        Clean up expired sessions and blacklisted tokens
        
        Returns:
            Number of records cleaned up
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Deactivate expired sessions
            cursor.execute('''
                UPDATE sessions 
                SET is_active = FALSE 
                WHERE expires_at <= ?
            ''', (datetime.utcnow(),))
            
            sessions_cleaned = cursor.rowcount
            
            # Remove expired blacklisted tokens
            cursor.execute('''
                DELETE FROM token_blacklist 
                WHERE expires_at <= ?
            ''', (datetime.utcnow(),))
            
            tokens_cleaned = cursor.rowcount
            
            # Remove old security logs (older than 90 days)
            ninety_days_ago = datetime.utcnow() - timedelta(days=90)
            cursor.execute('''
                DELETE FROM security_logs 
                WHERE created_at <= ?
            ''', (ninety_days_ago,))
            
            logs_cleaned = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return sessions_cleaned + tokens_cleaned + logs_cleaned
            
        except sqlite3.Error:
            return 0
    
    def _is_token_blacklisted(self, token: str) -> bool:
        """Check if token is in blacklist"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id FROM token_blacklist 
                WHERE token = ? AND expires_at > ?
            ''', (token, datetime.utcnow()))
            
            result = cursor.fetchone() is not None
            conn.close()
            
            return result
            
        except sqlite3.Error:
            return False
    
    def log_security_event(self, user_id: Optional[int], action: str, 
                          ip_address: str = None, user_agent: str = None,
                          details: str = None):
        """
        Log security-related event
        
        Args:
            user_id: User ID (None for system events)
            action: Action description
            ip_address: Client IP
            user_agent: Client user agent
            details: Additional details
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO security_logs 
                (user_id, action, ip_address, user_agent, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, action, ip_address, user_agent, details))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error:
            pass  # Silent fail for logging errors

# Singleton instance
session_manager = SessionManager()

# Flask middleware for session management
def session_middleware(app):
    """Add session management middleware to Flask app"""
    from flask import request, g
    
    @app.before_request
    def load_session():
        """Load session data for authenticated requests"""
        g.session = None
        g.user_id = None
        
        # Skip for auth endpoints
        if request.path.startswith('/api/auth/'):
            return
        
        # Check for session token
        session_token = request.headers.get('X-Session-Token') or \
                       request.cookies.get('session_token')
        
        if session_token:
            session_data = session_manager.validate_session(session_token)
            if session_data:
                g.session = session_data
                g.user_id = session_data['user_id']
    
    @app.after_request
    def update_session_activity(response):
        """Update session activity timestamp"""
        if hasattr(g, 'session') and g.session:
            # Activity already updated in validate_session
            pass
        return response

def require_session(f):
    """Decorator to require valid session"""
    from flask import request, jsonify, g
    from functools import wraps
    
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    
    return decorated_function

if __name__ == '__main__':
    # Test session manager
    print("Testing Session Manager...")
    
    manager = SessionManager()
    
    # Create a test session
    session = manager.create_session(
        user_id=1,
        ip_address="192.168.1.100",
        user_agent="Test Browser"
    )
    
    print(f"Session created: {session['session_token'][:50]}...")
    
    # Validate session
    validated = manager.validate_session(session['session_token'])
    if validated:
        print(f"Session validated for user {validated['user_id']}")
    else:
        print("Session validation failed")
    
    # Get active sessions
    active_sessions = manager.get_active_sessions(1)
    print(f"Active sessions: {len(active_sessions)}")
    
    # Cleanup
    cleaned = manager.cleanup_expired_sessions()
    print(f"Cleaned up {cleaned} expired records")
    
    print("Session manager test completed")
