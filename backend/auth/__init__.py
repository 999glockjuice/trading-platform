"""
Authentication Package for Trading Platform
Centralized authentication and user management system
"""

from .authentication import (
    UserManager,
    user_manager,
    create_auth_blueprint,
    AuthenticationError
)

from .session_manager import (
    SessionManager,
    session_manager,
    session_middleware,
    require_session
)

from .email_verification import (
    EmailVerificationManager,
    email_verification_manager,
    create_email_verification_blueprint,
    EmailVerificationError
)

from .password_reset import (
    PasswordResetManager,
    password_reset_manager,
    create_password_reset_blueprint,
    PasswordResetError
)

from .two_factor import (
    TwoFactorManager,
    two_factor_manager,
    create_two_factor_blueprint,
    TwoFactorError
)

# Version information
__version__ = '1.0.0'
__author__ = 'Trading Platform Team'
__description__ = 'Professional authentication system for trading platform'

# Export all authentication blueprints
def get_all_auth_blueprints():
    """Get all authentication-related Flask blueprints"""
    return {
        'auth': create_auth_blueprint(),
        'email_verification': create_email_verification_blueprint(),
        'password_reset': create_password_reset_blueprint(),
        'two_factor': create_two_factor_blueprint()
    }

# Export all managers
def get_all_managers():
    """Get all authentication managers"""
    return {
        'user_manager': user_manager,
        'session_manager': session_manager,
        'email_verification_manager': email_verification_manager,
        'password_reset_manager': password_reset_manager,
        'two_factor_manager': two_factor_manager
    }

# Initialize all authentication systems
def init_auth_systems(app):
    """
    Initialize all authentication systems for Flask app
    
    Args:
        app: Flask application instance
    """
    # Initialize database tables
    user_manager._init_database()
    session_manager._init_session_tables()
    email_verification_manager._init_verification_tables()
    password_reset_manager._init_reset_tables()
    two_factor_manager._init_2fa_tables()
    
    # Add session middleware
    session_middleware(app)
    
    # Register all blueprints
    blueprints = get_all_auth_blueprints()
    for name, blueprint in blueprints.items():
        app.register_blueprint(blueprint)
    
    # Schedule cleanup tasks (in production, use Celery or similar)
    schedule_cleanup_tasks()

def schedule_cleanup_tasks():
    """Schedule periodic cleanup tasks for authentication systems"""
    import threading
    import time
    
    def cleanup_job():
        """Run cleanup tasks periodically"""
        while True:
            try:
                # Run every hour
                time.sleep(3600)
                
                # Cleanup expired sessions
                sessions_cleaned = session_manager.cleanup_expired_sessions()
                
                # Cleanup expired email verifications
                verifications_cleaned = email_verification_manager.cleanup_expired_verifications()
                
                # Cleanup expired password resets
                resets_cleaned = password_reset_manager.cleanup_expired_resets()
                
                # Log cleanup results (in production)
                if any([sessions_cleaned, verifications_cleaned, resets_cleaned]):
                    print(f"[AUTH CLEANUP] Sessions: {sessions_cleaned}, "
                          f"Verifications: {verifications_cleaned}, "
                          f"Resets: {resets_cleaned}")
                    
            except Exception as e:
                print(f"[AUTH CLEANUP ERROR] {e}")
    
    # Start cleanup thread (daemon will exit when main thread exits)
    cleanup_thread = threading.Thread(target=cleanup_job, daemon=True)
    cleanup_thread.start()
    print("[AUTH] Cleanup tasks scheduled")

# Convenience functions for common operations
def authenticate_user(email: str, password: str) -> dict:
    """Authenticate user with email and password"""
    return user_manager.login_user(email, password)

def register_new_user(email: str, username: str, password: str, 
                     account_type: str = 'demo') -> dict:
    """Register a new user"""
    return user_manager.register_user(email, username, password, account_type)

def verify_jwt_token(token: str) -> dict:
    """Verify JWT token"""
    return user_manager.verify_token(token)

def create_user_session(user_id: int, ip_address: str = None, 
                       user_agent: str = None) -> dict:
    """Create a new session for user"""
    return session_manager.create_session(user_id, ip_address, user_agent)

def setup_user_2fa(user_id: int, email: str, username: str) -> dict:
    """Set up 2FA for user"""
    return two_factor_manager.setup_2fa(user_id, email, username)

def request_password_reset(email: str, ip_address: str = None,
                          user_agent: str = None) -> dict:
    """Request password reset for user"""
    return password_reset_manager.request_password_reset(email, ip_address, user_agent)

def get_user_auth_status(user_id: int) -> dict:
    """Get comprehensive authentication status for user"""
    user_info = user_manager.get_user_by_id(user_id)
    
    if not user_info:
        return {'error': 'User not found'}
    
    # Get 2FA status
    twofa_status = two_factor_manager.get_2fa_status(user_id)
    
    # Get email verification status
    email_status = email_verification_manager.get_verification_status(user_id)
    
    # Get active sessions
    active_sessions = session_manager.get_active_sessions(user_id)
    
    return {
        'user': {
            'id': user_info['id'],
            'email': user_info['email'],
            'username': user_info['username'],
            'account_type': user_info['account_type'],
            'is_email_verified': user_info['is_email_verified'],
            'is_kyc_verified': user_info['is_kyc_verified'],
            'created_at': user_info['created_at'],
            'last_login': user_info.get('last_login')
        },
        'two_factor': twofa_status,
        'email_verification': email_status,
        'sessions': {
            'active_count': len(active_sessions),
            'devices': active_sessions
        }
    }

# Export everything
__all__ = [
    # Managers
    'UserManager',
    'SessionManager', 
    'EmailVerificationManager',
    'PasswordResetManager',
    'TwoFactorManager',
    
    # Instances
    'user_manager',
    'session_manager',
    'email_verification_manager',
    'password_reset_manager',
    'two_factor_manager',
    
    # Blueprint creators
    'create_auth_blueprint',
    'create_email_verification_blueprint',
    'create_password_reset_blueprint',
    'create_two_factor_blueprint',
    
    # Middleware and decorators
    'session_middleware',
    'require_session',
    
    # Errors
    'AuthenticationError',
    'EmailVerificationError',
    'PasswordResetError',
    'TwoFactorError',
    
    # Convenience functions
    'get_all_auth_blueprints',
    'get_all_managers',
    'init_auth_systems',
    'authenticate_user',
    'register_new_user',
    'verify_jwt_token',
    'create_user_session',
    'setup_user_2fa',
    'request_password_reset',
    'get_user_auth_status'
]

if __name__ == '__main__':
    print(f"Trading Platform Authentication System v{__version__}")
    print(f"Description: {__description__}")
    print(f"Author: {__author__}")
    print("\nAvailable components:")
    print("- User Management")
    print("- Session Management")
    print("- Email Verification")
    print("- Password Reset")
    print("- Two-Factor Authentication")
    print("\nReady for integration with Flask application.")
