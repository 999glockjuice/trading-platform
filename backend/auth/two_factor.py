"""
Two-Factor Authentication (2FA) Module for Trading Platform
Provides enhanced security for user accounts
"""

import sqlite3
import pyotp
import qrcode
import base64
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import os
import io

# Database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                       'data', 'databases', 'users.db')

# 2FA configuration
TOTP_INTERVAL = 30  # Time-based OTP interval in seconds
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_LENGTH = 8

class TwoFactorError(Exception):
    """Custom exception for 2FA errors"""
    pass

class TwoFactorManager:
    """Manages Two-Factor Authentication operations"""
    
    def __init__(self):
        self._init_2fa_tables()
    
    def _init_2fa_tables(self):
        """Initialize 2FA related tables"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 2FA secrets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS two_factor_secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER UNIQUE NOT NULL,
                secret_key TEXT NOT NULL,
                backup_codes TEXT,  -- JSON array of backup codes
                enabled_at TIMESTAMP,
                last_used TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # 2FA verification attempts (for rate limiting)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS two_factor_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                successful BOOLEAN DEFAULT FALSE,
                ip_address TEXT,
                user_agent TEXT,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # 2FA devices (for remembering trusted devices)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                device_id TEXT NOT NULL,
                device_name TEXT,
                user_agent TEXT,
                ip_address TEXT,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_trusted BOOLEAN DEFAULT TRUE,
                FOREIGN KEY (user_id) REFERENCES users (id),
                UNIQUE(user_id, device_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_2fa_user 
            ON two_factor_secrets(user_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_2fa_attempts_user 
            ON two_factor_attempts(user_id)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_trusted_devices_user 
            ON trusted_devices(user_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def _generate_secret_key(self) -> str:
        """Generate a new TOTP secret key"""
        return pyotp.random_base32()
    
    def _generate_recovery_codes(self) -> list:
        """Generate recovery codes for 2FA"""
        codes = []
        for _ in range(RECOVERY_CODE_COUNT):
            code = secrets.token_hex(RECOVERY_CODE_LENGTH // 2).upper()
            codes.append(code)
        return codes
    
    def _hash_recovery_code(self, code: str) -> str:
        """Create a secure hash of recovery code"""
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()
    
    def _can_attempt_2fa(self, user_id: int) -> Tuple[bool, str]:
        """
        Check if 2FA can be attempted (rate limiting)
        
        Args:
            user_id: User ID
        
        Returns:
            Tuple of (can_attempt, reason)
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check recent failed attempts (last 15 minutes)
            fifteen_minutes_ago = datetime.now() - timedelta(minutes=15)
            cursor.execute('''
                SELECT COUNT(*) FROM two_factor_attempts 
                WHERE user_id = ? AND attempt_time > ? AND successful = FALSE
            ''', (user_id, fifteen_minutes_ago))
            
            failed_attempts = cursor.fetchone()[0]
            
            conn.close()
            
            # Rate limits
            if failed_attempts >= 5:
                return False, "Too many failed attempts. Please try again in 15 minutes."
            if failed_attempts >= 3:
                return False, "Multiple failed attempts. Please wait before trying again."
            
            return True, "2FA can be attempted"
            
        except sqlite3.Error:
            return False, "Internal error checking 2FA limits"
    
    def _record_2fa_attempt(self, user_id: int, successful: bool, 
                          ip_address: str = None, user_agent: str = None):
        """Record a 2FA verification attempt"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO two_factor_attempts 
                (user_id, successful, ip_address, user_agent)
                VALUES (?, ?, ?, ?)
            ''', (user_id, successful, ip_address, user_agent))
            
            conn.commit()
            conn.close()
            
        except sqlite3.Error:
            pass  # Silent fail for logging errors
    
    def setup_2fa(self, user_id: int, email: str, username: str) -> Dict:
        """
        Set up 2FA for a user
        
        Args:
            user_id: User ID
            email: User email (for QR code label)
            username: Username (for QR code label)
        
        Returns:
            2FA setup details including QR code
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Check if 2FA already enabled
            cursor.execute('SELECT id FROM two_factor_secrets WHERE user_id = ?', (user_id,))
            if cursor.fetchone():
                conn.close()
                raise TwoFactorError("2FA is already enabled for this account")
            
            # Generate secret key
            secret_key = self._generate_secret_key()
            
            # Generate recovery codes
            recovery_codes = self._generate_recovery_codes()
            recovery_codes_hashed = [self._hash_recovery_code(code) for code in recovery_codes]
            
            # Store in database (not enabled yet)
            cursor.execute('''
                INSERT INTO two_factor_secrets (user_id, secret_key, backup_codes)
                VALUES (?, ?, ?)
            ''', (user_id, secret_key, str(recovery_codes_hashed)))
            
            conn.commit()
            conn.close()
            
            # Generate TOTP URI for QR code
            totp = pyotp.TOTP(secret_key)
            issuer = "Trading Platform"
            account_name = f"{username} ({email})"
            
            provisioning_uri = totp.provisioning_uri(
                name=account_name,
                issuer_name=issuer
            )
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(provisioning_uri)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convert QR code to base64 for API response
            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
            
            return {
                'success': True,
                'message': '2FA setup initialized',
                'secret_key': secret_key,  # For manual entry
                'provisioning_uri': provisioning_uri,
                'qr_code': f"data:image/png;base64,{qr_code_base64}",
                'recovery_codes': recovery_codes,  # Show only once!
                'setup_complete': False,
                'instructions': 'Scan QR code with authenticator app and verify with code'
            }
            
        except sqlite3.Error as e:
            raise TwoFactorError(f"Database error: {str(e)}")
    
    def verify_2fa_setup(self, user_id: int, verification_code: str) -> Dict:
        """
        Verify 2FA setup by checking a code
        
        Args:
            user_id: User ID
            verification_code: Code from authenticator app
        
        Returns:
            Verification result
        """
        # Check rate limits
        can_attempt, reason = self._can_attempt_2fa(user_id)
        if not can_attempt:
            self._record_2fa_attempt(user_id, False)
            raise TwoFactorError(reason)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get secret key
            cursor.execute('''
                SELECT secret_key, backup_codes FROM two_factor_secrets 
                WHERE user_id = ? AND enabled_at IS NULL
            ''', (user_id,))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                self._record_2fa_attempt(user_id, False)
                raise TwoFactorError("No pending 2FA setup found")
            
            secret_key, backup_codes = result
            
            # Verify code
            totp = pyotp.TOTP(secret_key)
            is_valid = totp.verify(verification_code)
            
            if not is_valid:
                # Check if it's a recovery code
                if backup_codes:
                    backup_codes_list = eval(backup_codes)  # Should be stored as JSON string
                    code_hash = self._hash_recovery_code(verification_code)
                    
                    if code_hash in backup_codes_list:
                        is_valid = True
                        # Remove used recovery code
                        backup_codes_list.remove(code_hash)
                        cursor.execute('''
                            UPDATE two_factor_secrets 
                            SET backup_codes = ?
                            WHERE user_id = ?
                        ''', (str(backup_codes_list), user_id))
            
            if is_valid:
                # Enable 2FA
                cursor.execute('''
                    UPDATE two_factor_secrets 
                    SET enabled_at = ?, last_used = ?
                    WHERE user_id = ?
                ''', (datetime.now(), datetime.now(), user_id))
                
                # Update user's 2FA status
                cursor.execute('''
                    UPDATE users 
                    SET two_factor_enabled = TRUE 
                    WHERE id = ?
                ''', (user_id,))
                
                # Record successful attempt
                self._record_2fa_attempt(user_id, True)
                
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'message': '2FA enabled successfully',
                    'enabled_at': datetime.now().isoformat()
                }
            else:
                self._record_2fa_attempt(user_id, False)
                conn.close()
                raise TwoFactorError("Invalid verification code")
            
        except sqlite3.Error as e:
            self._record_2fa_attempt(user_id, False)
            raise TwoFactorError(f"Database error: {str(e)}")
    
    def verify_2fa_login(self, user_id: int, verification_code: str, 
                        device_id: str = None, ip_address: str = None,
                        user_agent: str = None) -> Dict:
        """
        Verify 2FA during login
        
        Args:
            user_id: User ID
            verification_code: Code from authenticator app
            device_id: Unique device identifier
            ip_address: Client IP
            user_agent: Client user agent
        
        Returns:
            Verification result with session token if trusted device
        """
        # Check rate limits
        can_attempt, reason = self._can_attempt_2fa(user_id)
        if not can_attempt:
            self._record_2fa_attempt(user_id, False, ip_address, user_agent)
            raise TwoFactorError(reason)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get secret key and check if 2FA is enabled
            cursor.execute('''
                SELECT ts.secret_key, ts.backup_codes, 
                       u.two_factor_enabled, td.id as trusted_device_id
                FROM two_factor_secrets ts
                JOIN users u ON ts.user_id = u.id
                LEFT JOIN trusted_devices td ON td.user_id = u.id 
                    AND td.device_id = ? AND td.is_trusted = TRUE
                WHERE u.id = ? AND u.status = 'active'
            ''', (device_id, user_id))
            
            result = cursor.fetchone()
            
            if not result:
                conn.close()
                self._record_2fa_attempt(user_id, False, ip_address, user_agent)
                raise TwoFactorError("2FA not configured for this account")
            
            secret_key, backup_codes, two_factor_enabled, trusted_device_id = result
            
            if not two_factor_enabled:
                conn.close()
                raise TwoFactorError("2FA is not enabled for this account")
            
            # Verify code
            totp = pyotp.TOTP(secret_key)
            is_valid = totp.verify(verification_code)
            
            if not is_valid:
                # Check if it's a recovery code
                if backup_codes:
                    backup_codes_list = eval(backup_codes)
                    code_hash = self._hash_recovery_code(verification_code)
                    
                    if code_hash in backup_codes_list:
                        is_valid = True
                        # Remove used recovery code
                        backup_codes_list.remove(code_hash)
                        cursor.execute('''
                            UPDATE two_factor_secrets 
                            SET backup_codes = ?
                            WHERE user_id = ?
                        ''', (str(backup_codes_list), user_id))
            
            if is_valid:
                # Update last used timestamp
                cursor.execute('''
                    UPDATE two_factor_secrets 
                    SET last_used = ?
                    WHERE user_id = ?
                ''', (datetime.now(), user_id))
                
                # Record successful attempt
                self._record_2fa_attempt(user_id, True, ip_address, user_agent)
                
                # If device is not trusted and user wants to trust it
                trust_device = False
                session_token = None
                
                if device_id and not trusted_device_id:
                    # In production, you might ask user if they want to trust device
                    # For now, we'll auto-trust after successful 2FA
                    cursor.execute('''
                        INSERT OR REPLACE INTO trusted_devices 
                        (user_id, device_id, device_name, user_agent, ip_address, last_used)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (user_id, device_id, 'Unknown Device', user_agent, ip_address, datetime.now()))
                    
                    trust_device = True
                
                conn.commit()
                conn.close()
                
                # Generate session token for trusted device
                if trust_device or trusted_device_id:
                    from .session_manager import session_manager
                    session = session_manager.create_session(
                        user_id, ip_address, user_agent
                    )
                    session_token = session['session_token']
                
                return {
                    'success': True,
                    'message': '2FA verification successful',
                    'trusted_device': trust_device or bool(trusted_device_id),
                    'session_token': session_token,
                    'requires_password_on_untrusted': not (trust_device or trusted_device_id)
                }
            else:
                self._record_2fa_attempt(user_id, False, ip_address, user_agent)
                conn.close()
                raise TwoFactorError("Invalid verification code")
            
        except sqlite3.Error as e:
            self._record_2fa_attempt(user_id, False, ip_address, user_agent)
            raise TwoFactorError(f"Database error: {str(e)}")
    
    def disable_2fa(self, user_id: int, verification_code: str = None, 
                   password: str = None) -> Dict:
        """
        Disable 2FA for a user
        
        Args:
            user_id: User ID
            verification_code: Current 2FA code or recovery code
            password: User password for additional verification
        
        Returns:
            Disable operation result
        """
        # Additional verification required
        if not verification_code and not password:
            raise TwoFactorError("Verification code or password required to disable 2FA")
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get user info for password verification
            if password:
                cursor.execute('''
                    SELECT password_hash FROM users WHERE id = ?
                ''', (user_id,))
                
                user_data = cursor.fetchone()
                if not user_data:
                    conn.close()
                    raise TwoFactorError("User not found")
                
                # Verify password
                from .authentication import UserManager
                user_manager = UserManager()
                if not user_manager._verify_password(password, user_data[0]):
                    conn.close()
                    raise TwoFactorError("Invalid password")
            
            # If verification code provided, verify it
            if verification_code:
                cursor.execute('''
                    SELECT secret_key, backup_codes FROM two_factor_secrets 
                    WHERE user_id = ?
                ''', (user_id,))
                
                result = cursor.fetchone()
                if not result:
                    conn.close()
                    raise TwoFactorError("2FA not configured for this account")
                
                secret_key, backup_codes = result
                
                totp = pyotp.TOTP(secret_key)
                is_valid = totp.verify(verification_code)
                
                if not is_valid and backup_codes:
                    # Check recovery codes
                    backup_codes_list = eval(backup_codes)
                    code_hash = self._hash_recovery_code(verification_code)
                    is_valid = code_hash in backup_codes_list
            
            # If we have either password verification or code verification
            if password or (verification_code and is_valid):
                # Remove 2FA secret
                cursor.execute('DELETE FROM two_factor_secrets WHERE user_id = ?', (user_id,))
                
                # Remove trusted devices
                cursor.execute('DELETE FROM trusted_devices WHERE user_id = ?', (user_id,))
                
                # Update user status
                cursor.execute('''
                    UPDATE users 
                    SET two_factor_enabled = FALSE 
                    WHERE id = ?
                ''', (user_id,))
                
                # Invalidate all sessions (security measure)
                from .session_manager import session_manager
                session_manager.invalidate_all_user_sessions(
                    user_id, 
                    reason="2fa_disabled"
                )
                
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'message': '2FA disabled successfully',
                    'disabled_at': datetime.now().isoformat()
                }
            else:
                conn.close()
                raise TwoFactorError("Invalid verification code")
            
        except sqlite3.Error as e:
            raise TwoFactorError(f"Database error: {str(e)}")
    
    def get_recovery_codes(self, user_id: int, verification_code: str) -> Dict:
        """
        Get new recovery codes (requires current 2FA code)
        
        Args:
            user_id: User ID
            verification_code: Current 2FA code
        
        Returns:
            New recovery codes
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get secret key and verify current code
            cursor.execute('SELECT secret_key FROM two_factor_secrets WHERE user_id = ?', (user_id,))
            
            result = cursor.fetchone()
            if not result:
                conn.close()
                raise TwoFactorError("2FA not configured for this account")
            
            secret_key = result[0]
            totp = pyotp.TOTP(secret_key)
            
            if not totp.verify(verification_code):
                conn.close()
                raise TwoFactorError("Invalid verification code")
            
            # Generate new recovery codes
            recovery_codes = self._generate_recovery_codes()
            recovery_codes_hashed = [self._hash_recovery_code(code) for code in recovery_codes]
            
            # Update backup codes
            cursor.execute('''
                UPDATE two_factor_secrets 
                SET backup_codes = ?
                WHERE user_id = ?
            ''', (str(recovery_codes_hashed), user_id))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'message': 'New recovery codes generated',
                'recovery_codes': recovery_codes,
                'generated_at': datetime.now().isoformat(),
                'warning': 'Save these codes securely. They will not be shown again.'
            }
            
        except sqlite3.Error as e:
            raise TwoFactorError(f"Database error: {str(e)}")
    
    def get_2fa_status(self, user_id: int) -> Dict:
        """Get 2FA status for a user"""
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT ts.enabled_at, ts.last_used,
                       u.two_factor_enabled,
                       (SELECT COUNT(*) FROM trusted_devices WHERE user_id = ?) as trusted_devices_count
                FROM users u
                LEFT JOIN two_factor_secrets ts ON u.id = ts.user_id
                WHERE u.id = ?
            ''', (user_id, user_id))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return {'enabled': False}
            
            enabled_at, last_used, two_factor_enabled, trusted_devices_count = result
            
            status = {
                'enabled': bool(two_factor_enabled),
                'enabled_at': enabled_at,
                'last_used': last_used,
                'trusted_devices_count': trusted_devices_count or 0
            }
            
            return status
            
        except sqlite3.Error:
            return {'enabled': False}

# Singleton instance
two_factor_manager = TwoFactorManager()

# Flask Blueprint for 2FA endpoints
def create_two_factor_blueprint():
    """Create Flask Blueprint for 2FA operations"""
    from flask import Blueprint, request, jsonify
    
    twofa_bp = Blueprint('two_factor', __name__, url_prefix='/api/2fa')
    
    @twofa_bp.route('/setup', methods=['POST'])
    def setup_2fa():
        """Start 2FA setup process"""
        try:
            # Requires authentication
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            # In production, decode JWT to get user_id
            data = request.get_json()
            user_id = data.get('user_id')
            email = data.get('email')
            username = data.get('username')
            
            if not all([user_id, email, username]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            result = two_factor_manager.setup_2fa(user_id, email, username)
            return jsonify(result), 200
            
        except TwoFactorError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @twofa_bp.route('/verify-setup', methods=['POST'])
    def verify_setup():
        """Verify 2FA setup with code"""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            verification_code = data.get('code', '').strip()
            
            if not all([user_id, verification_code]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            result = two_factor_manager.verify_2fa_setup(user_id, verification_code)
            return jsonify(result), 200
            
        except TwoFactorError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @twofa_bp.route('/verify-login', methods=['POST'])
    def verify_login():
        """Verify 2FA during login"""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            verification_code = data.get('code', '').strip()
            device_id = data.get('device_id')
            
            if not all([user_id, verification_code]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            ip_address = request.remote_addr
            user_agent = request.headers.get('User-Agent')
            
            result = two_factor_manager.verify_2fa_login(
                user_id, verification_code, device_id, ip_address, user_agent
            )
            
            return jsonify(result), 200
            
        except TwoFactorError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @twofa_bp.route('/disable', methods=['POST'])
    def disable_2fa():
        """Disable 2FA"""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            verification_code = data.get('code')
            password = data.get('password')
            
            if not user_id or (not verification_code and not password):
                return jsonify({'error': 'Missing required fields'}), 400
            
            result = two_factor_manager.disable_2fa(user_id, verification_code, password)
            return jsonify(result), 200
            
        except TwoFactorError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @twofa_bp.route('/recovery-codes', methods=['POST'])
    def get_new_recovery_codes():
        """Generate new recovery codes"""
        try:
            data = request.get_json()
            user_id = data.get('user_id')
            verification_code = data.get('code', '').strip()
            
            if not all([user_id, verification_code]):
                return jsonify({'error': 'Missing required fields'}), 400
            
            result = two_factor_manager.get_recovery_codes(user_id, verification_code)
            return jsonify(result), 200
            
        except TwoFactorError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @twofa_bp.route('/status/<int:user_id>', methods=['GET'])
    def get_status(user_id):
        """Get 2FA status"""
        try:
            # Requires authentication
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            status = two_factor_manager.get_2fa_status(user_id)
            return jsonify(status), 200
            
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    return twofa_bp

if __name__ == '__main__':
    # Test the 2FA system
    print("Testing Two-Factor Authentication System...")
    
    manager = TwoFactorManager()
    
    try:
        # Test setup (would need real user_id)
        print("2FA Manager initialized successfully")
        
        # Get status for non-existent user
        status = manager.get_2fa_status(999)
        print(f"2FA status for non-existent user: {status}")
        
        # Note: Full testing requires database with actual users
        print("\n2FA system test completed (full test requires database setup)")
        
    except Exception as e:
        print(f"Test error: {e}")
