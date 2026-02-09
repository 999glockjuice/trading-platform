"""
Email Verification Module for Trading Platform
Handles email verification for user accounts
"""

import sqlite3
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple
import os
import threading

# Database configuration
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                       'data', 'databases', 'users.db')

# Email configuration (configure in production)
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
EMAIL_SENDER = os.environ.get('EMAIL_SENDER', 'noreply@tradingplatform.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
EMAIL_USE_TLS = os.environ.get('EMAIL_USE_TLS', 'True').lower() == 'true'

# Verification token expiry (24 hours)
VERIFICATION_TOKEN_EXPIRE_HOURS = 24

class EmailVerificationError(Exception):
    """Custom exception for email verification errors"""
    pass

class EmailVerificationManager:
    """Manages email verification process"""
    
    def __init__(self):
        self._init_verification_tables()
    
    def _init_verification_tables(self):
        """Initialize verification tables if not exists"""
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Email verification requests table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                email TEXT NOT NULL,
                verification_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                verified_at TIMESTAMP,
                is_used BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        
        # Create index for faster lookups
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_verification_token 
            ON email_verifications(verification_token)
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_verification_user 
            ON email_verifications(user_id)
        ''')
        
        conn.commit()
        conn.close()
    
    def generate_verification_token(self) -> str:
        """Generate a secure verification token"""
        return secrets.token_urlsafe(32)
    
    def _send_verification_email(self, to_email: str, token: str, username: str):
        """
        Send verification email to user
        
        Args:
            to_email: Recipient email
            token: Verification token
            username: User's username
        """
        # In production, implement actual email sending
        # For development, we'll just log it
        
        verification_url = f"https://yourplatform.com/verify-email?token={token}"
        
        # HTML email template
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Verify Your Email - Trading Platform</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header {{
                    background-color: #1a237e;
                    color: white;
                    padding: 20px;
                    text-align: center;
                }}
                .content {{
                    background-color: #f9f9f9;
                    padding: 30px;
                    border-radius: 5px;
                    margin-top: 20px;
                }}
                .button {{
                    display: inline-block;
                    background-color: #1a237e;
                    color: white;
                    padding: 12px 24px;
                    text-decoration: none;
                    border-radius: 4px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .footer {{
                    margin-top: 30px;
                    padding-top: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 12px;
                    color: #777;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>Trading Platform</h1>
                </div>
                <div class="content">
                    <h2>Verify Your Email Address</h2>
                    <p>Hello {username},</p>
                    <p>Thank you for registering with Trading Platform. To complete your registration and start trading, please verify your email address by clicking the button below:</p>
                    
                    <a href="{verification_url}" class="button">Verify Email Address</a>
                    
                    <p>If the button doesn't work, you can also copy and paste this link into your browser:</p>
                    <p><code>{verification_url}</code></p>
                    
                    <p>This verification link will expire in 24 hours.</p>
                    
                    <p>If you didn't create an account with Trading Platform, please ignore this email.</p>
                    
                    <p>Best regards,<br>The Trading Platform Team</p>
                </div>
                <div class="footer">
                    <p>© 2024 Trading Platform. All rights reserved.</p>
                    <p>This is an automated message, please do not reply to this email.</p>
                    <p>For assistance, please contact our support team.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Plain text version
        text_content = f"""
        Verify Your Email Address
        
        Hello {username},
        
        Thank you for registering with Trading Platform. To complete your registration and start trading, please verify your email address by clicking the link below:
        
        {verification_url}
        
        This verification link will expire in 24 hours.
        
        If you didn't create an account with Trading Platform, please ignore this email.
        
        Best regards,
        The Trading Platform Team
        """
        
        # In development, log the email instead of sending
        if os.environ.get('ENVIRONMENT') == 'development':
            print(f"\n{'='*60}")
            print("📧 DEVELOPMENT EMAIL (Not actually sent)")
            print(f"To: {to_email}")
            print(f"Subject: Verify Your Email - Trading Platform")
            print(f"Verification Token: {token}")
            print(f"Verification URL: {verification_url}")
            print(f"{'='*60}\n")
            
            # Also save to file for testing
            email_log_path = os.path.join(os.path.dirname(DB_PATH), '..', 'logs', 'email_log.txt')
            os.makedirs(os.path.dirname(email_log_path), exist_ok=True)
            
            with open(email_log_path, 'a') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Time: {datetime.now()}\n")
                f.write(f"To: {to_email}\n")
                f.write(f"Token: {token}\n")
                f.write(f"URL: {verification_url}\n")
                f.write(f"{'='*60}\n")
            
            return True
        
        # Production email sending (commented out for now)
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Verify Your Email - Trading Platform'
            msg['From'] = EMAIL_SENDER
            msg['To'] = to_email
            
            # Attach both HTML and plain text versions
            part1 = MIMEText(text_content, 'plain')
            part2 = MIMEText(html_content, 'html')
            
            msg.attach(part1)
            msg.attach(part2)
            
            # Send email
            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                if EMAIL_USE_TLS:
                    server.starttls()
                if EMAIL_PASSWORD:
                    server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            # In production, you might want to queue this for retry
            return False
    
    def create_verification_request(self, user_id: int, email: str, username: str) -> Dict:
        """
        Create a new email verification request
        
        Args:
            user_id: User ID
            email: User email to verify
            username: User's username for personalization
        
        Returns:
            Verification request details
        """
        # Generate verification token
        token = self.generate_verification_token()
        
        # Calculate expiry time
        expires_at = datetime.now() + timedelta(hours=VERIFICATION_TOKEN_EXPIRE_HOURS)
        
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Deactivate any existing verification requests for this user
            cursor.execute('''
                UPDATE email_verifications 
                SET is_used = TRUE 
                WHERE user_id = ? AND is_used = FALSE
            ''', (user_id,))
            
            # Create new verification request
            cursor.execute('''
                INSERT INTO email_verifications 
                (user_id, email, verification_token, expires_at)
                VALUES (?, ?, ?, ?)
            ''', (user_id, email, token, expires_at))
            
            conn.commit()
            conn.close()
            
            # Send verification email (in background thread)
            thread = threading.Thread(
                target=self._send_verification_email,
                args=(email, token, username)
            )
            thread.daemon = True
            thread.start()
            
            return {
                'verification_token': token,
                'expires_at': expires_at.isoformat(),
                'email_sent': True,
                'message': 'Verification email sent'
            }
            
        except sqlite3.Error as e:
            raise EmailVerificationError(f"Database error: {str(e)}")
    
    def verify_email(self, token: str) -> Tuple[bool, Dict]:
        """
        Verify email using token
        
        Args:
            token: Verification token
        
        Returns:
            Tuple of (success, verification details)
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Find verification request
            cursor.execute('''
                SELECT id, user_id, email, expires_at, verified_at, is_used
                FROM email_verifications 
                WHERE verification_token = ? AND is_used = FALSE
            ''', (token,))
            
            verification = cursor.fetchone()
            
            if not verification:
                conn.close()
                return False, {'error': 'Invalid or expired verification token'}
            
            verification_id, user_id, email, expires_at, verified_at, is_used = verification
            
            # Check if token is expired
            if datetime.now() > datetime.fromisoformat(expires_at):
                conn.close()
                return False, {'error': 'Verification token has expired'}
            
            # Check if already verified
            if verified_at:
                conn.close()
                return False, {'error': 'Email already verified'}
            
            # Mark as verified
            cursor.execute('''
                UPDATE email_verifications 
                SET verified_at = ?, is_used = TRUE 
                WHERE id = ?
            ''', (datetime.now(), verification_id))
            
            # Update user's email verification status
            cursor.execute('''
                UPDATE users 
                SET is_email_verified = TRUE 
                WHERE id = ? AND email = ?
            ''', (user_id, email))
            
            # Get user info
            cursor.execute('''
                SELECT username, account_type FROM users WHERE id = ?
            ''', (user_id,))
            
            user_data = cursor.fetchone()
            username = user_data[0] if user_data else ''
            account_type = user_data[1] if user_data else ''
            
            conn.commit()
            conn.close()
            
            return True, {
                'success': True,
                'message': 'Email verified successfully',
                'user_id': user_id,
                'email': email,
                'username': username,
                'account_type': account_type,
                'verified_at': datetime.now().isoformat()
            }
            
        except sqlite3.Error as e:
            return False, {'error': f'Database error: {str(e)}'}
        except Exception as e:
            return False, {'error': f'Unexpected error: {str(e)}'}
    
    def resend_verification_email(self, user_id: int) -> Dict:
        """
        Resend verification email
        
        Args:
            user_id: User ID
        
        Returns:
            Resend operation details
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get user info
            cursor.execute('''
                SELECT email, username, is_email_verified 
                FROM users WHERE id = ? AND status = 'active'
            ''', (user_id,))
            
            user_data = cursor.fetchone()
            
            if not user_data:
                conn.close()
                raise EmailVerificationError("User not found")
            
            email, username, is_verified = user_data
            
            if is_verified:
                conn.close()
                raise EmailVerificationError("Email already verified")
            
            conn.close()
            
            # Create new verification request
            return self.create_verification_request(user_id, email, username)
            
        except sqlite3.Error as e:
            raise EmailVerificationError(f"Database error: {str(e)}")
    
    def get_verification_status(self, user_id: int) -> Dict:
        """
        Get email verification status for user
        
        Args:
            user_id: User ID
        
        Returns:
            Verification status
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Get user verification status
            cursor.execute('''
                SELECT email, is_email_verified, 
                       (SELECT COUNT(*) FROM email_verifications 
                        WHERE user_id = ? AND is_used = FALSE AND expires_at > ?) as pending_requests
                FROM users WHERE id = ?
            ''', (user_id, datetime.now(), user_id))
            
            user_data = cursor.fetchone()
            
            if not user_data:
                conn.close()
                return {'error': 'User not found'}
            
            email, is_verified, pending_requests = user_data
            
            # Get latest verification request if any
            cursor.execute('''
                SELECT verification_token, created_at, expires_at 
                FROM email_verifications 
                WHERE user_id = ? AND is_used = FALSE AND expires_at > ?
                ORDER BY created_at DESC LIMIT 1
            ''', (user_id, datetime.now()))
            
            latest_request = cursor.fetchone()
            
            conn.close()
            
            result = {
                'email': email,
                'is_verified': bool(is_verified),
                'pending_requests': pending_requests
            }
            
            if latest_request:
                token, created_at, expires_at = latest_request
                result['latest_request'] = {
                    'token': token,
                    'created_at': created_at,
                    'expires_at': expires_at
                }
            
            return result
            
        except sqlite3.Error as e:
            return {'error': f'Database error: {str(e)}'}
    
    def cleanup_expired_verifications(self) -> int:
        """
        Clean up expired verification requests
        
        Returns:
            Number of records cleaned
        """
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Mark expired verifications as used
            cursor.execute('''
                UPDATE email_verifications 
                SET is_used = TRUE 
                WHERE expires_at <= ? AND is_used = FALSE
            ''', (datetime.now(),))
            
            cleaned_count = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return cleaned_count
            
        except sqlite3.Error:
            return 0

# Singleton instance
email_verification_manager = EmailVerificationManager()

# Flask Blueprint for email verification endpoints
def create_email_verification_blueprint():
    """Create Flask Blueprint for email verification"""
    from flask import Blueprint, request, jsonify
    
    email_bp = Blueprint('email_verification', __name__, url_prefix='/api/email')
    
    @email_bp.route('/verify', methods=['POST'])
    def verify_email():
        """Verify email using token"""
        try:
            data = request.get_json()
            token = data.get('token', '').strip()
            
            if not token:
                return jsonify({'error': 'Verification token required'}), 400
            
            success, result = email_verification_manager.verify_email(token)
            
            if success:
                return jsonify(result), 200
            else:
                return jsonify(result), 400
            
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @email_bp.route('/resend', methods=['POST'])
    def resend_verification():
        """Resend verification email"""
        try:
            # This endpoint requires authentication
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            # In production, decode JWT to get user_id
            # For now, accept user_id in request (protected by authentication)
            data = request.get_json()
            user_id = data.get('user_id')
            
            if not user_id:
                return jsonify({'error': 'User ID required'}), 400
            
            result = email_verification_manager.resend_verification_email(user_id)
            return jsonify(result), 200
            
        except EmailVerificationError as e:
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    @email_bp.route('/status/<int:user_id>', methods=['GET'])
    def get_verification_status(user_id):
        """Get email verification status"""
        try:
            # This endpoint requires authentication
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            status = email_verification_manager.get_verification_status(user_id)
            
            if 'error' in status:
                return jsonify(status), 404
            
            return jsonify(status), 200
            
        except Exception as e:
            return jsonify({'error': 'Internal server error'}), 500
    
    return email_bp

if __name__ == '__main__':
    # Test the email verification system
    print("Testing Email Verification System...")
    
    manager = EmailVerificationManager()
    
    # Create a test verification request
    try:
        result = manager.create_verification_request(
            user_id=1,
            email="test@example.com",
            username="testuser"
        )
        
        print("Verification request created:")
        print(f"Token: {result['verification_token'][:50]}...")
        print(f"Expires at: {result['expires_at']}")
        print(f"Email sent: {result['email_sent']}")
        
        # Test verification (this would fail with a fake token)
        success, verify_result = manager.verify_email("fake_token")
        print(f"\nVerification test (with fake token): {'Failed as expected' if not success else 'UNEXPECTED SUCCESS'}")
        
        # Get verification status
        status = manager.get_verification_status(1)
        print(f"\nVerification status: {status}")
        
        # Cleanup
        cleaned = manager.cleanup_expired_verifications()
        print(f"\nCleaned up {cleaned} expired verification requests")
        
    except EmailVerificationError as e:
        print(f"Test failed: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    print("\nEmail verification test completed")
