"""
Main Flask Application for Trading Platform
Serves as the entry point for the entire platform
"""

import os
import sys
from datetime import datetime
from flask import Flask, send_from_directory, jsonify, render_template_string

# Add project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

def create_app():
    """Create and configure the Flask application"""
    
    # Initialize Flask app
    app = Flask(
        __name__,
        static_folder=os.path.join('..', '..', 'frontend'),
        static_url_path='',
        template_folder=os.path.join('..', '..', 'frontend', 'pages')
    )
    
    # Configuration
    app.config.update(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'trading-platform-secret-key-2024'),
        DEBUG=True if os.environ.get('ENVIRONMENT') == 'development' else False,
        PORT=int(os.environ.get('PORT', 5000)),
        HOST=os.environ.get('HOST', '0.0.0.0'),
        MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            'DATABASE_URL', 
            f'sqlite:///{os.path.join(os.path.dirname(__file__), "..", "..", "data", "databases", "users.db")}'
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False
    )
    
    # Initialize authentication system
    from backend.auth import init_auth_systems
    init_auth_systems(app)
    
    # ============ STATIC FILE SERVING ============
    
    @app.route('/')
    def serve_index():
        """Serve the main dashboard or login page"""
        return send_from_directory(app.template_folder, 'login.html')
    
    @app.route('/login')
    def serve_login():
        """Serve login page"""
        return send_from_directory(app.template_folder, 'login.html')
    
    @app.route('/register')
    def serve_register():
        """Serve registration page"""
        return send_from_directory(app.template_folder, 'register.html')
    
    @app.route('/dashboard')
    def serve_dashboard():
        """Serve dashboard page"""
        # For now, redirect to login - will add auth later
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Dashboard - Coming Soon</title>
            <meta http-equiv="refresh" content="3;url=/login">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                    background: linear-gradient(135deg, #1a237e 0%, #000051 100%);
                    color: white;
                }
                .message {
                    text-align: center;
                    padding: 40px;
                    background: rgba(255, 255, 255, 0.1);
                    border-radius: 12px;
                    backdrop-filter: blur(10px);
                }
                .spinner {
                    border: 4px solid rgba(255, 255, 255, 0.3);
                    border-radius: 50%;
                    border-top: 4px solid white;
                    width: 40px;
                    height: 40px;
                    animation: spin 1s linear infinite;
                    margin: 20px auto;
                }
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
            </style>
        </head>
        <body>
            <div class="message">
                <h1>Trading Platform Dashboard</h1>
                <p>Dashboard is under development. Redirecting to login...</p>
                <div class="spinner"></div>
                <p><a href="/login" style="color: #00acc1;">Click here if not redirected</a></p>
            </div>
        </body>
        </html>
        '''
    
    @app.route('/<path:filename>')
    def serve_static_files(filename):
        """Serve static files (CSS, JS, images)"""
        # Check if file exists in static folder
        static_folder = app.static_folder
        file_path = os.path.join(static_folder, filename)
        
        if os.path.exists(file_path):
            return send_from_directory(static_folder, filename)
        else:
            # Check in pages folder
            pages_folder = os.path.join(static_folder, 'pages')
            pages_path = os.path.join(pages_folder, filename)
            
            if os.path.exists(pages_path):
                return send_from_directory(pages_folder, filename)
            else:
                # Check in components
                components_folder = os.path.join(static_folder, 'components')
                components_path = os.path.join(components_folder, filename)
                
                if os.path.exists(components_path):
                    return send_from_directory(components_folder, filename)
        
        # File not found
        return jsonify({'error': 'File not found'}), 404
    
    # ============ API ENDPOINTS ============
    
    @app.route('/api/status')
    def api_status():
        """API status endpoint"""
        return jsonify({
            'status': 'operational',
            'service': 'trading-platform',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'environment': os.environ.get('ENVIRONMENT', 'development'),
            'features': {
                'authentication': True,
                'user_registration': True,
                'two_factor_auth': True,
                'email_verification': True,
                'password_reset': True,
                'trading_engine': 'coming_soon',
                'real_time_data': 'coming_soon',
                'payment_processing': 'coming_soon'
            }
        })
    
    @app.route('/api/platform/info')
    def platform_info():
        """Platform information"""
        return jsonify({
            'platform': {
                'name': 'Trading Platform',
                'description': 'Professional multi-asset trading platform',
                'version': '1.0.0-alpha',
                'license': 'Proprietary',
                'website': 'https://tradingplatform.example.com',
                'support_email': 'support@tradingplatform.example.com'
            },
            'capabilities': {
                'account_types': ['demo', 'live'],
                'demo_balance': 500000.00,
                'live_starting_balance': 20.00,
                'minimum_withdrawal': 50.00,
                'asset_classes': ['stocks', 'cryptocurrency', 'forex', 'commodities'],
                'security_features': ['2fa', 'email_verification', 'encrypted_storage', 'jwt_tokens']
            },
            'requirements': {
                'minimum_age': 18,
                'kyc_required': True,
                'identity_verification': True
            }
        })
    
    @app.route('/api/user/me', methods=['GET'])
    def get_current_user():
        """Get current user info (protected endpoint example)"""
        # This is a placeholder - will be implemented with proper auth middleware
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        # In production, verify JWT token here
        return jsonify({
            'message': 'User endpoint - Authentication will be implemented',
            'note': 'This endpoint requires valid JWT token'
        })
    
    # ============ ERROR HANDLERS ============
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 errors"""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'API endpoint not found'}), 404
        else:
            # Serve custom 404 page for frontend
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Page Not Found - Trading Platform</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #1a237e 0%, #000051 100%);
                        color: white;
                    }
                    .error-container {
                        text-align: center;
                        padding: 40px;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 12px;
                        backdrop-filter: blur(10px);
                    }
                    .error-code {
                        font-size: 72px;
                        font-weight: bold;
                        color: #ff9800;
                    }
                    .home-link {
                        display: inline-block;
                        margin-top: 20px;
                        padding: 10px 20px;
                        background: #00acc1;
                        color: white;
                        text-decoration: none;
                        border-radius: 6px;
                        transition: background 0.3s;
                    }
                    .home-link:hover {
                        background: #0097a7;
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-code">404</div>
                    <h1>Page Not Found</h1>
                    <p>The page you're looking for doesn't exist or has been moved.</p>
                    <a href="/" class="home-link">Go to Homepage</a>
                </div>
            </body>
            </html>
            ''', 404
    
    @app.errorhandler(500)
    def internal_error(error):
        """Handle 500 errors"""
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Internal server error'}), 500
        else:
            return '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Server Error - Trading Platform</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        height: 100vh;
                        margin: 0;
                        background: linear-gradient(135deg, #1a237e 0%, #000051 100%);
                        color: white;
                    }
                    .error-container {
                        text-align: center;
                        padding: 40px;
                        background: rgba(255, 255, 255, 0.1);
                        border-radius: 12px;
                        backdrop-filter: blur(10px);
                    }
                    .error-code {
                        font-size: 72px;
                        font-weight: bold;
                        color: #f44336;
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <div class="error-code">500</div>
                    <h1>Internal Server Error</h1>
                    <p>Something went wrong on our end. Please try again later.</p>
                    <p><a href="/" style="color: #00acc1;">Return to Homepage</a></p>
                </div>
            </body>
            </html>
            ''', 500
    
    # ============ STARTUP MESSAGE ============
    
    @app.before_first_request
    def startup_message():
        """Print startup message"""
        print("\n" + "="*60)
        print("🚀 TRADING PLATFORM - STARTING")
        print("="*60)
        print(f"📁 Project Root: {os.path.abspath('.')}")
        print(f"🌐 Server: http://{app.config['HOST']}:{app.config['PORT']}")
        print(f"🔧 Environment: {os.environ.get('ENVIRONMENT', 'development')}")
        print(f"⚡ Debug Mode: {app.config['DEBUG']}")
        print("\n📋 Available Routes:")
        print("  • GET  /                 → Login Page")
        print("  • GET  /login            → Login Page")
        print("  • GET  /register         → Registration Page")
        print("  • GET  /dashboard        → Dashboard (Coming Soon)")
        print("  • GET  /api/status       → Platform Status")
        print("  • GET  /api/platform/info → Platform Information")
        print("\n🔐 Authentication API:")
        print("  • POST /api/auth/register → Register new user")
        print("  • POST /api/auth/login    → User login")
        print("  • POST /api/auth/verify   → Verify JWT token")
        print("  • POST /api/auth/refresh  → Refresh access token")
        print("\n📧 Email & Security:")
        print("  • POST /api/email/verify  → Verify email")
        print("  • POST /api/password/reset/* → Password reset")
        print("  • POST /api/2fa/*         → Two-factor authentication")
        print("="*60)
        print("Press Ctrl+C to stop the server")
        print("="*60 + "\n")
    
    return app

# Application instance
app = create_app()

# Import request here to avoid circular imports
from flask import request

if __name__ == '__main__':
    # Run the application
    app.run(
        host=app.config['HOST'],
        port=app.config['PORT'],
        debug=app.config['DEBUG']
    )
