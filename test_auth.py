#!/usr/bin/env python3
"""
Test Script for Trading Platform Authentication System
Run this to verify all auth components work
"""

import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.auth import (
    user_manager,
    session_manager,
    email_verification_manager,
    password_reset_manager,
    two_factor_manager,
    init_auth_systems
)

from flask import Flask, jsonify

def test_database_initialization():
    """Test that all database tables are created"""
    print("=" * 60)
    print("TEST 1: Database Initialization")
    print("=" * 60)
    
    try:
        # Initialize all tables
        user_manager._init_database()
        session_manager._init_session_tables()
        email_verification_manager._init_verification_tables()
        password_reset_manager._init_reset_tables()
        two_factor_manager._init_2fa_tables()
        
        print("✅ All database tables initialized successfully")
        return True
    except Exception as e:
        print(f"❌ Database initialization failed: {e}")
        return False

def test_user_registration():
    """Test user registration"""
    print("\n" + "=" * 60)
    print("TEST 2: User Registration")
    print("=" * 60)
    
    try:
        # Test demo account registration
        demo_user = user_manager.register_user(
            email="demo@test.com",
            username="demotrader",
            password="Demo123!@#",
            account_type="demo"
        )
        
        print(f"✅ Demo user registered successfully:")
        print(f"   User ID: {demo_user['user']['id']}")
        print(f"   Email: {demo_user['user']['email']}")
        print(f"   Username: {demo_user['user']['username']}")
        print(f"   Account Type: {demo_user['user']['account_type']}")
        print(f"   Demo Balance: ${demo_user['user']['demo_balance']:,.2f}")
        print(f"   Live Balance: ${demo_user['user']['live_balance']:,.2f}")
        
        # Test live account registration
        live_user = user_manager.register_user(
            email="live@test.com",
            username="livetrader",
            password="Live123!@#",
            account_type="live"
        )
        
        print(f"\n✅ Live user registered successfully:")
        print(f"   User ID: {live_user['user']['id']}")
        print(f"   Account Type: {live_user['user']['account_type']}")
        print(f"   Demo Balance: ${live_user['user']['demo_balance']:,.2f}")
        print(f"   Live Balance: ${live_user['user']['live_balance']:,.2f}")
        
        return demo_user['user']['id'], live_user['user']['id']
        
    except Exception as e:
        print(f"❌ User registration failed: {e}")
        return None, None

def test_user_login(demo_user_id):
    """Test user login"""
    print("\n" + "=" * 60)
    print("TEST 3: User Login")
    print("=" * 60)
    
    try:
        # Test successful login
        login_result = user_manager.login_user("demo@test.com", "Demo123!@#")
        
        print(f"✅ Login successful:")
        print(f"   User ID: {login_result['user']['id']}")
        print(f"   Access Token: {login_result['tokens']['access_token'][:50]}...")
        print(f"   Token Type: {login_result['tokens']['token_type']}")
        print(f"   Expires in: {login_result['tokens']['expires_in']} seconds")
        
        # Test token verification
        token_data = user_manager.verify_token(login_result['tokens']['access_token'])
        
        print(f"\n✅ Token verification successful:")
        print(f"   Valid: {token_data['valid']}")
        print(f"   User Email: {token_data['user']['email']}")
        print(f"   Expires at: {token_data['expires']}")
        
        return login_result['tokens']['access_token']
        
    except Exception as e:
        print(f"❌ Login failed: {e}")
        return None

def test_password_operations(demo_user_id):
    """Test password-related operations"""
    print("\n" + "=" * 60)
    print("TEST 4: Password Operations")
    print("=" * 60)
    
    try:
        # Test password reset request
        reset_request = password_reset_manager.request_password_reset(
            email="demo@test.com",
            ip_address="192.168.1.100",
            user_agent="Test Browser"
        )
        
        print(f"✅ Password reset request created:")
        print(f"   Success: {reset_request.get('success', False)}")
        print(f"   Message: {reset_request.get('message', 'N/A')}")
        
        if 'token' in reset_request:
            print(f"   Token (dev): {reset_request['token'][:50]}...")
        
        # Test cleanup of expired resets
        cleaned = password_reset_manager.cleanup_expired_resets()
        print(f"\n✅ Cleaned up {cleaned} expired password reset requests")
        
        return True
        
    except Exception as e:
        print(f"❌ Password operations failed: {e}")
        return False

def test_email_verification(demo_user_id):
    """Test email verification system"""
    print("\n" + "=" * 60)
    print("TEST 5: Email Verification")
    print("=" * 60)
    
    try:
        # Create verification request
        verification = email_verification_manager.create_verification_request(
            user_id=demo_user_id,
            email="demo@test.com",
            username="demotrader"
        )
        
        print(f"✅ Email verification request created:")
        print(f"   Verification Token: {verification['verification_token'][:50]}...")
        print(f"   Email Sent: {verification.get('email_sent', False)}")
        print(f"   Expires at: {verification.get('expires_at', 'N/A')}")
        
        # Get verification status
        status = email_verification_manager.get_verification_status(demo_user_id)
        
        print(f"\n✅ Verification status retrieved:")
        print(f"   Email: {status.get('email', 'N/A')}")
        print(f"   Is Verified: {status.get('is_verified', False)}")
        print(f"   Pending Requests: {status.get('pending_requests', 0)}")
        
        # Cleanup expired verifications
        cleaned = email_verification_manager.cleanup_expired_verifications()
        print(f"\n✅ Cleaned up {cleaned} expired verification requests")
        
        return True
        
    except Exception as e:
        print(f"❌ Email verification test failed: {e}")
        return False

def test_session_management(demo_user_id):
    """Test session management"""
    print("\n" + "=" * 60)
    print("TEST 6: Session Management")
    print("=" * 60)
    
    try:
        # Create a session
        session = session_manager.create_session(
            user_id=demo_user_id,
            ip_address="192.168.1.100",
            user_agent="Test Browser"
        )
        
        print(f"✅ Session created:")
        print(f"   Session Token: {session['session_token'][:50]}...")
        print(f"   User ID: {session['user_id']}")
        print(f"   Expires at: {session['expires_at']}")
        
        # Validate the session
        validated = session_manager.validate_session(session['session_token'])
        
        print(f"\n✅ Session validated:")
        print(f"   Session ID: {validated['id']}")
        print(f"   User ID: {validated['user_id']}")
        print(f"   IP Address: {validated['ip_address']}")
        print(f"   Is Active: {validated['is_active']}")
        
        # Get active sessions
        active_sessions = session_manager.get_active_sessions(demo_user_id)
        
        print(f"\n✅ Active sessions retrieved:")
        print(f"   Count: {len(active_sessions)}")
        
        # Invalidate the session
        invalidated = session_manager.invalidate_session(session['session_token'], "test_completion")
        
        print(f"\n✅ Session invalidated: {invalidated}")
        
        # Cleanup expired sessions
        cleaned = session_manager.cleanup_expired_sessions()
        print(f"\n✅ Cleaned up {cleaned} expired sessions")
        
        return True
        
    except Exception as e:
        print(f"❌ Session management test failed: {e}")
        return False

def test_2fa_setup(demo_user_id):
    """Test 2FA setup"""
    print("\n" + "=" * 60)
    print("TEST 7: Two-Factor Authentication")
    print("=" * 60)
    
    try:
        # Setup 2FA
        setup_result = two_factor_manager.setup_2fa(
            user_id=demo_user_id,
            email="demo@test.com",
            username="demotrader"
        )
        
        print(f"✅ 2FA setup initialized:")
        print(f"   Success: {setup_result.get('success', False)}")
        print(f"   Secret Key: {setup_result.get('secret_key', 'N/A')[:30]}...")
        
        if 'qr_code' in setup_result:
            print(f"   QR Code: Generated (base64 image)")
        
        if 'recovery_codes' in setup_result:
            print(f"   Recovery Codes: {len(setup_result['recovery_codes'])} codes generated")
        
        # Get 2FA status
        status = two_factor_manager.get_2fa_status(demo_user_id)
        
        print(f"\n✅ 2FA status retrieved:")
        print(f"   Enabled: {status.get('enabled', False)}")
        print(f"   Trusted Devices: {status.get('trusted_devices_count', 0)}")
        
        return True
        
    except Exception as e:
        print(f"❌ 2FA test failed: {e}")
        return False

def test_flask_integration():
    """Test Flask integration"""
    print("\n" + "=" * 60)
    print("TEST 8: Flask Integration")
    print("=" * 60)
    
    try:
        # Create a minimal Flask app
        app = Flask(__name__)
        
        # Initialize auth systems
        init_auth_systems(app)
        
        # Add a test route
        @app.route('/test')
        def test_route():
            return jsonify({"status": "ok", "message": "Flask app is working"})
        
        print("✅ Flask app created and auth systems initialized")
        print("✅ Test route added: GET /test")
        print("\n📋 To run the Flask server:")
        print("   1. Install Flask: pip install Flask")
        print("   2. Run: python test_auth.py --run-server")
        print("   3. Open: http://localhost:5000/test")
        
        return app
        
    except Exception as e:
        print(f"❌ Flask integration failed: {e}")
        return None

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("TRADING PLATFORM - AUTHENTICATION SYSTEM TEST")
    print("=" * 60)
    
    results = {
        'database': False,
        'registration': False,
        'login': False,
        'password': False,
        'email': False,
        'session': False,
        '2fa': False,
        'flask': False
    }
    
    # Run tests
    results['database'] = test_database_initialization()
    
    demo_user_id, live_user_id = test_user_registration()
    results['registration'] = bool(demo_user_id and live_user_id)
    
    if demo_user_id:
        access_token = test_user_login(demo_user_id)
        results['login'] = bool(access_token)
        
        results['password'] = test_password_operations(demo_user_id)
        results['email'] = test_email_verification(demo_user_id)
        results['session'] = test_session_management(demo_user_id)
        results['2fa'] = test_2fa_setup(demo_user_id)
    
    app = test_flask_integration()
    results['flask'] = bool(app)
    
    # Print summary
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    for test_name, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name.upper():15} {status}")
    
    passed_count = sum(results.values())
    total_count = len(results)
    
    print(f"\nPassed: {passed_count}/{total_count} tests")
    
    if passed_count == total_count:
        print("\n🎉 All tests passed! Authentication system is ready.")
    else:
        print(f"\n⚠️  {total_count - passed_count} test(s) failed. Check logs above.")
    
    # Return Flask app if requested
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--run-server':
        if app:
            print("\n🚀 Starting Flask development server...")
            print("📱 Open: http://localhost:5000/test")
            print("🛑 Press Ctrl+C to stop\n")
            app.run(host='0.0.0.0', port=5000, debug=True)
    
    return all(results.values())

if __name__ == '__main__':
    # Check if we should run the server
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--run-server':
        # Initialize first
        test_database_initialization()
        app = test_flask_integration()
        if app:
            print("\n🚀 Starting Flask development server...")
            print("📱 Open: http://localhost:5000/test")
            print("🛑 Press Ctrl+C to stop\n")
            app.run(host='0.0.0.0', port=5000, debug=True)
    else:
        # Run tests
        success = main()
        sys.exit(0 if success else 1)
