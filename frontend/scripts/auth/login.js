/**
 * Trading Platform - Login JavaScript
 * Handles authentication, 2FA, and password reset
 * Version: 1.0.0
 */

class TradingPlatformAuth {
    constructor() {
        this.apiBaseUrl = window.location.origin + '/api';
        this.currentUser = null;
        this.is2FARequired = false;
        this.pendingUserId = null;
        this.deviceId = this.getDeviceId();
        
        this.init();
    }
    
    init() {
        this.bindEvents();
        this.checkExistingSession();
        this.setupTOTPInput();
        this.initPasswordResetModal();
        
        // Auto-focus email field on page load
        const emailInput = document.getElementById('email');
        if (emailInput && !this.is2FARequired) {
            setTimeout(() => emailInput.focus(), 100);
        }
    }
    
    getDeviceId() {
        // Generate or retrieve a unique device identifier
        let deviceId = localStorage.getItem('trading_device_id');
        if (!deviceId) {
            deviceId = 'device_' + Math.random().toString(36).substr(2, 9) + 
                      '_' + Date.now().toString(36);
            localStorage.setItem('trading_device_id', deviceId);
        }
        return deviceId;
    }
    
    bindEvents() {
        // Login form submission
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        // 2FA form submission
        const twoFactorForm = document.getElementById('twoFactorForm');
        if (twoFactorForm) {
            twoFactorForm.addEventListener('submit', (e) => this.handle2FAVerification(e));
        }
        
        // Recovery form submission
        const recoveryForm = document.getElementById('recoveryForm');
        if (recoveryForm) {
            recoveryForm.addEventListener('submit', (e) => this.handleRecoveryCode(e));
        }
        
        // Password toggle
        const togglePassword = document.getElementById('togglePassword');
        if (togglePassword) {
            togglePassword.addEventListener('click', () => this.togglePasswordVisibility());
        }
        
        // Forgot password link
        const forgotPassword = document.getElementById('forgotPassword');
        if (forgotPassword) {
            forgotPassword.addEventListener('click', (e) => {
                e.preventDefault();
                this.showPasswordResetModal();
            });
        }
        
        // Navigation between forms
        const backToLogin = document.getElementById('backToLogin');
        if (backToLogin) {
            backToLogin.addEventListener('click', () => this.showLoginForm());
        }
        
        const backTo2FA = document.getElementById('backTo2FA');
        if (backTo2FA) {
            backTo2FA.addEventListener('click', () => this.show2FAForm());
        }
        
        const useRecoveryCode = document.getElementById('useRecoveryCode');
        if (useRecoveryCode) {
            useRecoveryCode.addEventListener('click', () => this.showRecoveryForm());
        }
        
        // Modal controls
        const closeResetModal = document.getElementById('closeResetModal');
        if (closeResetModal) {
            closeResetModal.addEventListener('click', () => this.hidePasswordResetModal());
        }
        
        const cancelReset = document.getElementById('cancelReset');
        if (cancelReset) {
            cancelReset.addEventListener('click', () => this.hidePasswordResetModal());
        }
        
        const sendResetEmail = document.getElementById('sendResetEmail');
        if (sendResetEmail) {
            sendResetEmail.addEventListener('click', () => this.sendPasswordResetEmail());
        }
        
        // TOTP input auto-advance
        this.setupTOTPAutoAdvance();
    }
    
    setupTOTPInput() {
        const digits = document.querySelectorAll('.totp-digit');
        digits.forEach((digit, index) => {
            digit.addEventListener('input', (e) => {
                const value = e.target.value;
                
                // Only allow numbers
                if (!/^\d*$/.test(value)) {
                    e.target.value = '';
                    return;
                }
                
                // Auto-advance to next digit
                if (value.length === 1 && index < digits.length - 1) {
                    digits[index + 1].focus();
                }
                
                // Auto-submit when all digits are filled
                if (this.allDigitsFilled()) {
                    this.submit2FACode();
                }
            });
            
            // Handle backspace
            digit.addEventListener('keydown', (e) => {
                if (e.key === 'Backspace' && e.target.value === '' && index > 0) {
                    digits[index - 1].focus();
                }
            });
            
            // Handle paste
            digit.addEventListener('paste', (e) => {
                e.preventDefault();
                const pastedData = e.clipboardData.getData('text').trim();
                
                if (/^\d{6}$/.test(pastedData)) {
                    // Fill all digits with pasted code
                    for (let i = 0; i < Math.min(6, pastedData.length); i++) {
                        if (digits[i]) {
                            digits[i].value = pastedData[i];
                        }
                    }
                    
                    // Auto-submit if all digits filled
                    if (this.allDigitsFilled()) {
                        this.submit2FACode();
                    }
                }
            });
        });
    }
    
    setupTOTPAutoAdvance() {
        // Focus first digit when 2FA form is shown
        document.addEventListener('DOMContentLoaded', () => {
            const observer = new MutationObserver((mutations) => {
                mutations.forEach((mutation) => {
                    if (mutation.type === 'attributes' && 
                        mutation.attributeName === 'class' &&
                        !document.getElementById('twoFactorForm').classList.contains('hidden')) {
                        setTimeout(() => {
                            const firstDigit = document.getElementById('digit1');
                            if (firstDigit) firstDigit.focus();
                        }, 100);
                    }
                });
            });
            
            const twoFactorForm = document.getElementById('twoFactorForm');
            if (twoFactorForm) {
                observer.observe(twoFactorForm, { attributes: true });
            }
        });
    }
    
    allDigitsFilled() {
        const digits = document.querySelectorAll('.totp-digit');
        return Array.from(digits).every(digit => digit.value.length === 1);
    }
    
    get2FACode() {
        const digits = document.querySelectorAll('.totp-digit');
        return Array.from(digits).map(d => d.value).join('');
    }
    
    clear2FACode() {
        const digits = document.querySelectorAll('.totp-digit');
        digits.forEach(digit => digit.value = '');
    }
    
    async handleLogin(e) {
        e.preventDefault();
        
        const email = document.getElementById('email').value.trim();
        const password = document.getElementById('password').value;
        const rememberMe = document.getElementById('rememberMe').checked;
        
        // Clear previous errors
        this.clearErrors();
        
        // Validate inputs
        if (!this.validateEmail(email)) {
            this.showError('emailError', 'Please enter a valid email address');
            return;
        }
        
        if (!password) {
            this.showError('passwordError', 'Please enter your password');
            return;
        }
        
        // Show loading state
        this.setLoading('loginButton', true);
        
        try {
            const response = await this.apiRequest('/auth/login', 'POST', {
                email: email.toLowerCase(),
                password: password
            });
            
            if (response.tokens && response.user) {
                // Check if 2FA is required
                if (response.user.two_factor_enabled) {
                    this.pendingUserId = response.user.id;
                    this.is2FARequired = true;
                    
                    // Store temporary token for 2FA verification
                    sessionStorage.setItem('pending_auth', JSON.stringify({
                        userId: response.user.id,
                        email: response.user.email,
                        tokens: response.tokens
                    }));
                    
                    this.show2FAForm();
                    this.showToast('Two-Factor Authentication Required', 'Please enter the code from your authenticator app', 'info');
                } else {
                    // No 2FA required, complete login
                    await this.completeLogin(response, rememberMe);
                }
            }
        } catch (error) {
            this.showError('passwordError', error.message || 'Login failed. Please check your credentials.');
            
            // Log failed attempt (in production, this would be tracked)
            console.warn('Login attempt failed:', error);
        } finally {
            this.setLoading('loginButton', false);
        }
    }
    
    async handle2FAVerification(e) {
        e.preventDefault();
        
        const code = this.get2FACode();
        
        if (!code || code.length !== 6) {
            this.showError('totpError', 'Please enter a valid 6-digit code');
            return;
        }
        
        if (!this.pendingUserId) {
            this.showError('totpError', 'Session expired. Please login again.');
            return;
        }
        
        this.setLoading('verify2FAButton', true);
        
        try {
            const response = await this.apiRequest('/2fa/verify-login', 'POST', {
                user_id: this.pendingUserId,
                code: code,
                device_id: this.deviceId
            });
            
            if (response.success) {
                // Retrieve stored auth data
                const pendingAuth = JSON.parse(sessionStorage.getItem('pending_auth') || '{}');
                
                if (response.session_token) {
                    // Store session token for trusted device
                    localStorage.setItem('session_token', response.session_token);
                }
                
                if (pendingAuth.tokens) {
                    // Complete login with stored tokens
                    await this.completeLogin({
                        user: { id: this.pendingUserId, ...pendingAuth.user },
                        tokens: pendingAuth.tokens
                    }, true);
                } else {
                    // Fallback: redirect to dashboard
                    window.location.href = '/dashboard.html';
                }
                
                // Clear pending auth
                sessionStorage.removeItem('pending_auth');
            }
        } catch (error) {
            this.showError('totpError', error.message || 'Invalid verification code');
            this.clear2FACode();
            document.getElementById('digit1').focus();
        } finally {
            this.setLoading('verify2FAButton', false);
        }
    }
    
    async handleRecoveryCode(e) {
        e.preventDefault();
        
        const recoveryCode = document.getElementById('recoveryCode').value.trim().toUpperCase();
        
        if (!recoveryCode || recoveryCode.length !== 8) {
            this.showError('recoveryError', 'Please enter a valid 8-digit recovery code');
            return;
        }
        
        if (!this.pendingUserId) {
            this.showError('recoveryError', 'Session expired. Please login again.');
            return;
        }
        
        this.setLoading('verifyRecoveryButton', true);
        
        try {
            // For now, we'll simulate recovery code verification
            // In production, this would call the /2fa/verify-login endpoint with recovery code
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            // Simulate successful verification
            const pendingAuth = JSON.parse(sessionStorage.getItem('pending_auth') || '{}');
            
            if (pendingAuth.tokens) {
                await this.completeLogin({
                    user: { id: this.pendingUserId, ...pendingAuth.user },
                    tokens: pendingAuth.tokens
                }, true);
                
                // Clear pending auth
                sessionStorage.removeItem('pending_auth');
                
                this.showToast('Recovery Code Accepted', 'You have successfully logged in using a recovery code. Please set up 2FA again for security.', 'warning');
            }
        } catch (error) {
            this.showError('recoveryError', error.message || 'Invalid recovery code');
            document.getElementById('recoveryCode').value = '';
            document.getElementById('recoveryCode').focus();
        } finally {
            this.setLoading('verifyRecoveryButton', false);
        }
    }
    
    async completeLogin(authData, rememberMe) {
        // Store tokens
        if (rememberMe) {
            localStorage.setItem('access_token', authData.tokens.access_token);
            localStorage.setItem('refresh_token', authData.tokens.refresh_token);
        } else {
            sessionStorage.setItem('access_token', authData.tokens.access_token);
            sessionStorage.setItem('refresh_token', authData.tokens.refresh_token);
        }
        
        // Store user data
        localStorage.setItem('current_user', JSON.stringify(authData.user));
        this.currentUser = authData.user;
        
        // Set last login time
        localStorage.setItem('last_login', new Date().toISOString());
        
        // Show success message
        this.showToast('Login Successful', `Welcome back, ${authData.user.username}!`, 'success');
        
        // Redirect to dashboard after short delay
        setTimeout(() => {
            window.location.href = '/dashboard.html';
        }, 1500);
    }
    
    async checkExistingSession() {
        const accessToken = localStorage.getItem('access_token') || sessionStorage.getItem('access_token');
        
        if (accessToken) {
            try {
                const response = await this.apiRequest('/auth/verify', 'POST', {}, {
                    'Authorization': `Bearer ${accessToken}`
                });
                
                if (response.valid) {
                    // User is already logged in, redirect to dashboard
                    window.location.href = '/dashboard.html';
                }
            } catch (error) {
                // Invalid token, clear storage
                this.clearAuthStorage();
            }
        }
    }
    
    clearAuthStorage() {
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('current_user');
        sessionStorage.removeItem('access_token');
        sessionStorage.removeItem('refresh_token');
        sessionStorage.removeItem('pending_auth');
    }
    
    // Form Navigation
    showLoginForm() {
        document.getElementById('loginForm').classList.remove('hidden');
        document.getElementById('twoFactorForm').classList.add('hidden');
        document.getElementById('recoveryForm').classList.add('hidden');
        document.getElementById('email').focus();
    }
    
    show2FAForm() {
        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('twoFactorForm').classList.remove('hidden');
        document.getElementById('recoveryForm').classList.add('hidden');
        this.clear2FACode();
        setTimeout(() => document.getElementById('digit1').focus(), 100);
    }
    
    showRecoveryForm() {
        document.getElementById('loginForm').classList.add('hidden');
        document.getElementById('twoFactorForm').classList.add('hidden');
        document.getElementById('recoveryForm').classList.remove('hidden');
        document.getElementById('recoveryCode').focus();
    }
    
    // Password Reset
    initPasswordResetModal() {
        const modal = document.getElementById('passwordResetModal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    this.hidePasswordResetModal();
                }
            });
            
            // Handle Enter key in reset email field
            const resetEmail = document.getElementById('resetEmail');
            if (resetEmail) {
                resetEmail.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        this.sendPasswordResetEmail();
                    }
                });
            }
        }
    }
    
    showPasswordResetModal() {
        document.getElementById('passwordResetModal').classList.remove('hidden');
        document.getElementById('resetEmail').value = document.getElementById('email').value;
        document.getElementById('resetEmail').focus();
    }
    
    hidePasswordResetModal() {
        document.getElementById('passwordResetModal').classList.add('hidden');
        document.getElementById('resetEmail').value = '';
    }
    
    async sendPasswordResetEmail() {
        const email = document.getElementById('resetEmail').value.trim();
        
        if (!this.validateEmail(email)) {
            this.showToast('Invalid Email', 'Please enter a valid email address', 'error');
            return;
        }
        
        const sendButton = document.getElementById('sendResetEmail');
        const originalText = sendButton.innerHTML;
        sendButton.innerHTML = '<div class="spinner small"></div> Sending...';
        sendButton.disabled = true;
        
        try {
            await this.apiRequest('/password/reset/request', 'POST', {
                email: email.toLowerCase()
            });
            
            this.hidePasswordResetModal();
            this.showToast('Reset Email Sent', 'If an account exists with this email, you will receive password reset instructions.', 'success');
            
            // Clear email field
            document.getElementById('resetEmail').value = '';
        } catch (error) {
            this.showToast('Reset Failed', error.message || 'Could not send reset email. Please try again.', 'error');
        } finally {
            sendButton.innerHTML = originalText;
            sendButton.disabled = false;
        }
    }
    
    // Utility Methods
    validateEmail(email) {
        const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return re.test(email);
    }
    
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = document.querySelector('#togglePassword i');
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleIcon.classList.remove('fa-eye');
            toggleIcon.classList.add('fa-eye-slash');
        } else {
            passwordInput.type = 'password';
            toggleIcon.classList.remove('fa-eye-slash');
            toggleIcon.classList.add('fa-eye');
        }
    }
    
    clearErrors() {
        document.querySelectorAll('.error-message').forEach(el => {
            el.textContent = '';
        });
    }
    
    showError(elementId, message) {
        const element = document.getElementById(elementId);
        if (element) {
            element.textContent = message;
            element.style.display = 'block';
        }
    }
    
    setLoading(buttonId, isLoading) {
        const button = document.getElementById(buttonId);
        if (!button) return;
        
        const textSpan = button.querySelector('span');
        const spinner = button.querySelector('.spinner');
        
        if (isLoading) {
            button.disabled = true;
            if (textSpan) textSpan.classList.add('hidden');
            if (spinner) spinner.classList.remove('hidden');
        } else {
            button.disabled = false;
            if (textSpan) textSpan.classList.remove('hidden');
            if (spinner) spinner.classList.add('hidden');
        }
    }
    
    async apiRequest(endpoint, method = 'GET', data = null, headers = {}) {
        const url = this.apiBaseUrl + endpoint;
        
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            },
            credentials: 'same-origin'
        };
        
        if (data) {
            options.body = JSON.stringify(data);
        }
        
        try {
            const response = await fetch(url, options);
            const responseData = await response.json();
            
            if (!response.ok) {
                throw new Error(responseData.error || `HTTP ${response.status}: ${response.statusText}`);
            }
            
            return responseData;
        } catch (error) {
            // Handle network errors
            if (error.name === 'TypeError' && error.message.includes('fetch')) {
                throw new Error('Network error. Please check your connection.');
            }
            throw error;
        }
    }
    
    showToast(title, message, type = 'info') {
        const toastContainer = document.getElementById('toastContainer');
        if (!toastContainer) return;
        
        const toastId = 'toast-' + Date.now();
        const iconMap = {
            success: 'fas fa-check-circle',
            error: 'fas fa-exclamation-circle',
            warning: 'fas fa-exclamation-triangle',
            info: 'fas fa-info-circle'
        };
        
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.id = toastId;
        toast.innerHTML = `
            <div class="toast-icon">
                <i class="${iconMap[type] || iconMap.info}"></i>
            </div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close" onclick="document.getElementById('${toastId}').remove()">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        toastContainer.appendChild(toast);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (document.getElementById(toastId)) {
                toast.remove();
            }
        }, 5000);
        
        // Limit to 3 toasts at a time
        const toasts = toastContainer.querySelectorAll('.toast');
        if (toasts.length > 3) {
            toasts[0].remove();
        }
    }
    
    submit2FACode() {
        const event = new Event('submit');
        document.getElementById('twoFactorForm').dispatchEvent(event);
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.tradingAuth = new TradingPlatformAuth();
    
    // Add global helper for toasts
    window.showToast = (title, message, type) => {
        if (window.tradingAuth) {
            window.tradingAuth.showToast(title, message, type);
        }
    };
    
    // Handle social login buttons (demo functionality)
    document.querySelectorAll('.btn-social').forEach(button => {
        button.addEventListener('click', () => {
            window.tradingAuth.showToast(
                'Social Login', 
                'Social login integration would be configured in production.', 
                'info'
            );
        });
    });
    
    // Demo: Auto-fill demo credentials (for development only)
    if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
        const demoFillButton = document.createElement('button');
        demoFillButton.type = 'button';
        demoFillButton.className = 'btn-text text-sm';
        demoFillButton.style.marginTop = '10px';
        demoFillButton.textContent = 'Fill Demo Credentials';
        demoFillButton.onclick = () => {
            document.getElementById('email').value = 'demo@tradingplatform.com';
            document.getElementById('password').value = 'Demo123!';
            window.tradingAuth.showToast('Demo Credentials', 'Demo credentials filled. Click Sign In to test.', 'info');
        };
        
        const formGroup = document.querySelector('.auth-form .form-group:last-child');
        if (formGroup) {
            formGroup.appendChild(demoFillButton);
        }
    }
});
