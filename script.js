// Authentication System
class AuthSystem {
    constructor() {
        this.currentUser = null;
        this.apiBaseUrl = 'http://localhost:3000/api'; // Backend API URL
        this.init();
    }

    init() {
        this.bindEvents();
        this.checkAuthStatus();
        this.handleSocialLoginRedirect();
    }

    bindEvents() {
        // Modal triggers
        document.getElementById('sign-in').addEventListener('click', () => this.showModal('signInModal'));
        document.getElementById('sign-up').addEventListener('click', () => this.showModal('signUpModal'));
        
        // Footer CTA
        const footerBtn = document.getElementById('footer');
        if (footerBtn) {
            footerBtn.addEventListener('click', () => {
                // Resolve relative path whether on root or subpage
                const to = window.location.pathname.includes('/pages/') ? '../pages/getting-started.html' : './pages/getting-started.html';
                window.location.href = to;
            });
        }
        
        // Modal close buttons
        document.getElementById('closeSignIn').addEventListener('click', () => this.hideModal('signInModal'));
        document.getElementById('closeSignUp').addEventListener('click', () => this.hideModal('signUpModal'));
        
        // Form switches
        document.getElementById('switchToSignUp').addEventListener('click', (e) => {
            e.preventDefault();
            this.hideModal('signInModal');
            this.showModal('signUpModal');
        });
        
        document.getElementById('switchToSignIn').addEventListener('click', (e) => {
            e.preventDefault();
            this.hideModal('signUpModal');
            this.showModal('signInModal');
        });
        
        // Form submissions
        document.getElementById('signInForm').addEventListener('submit', (e) => this.handleSignIn(e));
        document.getElementById('signUpForm').addEventListener('submit', (e) => this.handleSignUp(e));
        
        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => this.handleLogout());
        
        // Forgot password
        document.getElementById('forgotPassword').addEventListener('click', (e) => {
            e.preventDefault();
            this.handleForgotPassword();
        });
        
        // Close modals when clicking outside
        window.addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) {
                this.hideModal(e.target.id);
            }
        });
    }

    showModal(modalId) {
        document.getElementById(modalId).style.display = 'block';
        this.clearFormMessages(modalId);
    }

    hideModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
        this.clearFormMessages(modalId);
    }

    clearFormMessages(modalId) {
        const modal = document.getElementById(modalId);
        const existingMessages = modal.querySelectorAll('.error-message, .success-message');
        existingMessages.forEach(msg => msg.remove());
    }

    showMessage(modalId, message, type = 'error') {
        const modal = document.getElementById(modalId);
        const messageDiv = document.createElement('div');
        messageDiv.className = `${type}-message`;
        messageDiv.textContent = message;
        
        const form = modal.querySelector('form');
        form.appendChild(messageDiv);
        
        // Auto-remove success messages after 3 seconds
        if (type === 'success') {
            setTimeout(() => messageDiv.remove(), 3000);
        }
    }

    async handleSignUp(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const userData = {
            name: formData.get('name'),
            email: formData.get('email'),
            password: formData.get('password'),
            confirmPassword: formData.get('confirmPassword')
        };

        // Client-side validation
        if (userData.password !== userData.confirmPassword) {
            this.showMessage('signUpModal', 'Passwords do not match');
            return;
        }

        if (userData.password.length < 6) {
            this.showMessage('signUpModal', 'Password must be at least 6 characters long');
            return;
        }

        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/signup`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(userData)
            });

            const result = await response.json();

            if (response.ok) {
                this.showMessage('signUpModal', 'Account created successfully!', 'success');
                setTimeout(() => {
                    this.hideModal('signUpModal');
                    e.target.reset();
                }, 1500);
            } else {
                this.showMessage('signUpModal', result.message || 'Sign up failed');
            }
        } catch (error) {
            console.error('Sign up error:', error);
            this.showMessage('signUpModal', 'Network error. Please try again.');
        }
    }

    async handleSignIn(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        const credentials = {
            email: formData.get('email'),
            password: formData.get('password'),
            token: formData.get('twoFactorToken')
        };

        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/signin-2fa`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(credentials)
            });

            const result = await response.json();

            if (response.ok) {
                if (result.requires2FA) {
                    // Show 2FA input field
                    document.getElementById('twoFactorGroup').style.display = 'block';
                    this.showMessage('signInModal', 'Please enter your 2FA code', 'info');
                    return;
                }

                // Store token and user data
                localStorage.setItem('authToken', result.token);
                localStorage.setItem('userData', JSON.stringify(result.user));
                
                this.currentUser = result.user;
                this.updateUI();
                this.hideModal('signInModal');
                e.target.reset();
                document.getElementById('twoFactorGroup').style.display = 'none';
                
                this.showMessage('signInModal', 'Welcome back!', 'success');
                
                // Handle social login redirect
                this.handleSocialLoginRedirect();
            } else {
                this.showMessage('signInModal', result.message || 'Sign in failed');
            }
        } catch (error) {
            console.error('Sign in error:', error);
            this.showMessage('signInModal', 'Network error. Please try again.');
        }
    }

    async handleLogout() {
        try {
            const token = localStorage.getItem('authToken');
            if (token) {
                await fetch(`${this.apiBaseUrl}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });
            } else {
                // still call endpoint, it is idempotent server-side
                await fetch(`${this.apiBaseUrl}/auth/logout`, { method: 'POST' });
            }
        } catch (error) {
            // swallow network errors; proceed to clear local state
            console.warn('Logout network issue ignored:', error);
        } finally {
            // Clear local storage and update UI regardless of API response
            localStorage.removeItem('authToken');
            localStorage.removeItem('userData');
            this.currentUser = null;
            this.updateUI();
        }
    }

    async checkAuthStatus() {
        const token = localStorage.getItem('authToken');
        const userData = localStorage.getItem('userData');

        if (token && userData) {
            try {
                // Verify token with backend
                const response = await fetch(`${this.apiBaseUrl}/auth/verify`, {
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                });

                if (response.ok) {
                    this.currentUser = JSON.parse(userData);
                    this.updateUI();
                } else {
                    // Token is invalid, clear storage
                    localStorage.removeItem('authToken');
                    localStorage.removeItem('userData');
                }
            } catch (error) {
                console.error('Auth verification error:', error);
                // On network error, still show user as logged in (offline mode)
                this.currentUser = JSON.parse(userData);
                this.updateUI();
            }
        }
    }

    updateUI() {
        const authButtons = document.querySelector('.auth-buttons');
        const userProfile = document.getElementById('userProfile');
        const userAvatar = document.getElementById('userAvatar');
        const userName = document.getElementById('userName');
        const adminLink = document.getElementById('adminLink');

        if (this.currentUser) {
            // User is logged in
            authButtons.style.display = 'none';
            userProfile.style.display = 'flex';
            
            // Set user avatar (first letter of name or actual avatar)
            if (this.currentUser.avatar_url) {
                userAvatar.innerHTML = `<img src="${this.currentUser.avatar_url}" alt="Avatar" style="width: 100%; height: 100%; border-radius: 50%; object-fit: cover;">`;
            } else {
                userAvatar.textContent = this.currentUser.name.charAt(0).toUpperCase();
            }
            userName.textContent = this.currentUser.name;
            
            // Show admin link if user is admin
            if (this.currentUser.role === 'admin') {
                adminLink.style.display = 'inline-block';
            } else {
                adminLink.style.display = 'none';
            }
        } else {
            // User is not logged in
            authButtons.style.display = 'flex';
            userProfile.style.display = 'none';
            adminLink.style.display = 'none';
        }
    }

    handleSocialLoginRedirect() {
        // Handle URL parameters for social login
        const urlParams = new URLSearchParams(window.location.search);
        const token = urlParams.get('token');
        const user = urlParams.get('user');
        const authError = urlParams.get('authError');

        if (authError) {
            try {
                this.showMessage('signInModal', 'Social login failed. Please try again.', 'error');
                // Clean up error param
                urlParams.delete('authError');
                const newUrl = `${window.location.pathname}${urlParams.toString() ? '?' + urlParams.toString() : ''}`;
                window.history.replaceState({}, document.title, newUrl);
            } catch (_) {}
        }

        if (token && user) {
            try {
                const userData = JSON.parse(decodeURIComponent(user));
                localStorage.setItem('authToken', token);
                localStorage.setItem('userData', JSON.stringify(userData));
                
                this.currentUser = userData;
                this.updateUI();
                
                // Clean up URL
                window.history.replaceState({}, document.title, window.location.pathname);
                
                this.showMessage('signInModal', 'Welcome! Social login successful.', 'success');
            } catch (error) {
                console.error('Error processing social login:', error);
            }
        }
    }

    async handleForgotPassword() {
        const email = prompt('Enter your email address:');
        if (!email) return;

        try {
            const response = await fetch(`${this.apiBaseUrl}/auth/forgot-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ email })
            });

            const result = await response.json();
            alert(result.message);
        } catch (error) {
            console.error('Forgot password error:', error);
            alert('Failed to send reset email. Please try again.');
        }
    }

    showMessage(modalId, message, type = 'error') {
        const modal = document.getElementById(modalId);
        const messageDiv = document.createElement('div');
        messageDiv.className = `${type}-message`;
        messageDiv.textContent = message;
        
        const form = modal.querySelector('form');
        if (form) {
            form.appendChild(messageDiv);
        } else {
            // For social login messages
            const modalContent = modal.querySelector('.modal-content');
            modalContent.appendChild(messageDiv);
        }
        
        // Auto-remove success messages after 3 seconds
        if (type === 'success') {
            setTimeout(() => messageDiv.remove(), 3000);
        }
    }
}

// Initialize the authentication system when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new AuthSystem();
});
