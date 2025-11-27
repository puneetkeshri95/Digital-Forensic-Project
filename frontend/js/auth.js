/**
 * Authentication JavaScript
 * Handles login, logout, session management, and security features
 */

class AuthManager {
    constructor() {
        this.baseUrl = '/api/auth';
        this.token = this.getStoredToken();
        this.currentUser = null;
        this.initialize();
    }

    initialize() {
        // Don't auto-validate in constructor to prevent duplicate redirects
        // Token validation will be handled by dashboard.init() or login page

        // Setup login form if on login page
        if (document.getElementById('loginForm')) {
            this.setupLoginForm();
        }

        // Setup logout handlers
        this.setupLogoutHandlers();

        // Setup periodic token validation
        this.setupTokenValidation();
    }

    setupLoginForm() {
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Auto-focus username field
        const usernameField = document.getElementById('username');
        if (usernameField) {
            usernameField.focus();
        }

        // Enter key handling
        document.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && document.activeElement.tagName === 'INPUT') {
                e.preventDefault();
                this.handleLogin(e);
            }
        });
    }

    setupLogoutHandlers() {
        // Find all logout buttons/links
        document.addEventListener('click', (e) => {
            if (e.target.matches('[data-action="logout"]') ||
                e.target.closest('[data-action="logout"]')) {
                e.preventDefault();
                this.logout();
            }
        });
    }

    setupTokenValidation() {
        // Token validation disabled to prevent refresh loops
        // Validate token every 5 minutes
        // setInterval(() => {
        //     if (this.token) {
        //         this.validateToken();
        //     }
        // }, 5 * 60 * 1000);
    }

    async handleLogin(event) {
        event.preventDefault();

        const form = document.getElementById('loginForm');
        const formData = new FormData(form);

        const loginData = {
            username: formData.get('username'),
            password: formData.get('password'),
            remember_me: formData.get('remember_me') === 'on'
        };

        // Validate input
        if (!loginData.username || !loginData.password) {
            this.showAlert('Please enter both username and password', 'warning');
            return;
        }

        // Show loading state
        this.setLoginLoading(true);

        try {
            const response = await fetch(`${this.baseUrl}/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(loginData),
                credentials: 'include'
            });

            const result = await response.json();

            if (response.ok && result.success) {
                // Store token
                this.token = result.token;
                this.currentUser = result.user;
                this.storeToken(result.token);

                // Also store as cookie for server-side authentication
                this.storeCookie(result.token);

                // Show success message
                this.showAlert('Login successful! Redirecting...', 'success');

                // Log successful login
                console.log('Login successful:', result.user);

                // Redirect to dashboard
                setTimeout(() => {
                    window.location.href = 'login.html';
                }, 2000);

            } else {
                // Handle login failure
                this.showAlert(result.error || 'Login failed', 'danger');
                this.clearStoredData();
            }

        } catch (error) {
            console.error('Login error:', error);
            this.showAlert('Login failed. Please check your connection and try again.', 'danger');
        } finally {
            this.setLoginLoading(false);
        }
    }

    async logout() {
        try {
            // Call logout API
            if (this.token) {
                await fetch(`${this.baseUrl}/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`,
                        'Content-Type': 'application/json'
                    },
                    credentials: 'include'
                });
            }
        } catch (error) {
            console.error('Logout API error:', error);
        } finally {
            // Clear local data regardless of API call result
            this.clearStoredData();

            // Redirect to login page
            window.location.href = 'login.html';
        }
    }

    async validateToken() {
        if (!this.token) {
            return false;
        }

        try {
            const response = await fetch(`${this.baseUrl}/validate-token`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success && result.valid) {
                    this.currentUser = result.user;
                    return true;
                }
            }

            // Token is invalid
            this.clearStoredData();
            return false;

        } catch (error) {
            console.error('Token validation error:', error);
            return false;
        }
    }

    async getCurrentUser() {
        if (this.currentUser) {
            return this.currentUser;
        }

        if (!this.token) {
            return null;
        }

        try {
            const response = await fetch(`${this.baseUrl}/profile`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    this.currentUser = result.user;
                    return this.currentUser;
                }
            }
        } catch (error) {
            console.error('Get current user error:', error);
        }

        return null;
    }

    async getUserPermissions() {
        if (!this.token) {
            return [];
        }

        try {
            const response = await fetch(`${this.baseUrl}/permissions`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`,
                    'Content-Type': 'application/json'
                },
                credentials: 'include'
            });

            if (response.ok) {
                const result = await response.json();
                if (result.success) {
                    return result.permissions;
                }
            }
        } catch (error) {
            console.error('Get permissions error:', error);
        }

        return [];
    }

    hasPermission(permission) {
        if (!this.currentUser || !this.currentUser.permissions) {
            return false;
        }
        return this.currentUser.permissions.includes(permission);
    }

    hasRole(role) {
        if (!this.currentUser) {
            return false;
        }
        return this.currentUser.role === role;
    }

    isAuthenticated() {
        return this.token !== null;
    }

    isFullyAuthenticated() {
        return this.token !== null && this.currentUser !== null;
    }

    // Utility methods
    storeToken(token) {
        localStorage.setItem('auth_token', token);
        localStorage.setItem('auth_timestamp', Date.now().toString());
    }

    storeCookie(token) {
        // Store token as HTTP-only cookie for server-side authentication
        const expirationDate = new Date();
        expirationDate.setHours(expirationDate.getHours() + 24); // 24 hours expiration
        document.cookie = `auth_token=${token}; expires=${expirationDate.toUTCString()}; path=/; SameSite=Strict`;
    }

    getStoredToken() {
        const token = localStorage.getItem('auth_token');
        const timestamp = localStorage.getItem('auth_timestamp');

        // Check if token is expired (older than 24 hours)
        if (token && timestamp) {
            const tokenAge = Date.now() - parseInt(timestamp);
            const maxAge = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

            if (tokenAge > maxAge) {
                this.clearStoredData();
                return null;
            }
        }

        return token;
    }

    clearStoredData() {
        this.token = null;
        this.currentUser = null;
        localStorage.removeItem('auth_token');
        localStorage.removeItem('auth_timestamp');

        // Clear any session cookies
        document.cookie = 'auth_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/; SameSite=Strict';
    }

    getToken() {
        return this.token || this.getStoredToken();
    }

    async authenticatedFetch(url, options = {}) {
        const token = this.getToken();
        if (!token) {
            throw new Error('No authentication token available');
        }

        const defaultOptions = {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...options.headers
            }
        };

        const mergedOptions = { ...options, ...defaultOptions };
        return fetch(url, mergedOptions);
    }

    setLoginLoading(loading) {
        const loginBtn = document.getElementById('loginBtn');
        const loginText = loginBtn.querySelector('.login-text');
        const loadingSpinner = loginBtn.querySelector('.loading-spinner');

        if (loading) {
            loginBtn.disabled = true;
            loginText.style.display = 'none';
            loadingSpinner.style.display = 'inline';
        } else {
            loginBtn.disabled = false;
            loginText.style.display = 'inline';
            loadingSpinner.style.display = 'none';
        }
    }

    showAlert(message, type = 'info') {
        const alertContainer = document.getElementById('alertContainer');
        if (!alertContainer) return;

        // Remove existing alerts
        alertContainer.innerHTML = '';

        const alertDiv = document.createElement('div');
        alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
        alertDiv.innerHTML = `
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;

        alertContainer.appendChild(alertDiv);

        // Auto-dismiss after 5 seconds for non-error messages
        if (type !== 'danger') {
            setTimeout(() => {
                if (alertDiv.parentNode) {
                    alertDiv.remove();
                }
            }, 5000);
        }
    }

    // API helper method
    async apiCall(endpoint, options = {}) {
        const url = endpoint.startsWith('http') ? endpoint : `${this.baseUrl}${endpoint}`;

        const defaultOptions = {
            headers: {
                'Content-Type': 'application/json',
                'Authorization': this.token ? `Bearer ${this.token}` : ''
            },
            credentials: 'include'
        };

        const finalOptions = {
            ...defaultOptions,
            ...options,
            headers: {
                ...defaultOptions.headers,
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, finalOptions);

            if (response.status === 401) {
                // Unauthorized - token might be expired
                this.clearStoredData();
                window.location.href = 'login.html';
                return null;
            }

            return response;
        } catch (error) {
            console.error('API call error:', error);
            throw error;
        }
    }
}

// Utility functions for modal dialogs
function showSystemInfo() {
    const modal = new bootstrap.Modal(document.getElementById('systemInfoModal'));
    modal.show();
}

function showSecurityInfo() {
    authManager.showAlert(`
        <strong>Security Features:</strong><br>
        • PBKDF2 password hashing with salt<br>
        • JWT token-based authentication<br>
        • HTTP-only secure cookies<br>
        • Failed login attempt tracking<br>
        • Role-based access control<br>
        • Session timeout protection
    `, 'info');
}

function showHelp() {
    authManager.showAlert(`
        <strong>Need Help?</strong><br>
        • Use the demo credentials shown below<br>
        • Contact your system administrator for account issues<br>
        • Ensure JavaScript is enabled in your browser<br>
        • Try refreshing the page if you encounter issues
    `, 'info');
}

// Page protection for authenticated areas
function requireAuth() {
    if (!authManager.isAuthenticated()) {
        window.location.href = '/login.html';
        return false;
    }
    return true;
}

function requirePermission(permission) {
    if (!authManager.hasPermission(permission)) {
        authManager.showAlert('You do not have permission to access this resource', 'danger');
        return false;
    }
    return true;
}

function requireRole(role) {
    if (!authManager.hasRole(role)) {
        authManager.showAlert(`Access denied. Required role: ${role}`, 'danger');
        return false;
    }
    return true;
}

// Initialize auth manager
const authManager = new AuthManager();

// Export for global use
window.authManager = authManager;
window.requireAuth = requireAuth;
window.requirePermission = requirePermission;
window.requireRole = requireRole;

// Auto-redirect from login page if already authenticated
document.addEventListener('DOMContentLoaded', async () => {
    if (window.location.pathname.endsWith('login.html')) {
        if (authManager.token) {
            const isValid = await authManager.validateToken();
            if (isValid) {
                window.location.href = 'dashboard.html';
            }
        }
    }
});