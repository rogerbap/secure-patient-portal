//client/assets/js/login.js
/**
 * HealthSecure Portal - Login Page JavaScript
 * Handles authentication, security monitoring, and user interactions
 * FIXED VERSION: Enhanced dashboard navigation and user data storage
 */

class LoginManager {
    constructor() {
        this.apiBaseUrl = 'http://localhost:3000';
        this.isDemoMode = true;
        this.currentUser = 'patient';
        this.isConnected = false;
        
        // Demo user configurations
        this.demoUsers = {
            patient: {
                email: 'patient@demo.com',
                riskScore: 25,
                riskLevel: 'LOW',
                profile: 'Standard patient with normal access patterns'
            },
            provider: {
                email: 'doctor@demo.com',
                riskScore: 15,
                riskLevel: 'LOW',
                profile: 'Healthcare provider with trusted network access'
            },
            admin: {
                email: 'admin@demo.com',
                riskScore: 35,
                riskLevel: 'MEDIUM',
                profile: 'System administrator with elevated privileges'
            },
            suspicious: {
                email: 'suspicious@demo.com',
                riskScore: 85,
                riskLevel: 'HIGH',
                profile: 'High-risk scenario with multiple security flags'
            }
        };

        this.init();
    }

    /**
     * Initialize the login manager
     */
    init() {
        console.log('🔐 Login Manager - Initializing...');
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.onDOMReady());
        } else {
            this.onDOMReady();
        }
    }

    /**
     * Handle DOM ready state
     */
    onDOMReady() {
        this.setupEventListeners();
        this.checkApiConnection();
        this.updateSecurityDisplay();
        this.startSecurityMonitoring();
        
        console.log('✅ Login Manager - Ready');
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Login form submission
        const loginForm = document.getElementById('loginForm');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }

        // Demo mode toggle
        const demoModeToggle = document.getElementById('demoMode');
        if (demoModeToggle) {
            demoModeToggle.addEventListener('change', (e) => this.toggleDemoMode(e.target.checked));
        }

        // Demo account buttons
        document.querySelectorAll('.account-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const userType = btn.dataset.user;
                if (userType) {
                    this.selectDemoAccount(userType, btn);
                }
            });
        });

        // Form validation
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        
        if (emailInput) {
            emailInput.addEventListener('input', () => this.validateEmail());
            emailInput.addEventListener('blur', () => this.validateEmail());
        }
        
        if (passwordInput) {
            passwordInput.addEventListener('input', () => this.validatePassword());
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));

        // Periodic connection checks
        setInterval(() => this.checkApiConnection(), 30000);
    }

    /**
     * Handle keyboard shortcuts
     */
    handleKeyboardShortcuts(event) {
        if (event.altKey) {
            switch (event.key) {
                case '1':
                    event.preventDefault();
                    this.selectDemoAccount('patient');
                    break;
                case '2':
                    event.preventDefault();
                    this.selectDemoAccount('provider');
                    break;
                case '3':
                    event.preventDefault();
                    this.selectDemoAccount('admin');
                    break;
                case '4':
                    event.preventDefault();
                    this.selectDemoAccount('suspicious');
                    break;
            }
        }
        
        // Enter key to submit form
        if (event.key === 'Enter' && !event.shiftKey) {
            const activeElement = document.activeElement;
            if (activeElement && activeElement.form && activeElement.form.id === 'loginForm') {
                event.preventDefault();
                this.handleLogin(event);
            }
        }
    }

    /**
     * Toggle between demo and production mode
     */
    toggleDemoMode(enabled) {
        this.isDemoMode = enabled;
        
        const demoAccounts = document.getElementById('demoAccounts');
        const demoTools = document.getElementById('demoTools');
        const productionInfo = document.getElementById('productionInfo');
        
        if (enabled) {
            demoAccounts?.classList.remove('hidden');
            demoTools?.classList.remove('hidden');
            productionInfo?.classList.add('hidden');
            
            // Reset to demo defaults
            this.selectDemoAccount('patient');
        } else {
            demoAccounts?.classList.add('hidden');
            demoTools?.classList.add('hidden');
            productionInfo?.classList.remove('hidden');
            
            // Clear form for production use
            this.clearForm();
        }

        console.log(`🔄 Mode switched: ${enabled ? 'Demo' : 'Production'}`);
    }

    /**
     * Select demo account
     */
    selectDemoAccount(userType, buttonElement = null) {
        if (!this.isDemoMode || !this.demoUsers[userType]) return;

        this.currentUser = userType;
        const user = this.demoUsers[userType];

        // Update form fields
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        
        if (emailInput) emailInput.value = user.email;
        if (passwordInput) passwordInput.value = 'SecurePass123!';

        // Update button states
        document.querySelectorAll('.account-btn').forEach(btn => {
            btn.classList.remove('active');
        });
        
        if (buttonElement) {
            buttonElement.classList.add('active');
        } else {
            const btn = document.querySelector(`[data-user="${userType}"]`);
            if (btn) btn.classList.add('active');
        }

        // Update security display
        this.updateRiskDisplay(user.riskScore, user.riskLevel);
        
        console.log(`👤 Selected ${userType}: ${user.profile}`);
    }

    /**
     * Clear form fields
     */
    clearForm() {
        const emailInput = document.getElementById('email');
        const passwordInput = document.getElementById('password');
        
        if (emailInput) emailInput.value = '';
        if (passwordInput) passwordInput.value = '';
        
        this.clearValidation();
    }

    /**
     * Validate email input
     */
    validateEmail() {
        const emailInput = document.getElementById('email');
        const validator = document.getElementById('emailValidator');
        
        if (!emailInput || !validator) return;

        const email = emailInput.value.trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        
        if (!email) {
            this.showValidation(validator, '', '');
            return;
        }
        
        if (emailRegex.test(email)) {
            this.showValidation(validator, '✓ Valid email format', 'success');
        } else {
            this.showValidation(validator, '✗ Invalid email format', 'error');
        }
    }

    /**
     * Validate password input
     */
    validatePassword() {
        const passwordInput = document.getElementById('password');
        const strengthIndicator = document.getElementById('passwordStrength');
        
        if (!passwordInput || !strengthIndicator) return;

        const password = passwordInput.value;
        const strength = this.calculatePasswordStrength(password);
        
        this.showPasswordStrength(strengthIndicator, strength);
    }

    /**
     * Calculate password strength
     */
    calculatePasswordStrength(password) {
        if (!password) return { level: 0, text: '', color: '' };

        let score = 0;
        const checks = {
            length: password.length >= 8,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /\d/.test(password),
            special: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
        };

        Object.values(checks).forEach(check => {
            if (check) score++;
        });

        if (score <= 2) {
            return { level: 1, text: 'Weak password', color: 'error' };
        } else if (score <= 3) {
            return { level: 2, text: 'Fair password', color: 'warning' };
        } else if (score <= 4) {
            return { level: 3, text: 'Good password', color: 'success' };
        } else {
            return { level: 4, text: 'Strong password', color: 'success' };
        }
    }

    /**
     * Show validation message
     */
    showValidation(element, message, type) {
        element.textContent = message;
        element.className = `input-validator ${type}`;
    }

    /**
     * Show password strength
     */
    showPasswordStrength(element, strength) {
        element.textContent = strength.text;
        element.className = `password-strength ${strength.color}`;
    }

    /**
     * Clear validation messages
     */
    clearValidation() {
        const validators = document.querySelectorAll('.input-validator, .password-strength');
        validators.forEach(validator => {
            validator.textContent = '';
            validator.className = validator.className.split(' ')[0];
        });
    }

    /**
     * Check API connection status
     */
    async checkApiConnection() {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            const response = await fetch(`${this.apiBaseUrl}/api/health`, {
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            const data = await response.json();
            
            if (data.status === 'healthy') {
                this.isConnected = true;
                this.updateConnectionStatus('Connected', 'connected');
                console.log('✅ API Connected:', data);
            } else {
                throw new Error('API unhealthy');
            }
        } catch (error) {
            this.isConnected = false;
            this.updateConnectionStatus('Offline', 'disconnected');
            console.warn('⚠️ API Connection failed:', error.message);
        }
    }

    /**
     * Update connection status indicator
     */
    updateConnectionStatus(status, type) {
        const statusIcon = document.getElementById('statusIcon');
        const statusText = document.getElementById('statusText');
        
        if (statusIcon && statusText) {
            statusIcon.className = `fas fa-circle ${type}`;
            statusText.textContent = status;
        }
    }

    /**
     * Handle login form submission
     */
    async handleLogin(event) {
        event.preventDefault();
        
        const email = document.getElementById('email')?.value?.trim();
        const password = document.getElementById('password')?.value;
        
        if (!email || !password) {
            this.showLoginResult('Please enter both email and password', 'error');
            return;
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            this.showLoginResult('Please enter a valid email address', 'error');
            return;
        }

        this.setLoadingState(true);

        try {
            if (this.isDemoMode) {
                await this.handleDemoLogin(email, password);
            } else {
                await this.handleProductionLogin(email, password);
            }
        } catch (error) {
            console.error('Login error:', error);
            this.showLoginResult('Login failed. Please try again.', 'error');
        } finally {
            this.setLoadingState(false);
        }
    }

    /**
     * Handle demo mode login - ENHANCED VERSION
     */
    async handleDemoLogin(email, password) {
        // Simulate authentication delay
        await this.simulateDelay(1500);
        
        const user = Object.values(this.demoUsers).find(u => u.email === email);
        
        if (user && password === 'SecurePass123!') {
            const userType = Object.keys(this.demoUsers).find(key => this.demoUsers[key] === user);
            
            this.showLoginResult(
                `✅ Authentication successful! Welcome ${userType}. Risk Level: ${user.riskLevel}`,
                'success'
            );
            
            // Update security display
            this.updateRiskDisplay(user.riskScore, user.riskLevel);
            this.updateSecurityActions(user.riskScore);
            
            // Store comprehensive user info for dashboard
            const userInfo = {
                id: userType,
                email: email,
                role: userType,
                firstName: userType.charAt(0).toUpperCase() + userType.slice(1),
                lastName: 'User'
            };

            sessionStorage.setItem('userInfo', JSON.stringify(userInfo));
            
            // Also store a demo token for authentication
            sessionStorage.setItem('authToken', 'demo-token-' + userType + '-' + Date.now());
            
            // Store complete login data as backup
            sessionStorage.setItem('loginData', JSON.stringify({
                user: userInfo,
                riskAssessment: {
                    riskScore: user.riskScore,
                    riskLevel: user.riskLevel
                },
                timestamp: new Date().toISOString()
            }));
            
            // Redirect to dashboard after delay
            setTimeout(() => {
                this.redirectToDashboard(userType);
            }, 2000);
            
            console.log(`✅ Demo login successful: ${userType}`);
        } else {
            this.showLoginResult('❌ Invalid credentials for demo account', 'error');
        }
    }

    /**
     * Handle production mode login - ENHANCED VERSION
     */
    async handleProductionLogin(email, password) {
        if (!this.isConnected) {
            this.showLoginResult('⚠️ Cannot connect to server. Please try again later.', 'warning');
            return;
        }

        try {
            const response = await fetch(`${this.apiBaseUrl}/api/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });

            const data = await response.json();

            if (data.success) {
                // Store authentication data
                if (data.accessToken) {
                    sessionStorage.setItem('authToken', data.accessToken);
                }
                
                if (data.user) {
                    sessionStorage.setItem('userInfo', JSON.stringify(data.user));
                    
                    // Store complete login data as backup
                    sessionStorage.setItem('loginData', JSON.stringify({
                        user: data.user,
                        riskAssessment: data.riskAssessment,
                        timestamp: new Date().toISOString()
                    }));
                }

                this.showLoginResult(
                    `✅ Welcome ${data.user?.firstName || 'User'}! Risk Score: ${data.riskAssessment?.riskScore || 'N/A'}/100`,
                    'success'
                );

                // Update security display with real data
                if (data.riskAssessment) {
                    this.updateRiskDisplay(data.riskAssessment.riskScore, data.riskAssessment.riskLevel);
                    this.updateSecurityActions(data.riskAssessment.riskScore);
                }

                // Redirect to dashboard
                setTimeout(() => {
                    this.redirectToDashboard(data.user?.role || 'patient');
                }, 2000);

                console.log('✅ Production login successful');
            } else {
                this.showLoginResult(`❌ ${data.message || 'Login failed'}`, 'error');
            }
        } catch (error) {
            console.error('Production login error:', error);
            this.showLoginResult('❌ Server error. Please try again.', 'error');
        }
    }

    /**
     * Set loading state for login form
     */
    setLoadingState(loading) {
        const loginBtn = document.getElementById('loginBtn');
        const btnText = loginBtn?.querySelector('.btn-text');
        const btnLoader = loginBtn?.querySelector('.btn-loader');
        
        if (loginBtn) {
            loginBtn.disabled = loading;
            
            if (loading) {
                loginBtn.classList.add('loading');
                if (btnText) btnText.style.opacity = '0';
                if (btnLoader) btnLoader.style.opacity = '1';
            } else {
                loginBtn.classList.remove('loading');
                if (btnText) btnText.style.opacity = '1';
                if (btnLoader) btnLoader.style.opacity = '0';
            }
        }
    }

    /**
     * Show login result message
     */
    showLoginResult(message, type) {
        const resultDiv = document.getElementById('loginResult');
        if (!resultDiv) return;

        resultDiv.innerHTML = `
            <div class="alert ${type}">
                ${message}
            </div>
        `;

        // Auto-clear after 8 seconds
        setTimeout(() => {
            if (resultDiv.innerHTML) {
                resultDiv.innerHTML = '';
            }
        }, 8000);
    }

    /**
     * Update risk assessment display
     */
    updateRiskDisplay(riskScore, riskLevel) {
        // Update risk meter
        const riskFill = document.getElementById('riskFill');
        const riskScoreEl = document.getElementById('riskScore');
        const threatBadge = document.querySelector('.threat-badge');
        
        if (riskFill) {
            riskFill.style.width = `${riskScore}%`;
        }
        
        if (riskScoreEl) {
            riskScoreEl.textContent = `${riskScore}/100`;
        }
        
        if (threatBadge) {
            threatBadge.textContent = `${riskLevel} RISK`;
            threatBadge.className = `threat-badge ${riskLevel.toLowerCase()}`;
        }

        // Update security factors
        this.updateSecurityFactors(riskScore);
    }

    /**
     * Update security factors based on risk score
     */
    updateSecurityFactors(riskScore) {
        const factors = {
            locationStatus: { element: 'locationStatus' },
            deviceStatus: { element: 'deviceStatus' },
            timingStatus: { element: 'timingStatus' },
            velocityStatus: { element: 'velocityStatus' }
        };

        let statusConfig;
        if (riskScore < 30) {
            statusConfig = {
                locationStatus: { text: 'Trusted', class: 'safe' },
                deviceStatus: { text: 'Recognized', class: 'safe' },
                timingStatus: { text: 'Normal', class: 'safe' },
                velocityStatus: { text: 'Standard', class: 'safe' }
            };
        } else if (riskScore < 60) {
            statusConfig = {
                locationStatus: { text: 'New Location', class: 'warning' },
                deviceStatus: { text: 'Recognized', class: 'safe' },
                timingStatus: { text: 'Normal', class: 'safe' },
                velocityStatus: { text: 'Standard', class: 'safe' }
            };
        } else {
            statusConfig = {
                locationStatus: { text: 'Unknown', class: 'danger' },
                deviceStatus: { text: 'Suspicious', class: 'danger' },
                timingStatus: { text: 'Anomalous', class: 'warning' },
                velocityStatus: { text: 'High', class: 'danger' }
            };
        }

        Object.keys(statusConfig).forEach(key => {
            const element = document.getElementById(key);
            if (element) {
                element.textContent = statusConfig[key].text;
                element.className = `factor-status ${statusConfig[key].class}`;
            }
        });
    }

    /**
     * Update security actions based on risk score
     */
    updateSecurityActions(riskScore) {
        // This would typically update a security actions panel
        // For now, we'll just log the security response
        let action;
        if (riskScore >= 70) {
            action = 'High risk detected - Additional verification required';
        } else if (riskScore >= 40) {
            action = 'Medium risk - Enhanced monitoring enabled';
        } else {
            action = 'Low risk - Standard security protocols active';
        }
        
        console.log(`🔒 Security Action: ${action}`);
    }

    /**
     * Start security monitoring
     */
    startSecurityMonitoring() {
        // Simulate real-time security monitoring
        setInterval(() => {
            this.updateSecurityDisplay();
        }, 30000); // Update every 30 seconds
    }

    /**
     * Update security display with current information
     */
    updateSecurityDisplay() {
        if (this.isDemoMode && this.demoUsers[this.currentUser]) {
            const user = this.demoUsers[this.currentUser];
            this.updateRiskDisplay(user.riskScore, user.riskLevel);
        }
    }

    /**
     * Redirect to appropriate dashboard - FIXED VERSION
     */
    redirectToDashboard(role) {
    console.log(`🔄 Redirecting to ${role} dashboard...`);
    
    // Map roles to dashboard URLs
    const dashboardUrls = {
        patient: '/dashboard/patient.html',
        provider: '/dashboard/provider.html', 
        admin: '/dashboard/admin.html'
    };
    
    // Default to patient dashboard if role not found
    let url = dashboardUrls[role] || dashboardUrls.patient;
    
    // For demo purposes, all roles use patient dashboard
    if (this.isDemoMode) {
        url = '/dashboard/patient.html';
    }
    
    // Add success parameters to help dashboard authenticate
    url += `?login=success&role=${role}&timestamp=${Date.now()}`;
    
    try {
        // Add a small delay to show the success message
        setTimeout(() => {
            window.location.href = url;
        }, 500);
    } catch (error) {
        console.error('Navigation failed:', error);
        // Fallback - show success message and manual navigation
        this.showLoginResult(`🎉 Login successful! Please click <a href="${url}">here</a> to continue to dashboard.`, 'success');
    }
}
    /**
     * Utility method to simulate async delays
     */
    simulateDelay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Toggle password visibility
     */
    togglePasswordVisibility() {
        const passwordInput = document.getElementById('password');
        const toggleIcon = document.getElementById('passwordToggleIcon');
        
        if (passwordInput && toggleIcon) {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            toggleIcon.className = isPassword ? 'fas fa-eye-slash' : 'fas fa-eye';
        }
    }
}

// Global functions for inline event handlers
function selectDemoAccount(userType, buttonElement) {
    if (window.loginManager) {
        window.loginManager.selectDemoAccount(userType, buttonElement);
    }
}

function togglePassword() {
    if (window.loginManager) {
        window.loginManager.togglePasswordVisibility();
    }
}

function simulateSecurityThreat() {
    if (window.loginManager) {
        window.loginManager.selectDemoAccount('suspicious');
        alert(`🚨 Security Threat Simulation Activated!

The system has detected:
• Suspicious login from unknown location
• New device accessing sensitive data
• Unusual access patterns detected
• Multiple rapid authentication attempts

Response Actions:
• Enhanced monitoring enabled
• Security team notified
• Additional verification required
• Session privileges restricted

This demonstrates how the system responds to real security threats.`);
    }
}

function viewSystemHealth() {
    if (window.loginManager) {
        const status = window.loginManager.isConnected ? 'Online' : 'Offline';
        alert(`System Health Report:

🔌 API Connection: ${status}
🎯 Demo Mode: ${window.loginManager.isDemoMode ? 'Enabled' : 'Disabled'}
🔒 Security Engine: Active
📊 Risk Assessment: Operational
🛡️ Threat Detection: Monitoring

${window.loginManager.isConnected ? 
    '✅ All systems operational' : 
    '⚠️ Backend API offline - Demo mode only'
}`);
    }
}

function showTechnicalInfo() {
    alert(`🔧 Technical Information:

Frontend Technologies:
• HTML5 with semantic markup
• CSS3 with modern features
• Vanilla JavaScript ES6+
• Font Awesome icons
• Responsive design

Backend Technologies:
• Node.js with Express
• JWT authentication
• Sequelize ORM
• Winston logging
• bcrypt password hashing

Security Features:
• Risk assessment engine
• Real-time threat detection
• Geographic analysis
• Device fingerprinting
• Audit logging
• Rate limiting

Architecture:
• RESTful API design
• Modular component structure
• Separation of concerns
• Industry best practices

This project demonstrates enterprise-grade security implementation suitable for healthcare applications.`);
}

// Initialize the login manager
document.addEventListener('DOMContentLoaded', () => {
    window.loginManager = new LoginManager();
});

// Handle page visibility changes for security
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        console.log('🔒 Page hidden - Security monitoring paused');
    } else {
        console.log('👁️ Page visible - Security monitoring resumed');
        if (window.loginManager) {
            window.loginManager.checkApiConnection();
        }
    }
});

// Handle beforeunload for security cleanup
window.addEventListener('beforeunload', () => {
    console.log('🔄 Page unloading - Cleaning up security session');
});

console.log('🔐 Login system loaded successfully');