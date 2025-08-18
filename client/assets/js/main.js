/**
 * Secure Patient Portal - Main Application Logic
 * Handles user interactions, API communication, and UI updates
 */

class PatientPortalApp {
    constructor() {
        this.currentUser = 'patient';
        this.apiConnected = false;
        this.apiBaseUrl = 'http://localhost:3000';
        
        // User configurations with detailed risk profiles
        this.users = {
            patient: { 
                email: 'patient@demo.com', 
                riskScore: 25, 
                riskLevel: 'Low',
                description: 'Regular patient account with normal access patterns',
                features: ['View Records', 'Book Appointments', 'Message Provider']
            },
            provider: { 
                email: 'doctor@demo.com', 
                riskScore: 15, 
                riskLevel: 'Low',
                description: 'Healthcare provider with trusted network access',
                features: ['Patient Management', 'Clinical Notes', 'Prescriptions']
            },
            admin: { 
                email: 'admin@demo.com', 
                riskScore: 35, 
                riskLevel: 'Medium',
                description: 'Administrator account with elevated privileges',
                features: ['User Management', 'System Config', 'Audit Reports']
            },
            suspicious: { 
                email: 'suspicious@demo.com', 
                riskScore: 85, 
                riskLevel: 'High',
                description: 'High-risk scenario with multiple security flags',
                features: ['Limited Access', 'Additional Verification Required']
            }
        };

        this.init();
    }

    /**
     * Initialize the application
     */
    init() {
        console.log('🏥 Secure Patient Portal - Initializing...');
        
        // Wait for DOM to be ready
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
        console.log('📱 DOM Ready - Setting up event listeners...');
        
        this.setupEventListeners();
        this.checkApiConnection();
        this.updateRiskDisplay();
        this.showWelcomeMessage();
        
        // Add fade-in animation to main container
        const mainContainer = document.querySelector('.main-container');
        if (mainContainer) {
            mainContainer.classList.add('fade-in');
        }
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

        // User selection buttons
        document.querySelectorAll('[data-user]').forEach(btn => {
            btn.addEventListener('click', (e) => this.setUser(e.target.dataset.user, e.target));
        });

        // Quick action buttons
        const quickActions = {
            'checkApiHealth': () => this.checkApiHealth(),
            'viewApiDocs': () => this.viewApiDocs(),
            'testHighRisk': () => this.testHighRisk()
        };

        Object.keys(quickActions).forEach(actionId => {
            const btn = document.getElementById(actionId);
            if (btn) {
                btn.addEventListener('click', quickActions[actionId]);
            }
        });

        // Setup periodic API health checks
        setInterval(() => this.checkApiConnection(), 30000);
    }

    /**
     * Show welcome message in console
     */
    showWelcomeMessage() {
        setTimeout(() => {
            console.log('👋 Welcome to the Secure Patient Portal Demo!');
            console.log('🔧 Try different user types to see risk assessment in action');
            console.log('📊 Watch the real-time security monitoring');
            console.log('🎯 Features: JWT Auth, Risk Assessment, Role-based Access Control');
        }, 1000);
    }

    /**
     * Check API connection status
     */
    async checkApiConnection() {
        try {
            console.log('🔌 Checking API connection...');
            
            const response = await fetch(`${this.apiBaseUrl}/api/health`);
            const data = await response.json();
            
            if (data.status === 'healthy') {
                this.apiConnected = true;
                this.updateApiStatus('Connected ✅', 'success');
                console.log('✅ API Connection established:', data);
            } else {
                throw new Error('API unhealthy');
            }
        } catch (error) {
            this.apiConnected = false;
            this.updateApiStatus('Disconnected ❌', 'danger');
            console.error('❌ API Connection failed:', error);
            console.log('💡 Make sure to run: npm run dev:server');
        }
    }

    /**
     * Update API status indicator
     */
    updateApiStatus(text, type) {
        const statusElement = document.getElementById('apiStatus');
        const statusText = document.getElementById('statusText');
        const statusSpinner = document.getElementById('statusSpinner');
        
        if (!statusElement || !statusText || !statusSpinner) return;
        
        statusText.textContent = `API ${text}`;
        statusSpinner.style.display = type === 'success' ? 'none' : 'inline-block';
        
        statusElement.className = `api-status alert alert-${type}`;
        
        if (type === 'success') {
            setTimeout(() => {
                statusElement.style.opacity = '0.8';
            }, 3000);
        }
    }

    /**
     * Set demo user
     */
    setUser(userType, buttonElement) {
        if (!this.users[userType]) {
            console.error('Invalid user type:', userType);
            return;
        }

        this.currentUser = userType;
        const user = this.users[userType];
        
        // Update form fields
        const emailField = document.getElementById('email');
        const passwordField = document.getElementById('password');
        
        if (emailField) emailField.value = user.email;
        if (passwordField) passwordField.value = 'SecurePass123!';
        
        this.updateRiskDisplay();
        
        console.log(`👤 Switched to ${userType} account:`, user.description);
        
        // Update button states
        document.querySelectorAll('[data-user]').forEach(btn => {
            btn.classList.remove('active');
        });
        
        if (buttonElement) {
            buttonElement.classList.add('active');
        }

        // Show user info
        this.showUserInfo(user);
    }

    /**
     * Show user information
     */
    showUserInfo(user) {
        const message = `Selected: ${user.description}\nRisk Level: ${user.riskLevel} (${user.riskScore}/100)`;
        
        // Create temporary info display
        const infoDiv = document.createElement('div');
        infoDiv.className = 'alert alert-info mt-2';
        infoDiv.innerHTML = `
            <i class="fas fa-info-circle"></i>
            <strong>${user.description}</strong><br>
            <small>Risk Level: ${user.riskLevel} (${user.riskScore}/100)</small>
        `;
        
        // Remove existing info
        const existing = document.querySelector('.user-info-temp');
        if (existing) existing.remove();
        
        infoDiv.classList.add('user-info-temp');
        
        // Insert after demo info
        const demoInfo = document.querySelector('.demo-info');
        if (demoInfo) {
            demoInfo.insertAdjacentElement('afterend', infoDiv);
            
            // Remove after 5 seconds
            setTimeout(() => {
                if (infoDiv.parentNode) {
                    infoDiv.remove();
                }
            }, 5000);
        }
    }

    /**
     * Update risk assessment display
     */
    updateRiskDisplay() {
        const user = this.users[this.currentUser];
        if (!user) return;

        // Update risk meter
        const riskMeter = document.getElementById('riskMeter');
        const riskLevel = document.getElementById('riskLevel');
        const riskScore = document.getElementById('riskScore');
        
        if (riskMeter) {
            riskMeter.style.width = user.riskScore + '%';
            riskMeter.className = 'risk-fill';
            
            if (user.riskScore < 30) {
                riskMeter.classList.add('risk-low');
            } else if (user.riskScore < 60) {
                riskMeter.classList.add('risk-medium');
            } else {
                riskMeter.classList.add('risk-high');
            }
        }
        
        if (riskLevel) riskLevel.textContent = user.riskLevel + ' Risk';
        if (riskScore) riskScore.textContent = user.riskScore + '/100';
        
        // Update status badges
        this.updateStatusBadges(user);
    }

    /**
     * Update individual status badges
     */
    updateStatusBadges(user) {
        const badges = {
            location: document.getElementById('locationStatus'),
            device: document.getElementById('deviceStatus'),
            timing: document.getElementById('timingStatus'),
            velocity: document.getElementById('velocityStatus')
        };
        
        // Define status based on risk score
        const statusConfig = this.getStatusConfig(user.riskScore);
        
        Object.keys(badges).forEach(key => {
            const badge = badges[key];
            if (badge && statusConfig[key]) {
                badge.textContent = statusConfig[key].text;
                badge.className = `badge badge-custom ${statusConfig[key].class}`;
            }
        });
    }

    /**
     * Get status configuration based on risk score
     */
    getStatusConfig(riskScore) {
        if (riskScore < 30) {
            return {
                location: { text: 'Trusted Location', class: 'bg-success' },
                device: { text: 'Recognized Device', class: 'bg-success' },
                timing: { text: 'Normal Hours', class: 'bg-success' },
                velocity: { text: 'Normal Pattern', class: 'bg-success' }
            };
        } else if (riskScore < 60) {
            return {
                location: { text: 'New Location', class: 'bg-warning' },
                device: { text: 'Recognized Device', class: 'bg-success' },
                timing: { text: 'Normal Hours', class: 'bg-success' },
                velocity: { text: 'Normal Pattern', class: 'bg-success' }
            };
        } else {
            return {
                location: { text: 'Unknown Location', class: 'bg-danger' },
                device: { text: 'New Device', class: 'bg-danger' },
                timing: { text: 'Unusual Hours', class: 'bg-warning' },
                velocity: { text: 'High Velocity', class: 'bg-danger' }
            };
        }
    }

    /**
     * Handle login form submission
     */
    async handleLogin(event) {
        event.preventDefault();
        
        if (!this.apiConnected) {
            this.showResult('⚠️ API connection required for authentication. Please start the backend server.', 'warning');
            return;
        }
        
        const email = document.getElementById('email')?.value;
        const password = document.getElementById('password')?.value;
        const loginBtn = document.getElementById('loginBtn');
        const form = document.getElementById('loginForm');
        
        if (!email || !password) {
            this.showResult('❌ Please enter both email and password', 'danger');
            return;
        }
        
        // Show loading state
        this.setLoadingState(loginBtn, form, true);
        
        console.log(`🔐 Attempting login for: ${email}`);
        
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
                console.log('✅ Login successful:', data);
                this.showResult(
                    `🎉 Welcome ${data.user.name}! Risk Score: ${data.riskAssessment.riskScore}/100 (${data.riskAssessment.riskLevel})`, 
                    'success'
                );
                this.updateSecurityActions(data.riskAssessment);
                
                // Store user session info
                sessionStorage.setItem('userSession', JSON.stringify({
                    user: data.user,
                    riskAssessment: data.riskAssessment,
                    timestamp: Date.now()
                }));
                
            } else {
                console.log('❌ Login failed:', data);
                this.showResult(`❌ ${data.message || 'Login failed'}`, 'danger');
            }
            
        } catch (error) {
            console.error('🚨 Login error:', error);
            this.showResult('🚨 Connection error. Make sure the backend server is running (npm run dev:server)', 'danger');
        } finally {
            this.setLoadingState(loginBtn, form, false);
        }
    }

    /**
     * Set loading state for form
     */
    setLoadingState(button, form, isLoading) {
        if (!button) return;
        
        if (isLoading) {
            button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Authenticating...';
            button.disabled = true;
            if (form) form.classList.add('loading');
        } else {
            button.innerHTML = '<i class="fas fa-sign-in-alt"></i> Login Securely';
            button.disabled = false;
            if (form) form.classList.remove('loading');
        }
    }

    /**
     * Show login result message
     */
    showResult(message, type) {
        const resultDiv = document.getElementById('loginResult');
        if (!resultDiv) return;
        
        const alertClass = type === 'success' ? 'alert-success' : 
                          type === 'warning' ? 'alert-warning' : 'alert-danger';
        
        resultDiv.innerHTML = `
            <div class="alert ${alertClass} fade-in">
                ${message}
            </div>
        `;
        
        // Auto-remove after 8 seconds
        setTimeout(() => {
            if (resultDiv.innerHTML) {
                resultDiv.innerHTML = '';
            }
        }, 8000);
    }

    /**
     * Update security actions based on risk assessment
     */
    updateSecurityActions(riskData) {
        const actionsDiv = document.getElementById('securityActions');
        if (!actionsDiv) return;
        
        let alertClass, icon, message;
        
        switch (riskData.riskLevel) {
            case 'HIGH':
                alertClass = 'alert-danger';
                icon = 'fas fa-exclamation-triangle';
                message = `<strong>High Risk Detected!</strong><br>${riskData.securityAction || 'Additional verification may be required'}`;
                break;
            case 'MEDIUM':
                alertClass = 'alert-warning';
                icon = 'fas fa-exclamation-circle';
                message = `<strong>Medium Risk</strong><br>${riskData.securityAction || 'Enhanced monitoring enabled'}`;
                break;
            default:
                alertClass = 'alert-success';
                icon = 'fas fa-check-circle';
                message = `<strong>Low Risk</strong><br>${riskData.securityAction || 'All security checks passed - Login approved'}`;
        }
        
        actionsDiv.innerHTML = `
            <div class="alert ${alertClass} fade-in">
                <i class="${icon}"></i> ${message}
            </div>
        `;
    }

    /**
     * Quick demo actions
     */
    async checkApiHealth() {
        try {
            const response = await fetch(`${this.apiBaseUrl}/api/health`);
            const data = await response.json();
            
            const healthInfo = `
API Health Check Results:

✅ Status: ${data.status}
📊 Version: ${data.version}
🌍 Environment: ${data.environment}
⏱️ Uptime: ${Math.round(data.uptime)}s
🔧 Features: ${Object.keys(data.features || {}).join(', ')}
            `.trim();
            
            alert(healthInfo);
            console.log('🏥 API Health Check:', data);
            
        } catch (error) {
            const errorMsg = `
❌ API Health Check Failed!

Make sure the backend server is running:
• npm run dev:server
• Check port 3000 is available
• Verify no firewall blocking

Error: ${error.message}
            `.trim();
            
            alert(errorMsg);
            console.error('❌ Health check failed:', error);
        }
    }

    async viewApiDocs() {
        try {
            const docsUrl = `${this.apiBaseUrl}/api/docs`;
            window.open(docsUrl, '_blank');
            console.log('📚 Opening API documentation...');
        } catch (error) {
            alert('Could not open API docs. Server may not be running.');
            console.error('❌ Could not open docs:', error);
        }
    }

    testHighRisk() {
        this.setUser('suspicious');
        
        const message = `
🔍 High-Risk User Simulation Activated!

Notice how the interface changes:
• Risk score jumps to 85/100
• Status indicators turn red/orange
• Security warnings appear
• Additional verification would be required

This demonstrates real-time threat detection in action.
        `.trim();
        
        alert(message);
        console.log('🚨 High-risk simulation activated');
    }

    /**
     * Get current session info
     */
    getSessionInfo() {
        try {
            const session = sessionStorage.getItem('userSession');
            return session ? JSON.parse(session) : null;
        } catch (error) {
            console.error('Error parsing session:', error);
            return null;
        }
    }

    /**
     * Clear session
     */
    clearSession() {
        sessionStorage.removeItem('userSession');
        console.log('🔐 Session cleared');
    }

    /**
     * Format timestamp for display
     */
    formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString();
    }

    /**
     * Log application metrics
     */
    logMetrics() {
        const metrics = {
            timestamp: new Date().toISOString(),
            currentUser: this.currentUser,
            apiConnected: this.apiConnected,
            sessionActive: !!this.getSessionInfo(),
            userAgent: navigator.userAgent,
            viewport: {
                width: window.innerWidth,
                height: window.innerHeight
            }
        };
        
        console.log('📊 App Metrics:', metrics);
        return metrics;
    }
}

// Initialize the application when script loads
window.PatientPortalApp = PatientPortalApp;

// Auto-initialize if DOM is ready
const app = new PatientPortalApp();

// Global utility functions for inline event handlers
window.setUser = (userType) => app.setUser(userType);
window.checkApiHealth = () => app.checkApiHealth();
window.viewApiDocs = () => app.viewApiDocs();
window.testHighRisk = () => app.testHighRisk();