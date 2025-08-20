//client/assets/js/dashboard.js
/**
 * HealthSecure Portal - Dashboard JavaScript
 * Handles dashboard functionality, navigation, and user interactions
 */

class DashboardManager {
    constructor() {
        this.apiBaseUrl = 'http://localhost:3000';
        this.currentSection = 'overview';
        this.sessionTimeout = null;
        this.sessionWarningShown = false;
        this.notificationPanel = false;
        this.userDropdown = false;

        this.init();
    }

    /**
     * Initialize the dashboard
     */
    init() {
        console.log('🏥 Dashboard Manager - Initializing...');

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
        this.loadUserData();
        this.startSessionTimer();
        this.animateCounters();
        this.checkAuthentication();

        console.log('✅ Dashboard Manager - Ready');
    }

    /**
     * Setup all event listeners
     */
    setupEventListeners() {
        // Navigation links
        document.querySelectorAll('.nav-link').forEach(link => {
            link.addEventListener('click', (e) => this.handleNavigation(e));
        });

        // User menu toggle
        const userAvatar = document.querySelector('.user-avatar');
        if (userAvatar) {
            userAvatar.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleUserMenu();
            });
        }

        // Notification toggle
        const notificationBtn = document.querySelector('.notifications');
        if (notificationBtn) {
            notificationBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleNotifications();
            });
        }

        // Close dropdowns when clicking outside
        document.addEventListener('click', () => {
            this.closeAllDropdowns();
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));

        // Session extension
        const extendBtn = document.querySelector('.extend-session-btn');
        if (extendBtn) {
            extendBtn.addEventListener('click', () => this.extendSession());
        }

        // Window events
        window.addEventListener('beforeunload', () => this.handleBeforeUnload());
        document.addEventListener('visibilitychange', () => this.handleVisibilityChange());
    }

    /**
     * Handle navigation between sections
     */
    handleNavigation(event) {
        event.preventDefault();

        const link = event.currentTarget;
        const section = link.dataset.section;

        if (section) {
            this.showSection(section);
            this.updateActiveNavigation(link);

            // Log navigation for analytics
            console.log(`📊 Navigation: ${this.currentSection} → ${section}`);
        }
    }

    /**
     * Show specific dashboard section
     */
    showSection(sectionName) {
        // Hide all sections
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });

        // Show target section
        const targetSection = document.getElementById(sectionName);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionName;

            // Load section-specific data
            this.loadSectionData(sectionName);
        }
    }

    /**
     * Update active navigation state
     */
    updateActiveNavigation(activeLink) {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });

        activeLink.classList.add('active');
    }

    /**
     * Load section-specific data
     */
    async loadSectionData(sectionName) {
        try {
            switch (sectionName) {
                case 'overview':
                    await this.loadOverviewData();
                    break;
                case 'appointments':
                    await this.loadAppointmentsData();
                    break;
                case 'records':
                    await this.loadRecordsData();
                    break;
                case 'messages':
                    await this.loadMessagesData();
                    break;
                case 'prescriptions':
                    await this.loadPrescriptionsData();
                    break;
            }
        } catch (error) {
            console.error(`Failed to load ${sectionName} data:`, error);
            this.showError(`Failed to load ${sectionName} data`);
        }
    }

    /**
     * Load overview dashboard data
     */
    async loadOverviewData() {
        try {
            const userInfo = this.getUserInfo();
            if (!userInfo) return;

            // For demo, we'll use static data
            // In production, this would make API calls
            const response = await this.makeAuthenticatedRequest(`/api/dashboard/${userInfo.role}`);

            if (response && response.success) {
                this.updateOverviewUI(response.data);
            }
        } catch (error) {
            console.warn('Using demo data for overview');
            this.updateOverviewUI(this.getDemoOverviewData());
        }
    }

    /**
     * Get demo overview data
     */
    getDemoOverviewData() {
        return {
            user: {
                name: 'John Patient',
                memberSince: '2023-01-15'
            },
            summary: {
                upcomingAppointments: 2,
                pendingResults: 1,
                unreadMessages: 3,
                prescriptions: 4
            }
        };
    }

    /**
     * Update overview UI with data
     */
    updateOverviewUI(data) {
        // Update user name
        const userNameEl = document.getElementById('patientName');
        if (userNameEl && data.user) {
            userNameEl.textContent = data.user.name?.split(' ')[0] || 'User';
        }

        // Update stat counters
        if (data.summary) {
            this.updateStatCounters(data.summary);
        }
    }

    /**
     * Update stat counters with animation
     */
    updateStatCounters(summary) {
        const statCards = document.querySelectorAll('.stat-number');

        statCards.forEach(card => {
            const target = parseInt(card.dataset.target) || 0;
            this.animateCounter(card, target);
        });
    }

    /**
     * Animate counter to target value
     */
    animateCounter(element, target) {
        let current = 0;
        const increment = target / 50; // 50 steps
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            element.textContent = Math.floor(current);
        }, 40); // 40ms intervals for smooth animation
    }

    /**
     * Animate all counters on page load
     */
    animateCounters() {
        const counters = document.querySelectorAll('.stat-number');

        counters.forEach(counter => {
            const target = parseInt(counter.dataset.target) || 0;
            setTimeout(() => {
                this.animateCounter(counter, target);
            }, 500); // Delay for page load
        });
    }

    /**
     * Load user data and update UI
     */
    async loadUserData() {
        try {
            const userInfo = this.getUserInfo();

            if (userInfo) {
                this.updateUserUI(userInfo);
            } else {
                // If no user info, redirect to login
                this.redirectToLogin();
            }
        } catch (error) {
            console.error('Failed to load user data:', error);
        }
    }

    /**
     * Get user info from session storage
     */
    getUserInfo() {
        try {
            const userInfo = sessionStorage.getItem('userInfo');
            return userInfo ? JSON.parse(userInfo) : null;
        } catch (error) {
            console.error('Error parsing user info:', error);
            return null;
        }
    }

    /**
     * Update user interface with user data
     */
    updateUserUI(userInfo) {
        // Update user name in header
        const userNameEl = document.getElementById('userName');
        if (userNameEl) {
            userNameEl.textContent = `${userInfo.firstName} ${userInfo.lastName}`;
        }

        // Update role badge if needed
        const roleBadge = document.querySelector('.role-badge');
        if (roleBadge) {
            roleBadge.textContent = `${userInfo.role} Portal`.replace(/^./, str => str.toUpperCase());
            roleBadge.className = `role-badge ${userInfo.role}`;
        }
    }

    /**
     * Check authentication status
     */
    async checkAuthentication() {
    try {
        console.log('🔍 Starting authentication check...');
        
        // Step 1: Check URL parameters first (from login redirect)
        const urlParams = new URLSearchParams(window.location.search);
        const loginSuccess = urlParams.get('login');
        const userRole = urlParams.get('role');
        
        if (loginSuccess === 'success' && userRole) {
            console.log('✅ Found login success parameters, creating session...');
            this.createSessionFromURL(userRole);
            
            // Clean up URL without page reload
            const newUrl = window.location.protocol + "//" + window.location.host + window.location.pathname;
            window.history.replaceState({path: newUrl}, '', newUrl);
            
            console.log('✅ Authentication successful from URL parameters');
            return; // Exit early - authentication successful
        }
        
        // Step 2: Check existing session storage
        let userInfo = this.getUserInfo();
        let authToken = sessionStorage.getItem('authToken');
        
        console.log('🔍 Checking existing session...', { 
            hasUserInfo: !!userInfo, 
            hasAuthToken: !!authToken,
            userEmail: userInfo?.email 
        });
        
        if (userInfo && userInfo.email && authToken) {
            console.log('✅ Valid existing session found');
            return; // Exit early - authentication successful
        }
        
        // Step 3: Check if we have a demo token but missing user info
        if (authToken && authToken.startsWith('demo-token-')) {
            console.log('✅ Demo token found, recreating user session...');
            const userType = this.extractUserTypeFromToken(authToken);
            if (userType) {
                this.createSessionFromToken(userType);
                console.log('✅ Session recreated from token');
                return; // Exit early - authentication successful
            }
        }
        
        // Step 4: Development mode fallback - create demo session
        if (this.isDevelopmentMode()) {
            console.log('🔧 Development mode - creating demo patient session...');
            this.createDemoSession('patient');
            console.log('✅ Demo session created');
            return; // Exit early - authentication successful
        }
        
        // Step 5: No valid authentication found
        console.log('❌ No valid authentication found');
        this.redirectToLogin();
        
    } catch (error) {
        console.error('❌ Authentication check failed:', error);
        
        // Emergency fallback for development
        if (this.isDevelopmentMode()) {
            console.log('🚨 Emergency fallback - creating demo session');
            this.createDemoSession('patient');
        } else {
            this.redirectToLogin();
        }
    }
}

/**
 * Create session from URL parameters
 */
createSessionFromURL(userRole) {
    const userInfo = {
        id: userRole,
        email: `${userRole}@demo.com`,
        role: userRole,
        firstName: userRole.charAt(0).toUpperCase() + userRole.slice(1),
        lastName: 'User'
    };
    
    const authToken = `demo-token-${userRole}-${Date.now()}`;
    
    const loginData = {
        user: userInfo,
        riskAssessment: {
            riskScore: this.getRiskScoreForRole(userRole),
            riskLevel: this.getRiskLevelForRole(userRole)
        },
        timestamp: new Date().toISOString()
    };
    
    // Store all session data
    sessionStorage.setItem('userInfo', JSON.stringify(userInfo));
    sessionStorage.setItem('authToken', authToken);
    sessionStorage.setItem('loginData', JSON.stringify(loginData));
    
    console.log(`✅ Session created for ${userRole} from URL parameters`);
}

/**
 * Create session from existing token
 */
createSessionFromToken(userType) {
    const userInfo = {
        id: userType,
        email: `${userType}@demo.com`,
        role: userType,
        firstName: userType.charAt(0).toUpperCase() + userType.slice(1),
        lastName: 'User'
    };
    
    const loginData = {
        user: userInfo,
        riskAssessment: {
            riskScore: this.getRiskScoreForRole(userType),
            riskLevel: this.getRiskLevelForRole(userType)
        },
        timestamp: new Date().toISOString()
    };
    
    // Store missing session data
    sessionStorage.setItem('userInfo', JSON.stringify(userInfo));
    sessionStorage.setItem('loginData', JSON.stringify(loginData));
    
    console.log(`✅ Session recreated for ${userType} from existing token`);
}

/**
 * Create demo session for development
 */
createDemoSession(userType = 'patient') {
    const userInfo = {
        id: userType,
        email: `${userType}@demo.com`,
        role: userType,
        firstName: userType === 'patient' ? 'Demo' : userType.charAt(0).toUpperCase() + userType.slice(1),
        lastName: userType === 'patient' ? 'Patient' : 'User'
    };
    
    const authToken = `demo-token-${userType}-${Date.now()}`;
    
    const loginData = {
        user: userInfo,
        riskAssessment: {
            riskScore: this.getRiskScoreForRole(userType),
            riskLevel: this.getRiskLevelForRole(userType)
        },
        timestamp: new Date().toISOString()
    };
    
    // Store all session data
    sessionStorage.setItem('userInfo', JSON.stringify(userInfo));
    sessionStorage.setItem('authToken', authToken);
    sessionStorage.setItem('loginData', JSON.stringify(loginData));
    
    console.log(`✅ Demo session created for ${userType}`);
}

/**
 * Extract user type from demo token
 */
extractUserTypeFromToken(token) {
    try {
        const parts = token.split('-');
        return parts.length >= 3 ? parts[2] : null;
    } catch (error) {
        console.error('Failed to extract user type from token:', error);
        return null;
    }
}

/**
 * Check if we're in development mode
 */
isDevelopmentMode() {
    return window.location.hostname === 'localhost' || 
           window.location.hostname === '127.0.0.1' ||
           window.location.hostname === '0.0.0.0' ||
           window.location.port === '8080';
}

/**
 * Get risk score for user role
 */
getRiskScoreForRole(role) {
    const riskScores = {
        patient: 25,
        provider: 15,
        admin: 35,
        suspicious: 85
    };
    return riskScores[role] || 25;
}

/**
 * Get risk level for user role
 */
getRiskLevelForRole(role) {
    const riskScore = this.getRiskScoreForRole(role);
    if (riskScore < 30) return 'LOW';
    if (riskScore < 60) return 'MEDIUM';
    return 'HIGH';
}

/**
 * Enhanced getUserInfo method
 */
getUserInfo() {
    try {
        // Try userInfo first
        const userInfo = sessionStorage.getItem('userInfo');
        if (userInfo) {
            const parsed = JSON.parse(userInfo);
            if (parsed && parsed.email) {
                return parsed;
            }
        }
        
        // Try loginData as fallback
        const loginData = sessionStorage.getItem('loginData');
        if (loginData) {
            const parsed = JSON.parse(loginData);
            if (parsed && parsed.user && parsed.user.email) {
                return parsed.user;
            }
        }
        
        return null;
    } catch (error) {
        console.error('Error parsing user info:', error);
        return null;
    }
}

    /**
     * Make authenticated API request
     */
    async makeAuthenticatedRequest(endpoint) {
        const token = sessionStorage.getItem('authToken');

        const response = await fetch(`${this.apiBaseUrl}${endpoint}`, {
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            }
        });

        if (response.status === 401) {
            this.redirectToLogin();
            return null;
        }

        return await response.json();
    }

    /**
     * Session management
     */
    startSessionTimer() {
        // 30 minutes session timeout
        const timeoutDuration = 30 * 60 * 1000;
        const warningTime = 5 * 60 * 1000; // 5 minutes warning

        // Clear existing timer
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }

        // Set session timeout
        this.sessionTimeout = setTimeout(() => {
            this.handleSessionTimeout();
        }, timeoutDuration);

        // Show warning before timeout
        setTimeout(() => {
            if (!this.sessionWarningShown) {
                this.showSessionWarning();
            }
        }, timeoutDuration - warningTime);

        // Update session timer display
        this.updateSessionTimer(timeoutDuration);
    }

    /**
     * Update session timer display
     */
    updateSessionTimer(remainingTime) {
        const timerEl = document.getElementById('sessionTimer');
        if (!timerEl) return;

        const updateDisplay = () => {
            remainingTime -= 1000;

            if (remainingTime <= 0) {
                timerEl.textContent = 'Session expired';
                return;
            }

            const hours = Math.floor(remainingTime / (1000 * 60 * 60));
            const minutes = Math.floor((remainingTime % (1000 * 60 * 60)) / (1000 * 60));

            timerEl.textContent = `Session: ${hours}h ${minutes}m remaining`;
        };

        updateDisplay();
        const interval = setInterval(() => {
            updateDisplay();
            if (remainingTime <= 0) {
                clearInterval(interval);
            }
        }, 60000); // Update every minute
    }

    /**
     * Show session warning
     */
    showSessionWarning() {
        this.sessionWarningShown = true;

        const confirmed = confirm(
            'Your session will expire in 5 minutes. Would you like to extend your session?'
        );

        if (confirmed) {
            this.extendSession();
        }
    }

    /**
     * Extend user session
     */
    async extendSession() {
        try {
            const response = await this.makeAuthenticatedRequest('/api/auth/refresh');

            if (response && response.success) {
                // Update token if provided
                if (response.accessToken) {
                    sessionStorage.setItem('authToken', response.accessToken);
                }

                // Restart session timer
                this.sessionWarningShown = false;
                this.startSessionTimer();

                this.showNotification('Session extended successfully', 'success');
            }
        } catch (error) {
            console.error('Failed to extend session:', error);
            this.showNotification('Failed to extend session', 'error');
        }
    }

    /**
     * Handle session timeout
     */
    handleSessionTimeout() {
        alert('Your session has expired. You will be redirected to the login page.');
        this.logout();
    }

    /**
     * Toggle user dropdown menu
     */
    toggleUserMenu() {
        const dropdown = document.getElementById('userDropdown');

        if (dropdown) {
            this.userDropdown = !this.userDropdown;

            if (this.userDropdown) {
                dropdown.classList.add('show');
                this.notificationPanel = false;
                this.hideNotifications();
            } else {
                dropdown.classList.remove('show');
            }
        }
    }

    /**
     * Toggle notifications panel
     */
    toggleNotifications() {
        const panel = document.getElementById('notificationPanel');

        if (panel) {
            this.notificationPanel = !this.notificationPanel;

            if (this.notificationPanel) {
                panel.classList.add('show');
                this.userDropdown = false;
                this.hideUserDropdown();
                this.loadNotifications();
            } else {
                panel.classList.remove('show');
            }
        }
    }

    /**
     * Close all dropdown menus
     */
    closeAllDropdowns() {
        this.hideUserDropdown();
        this.hideNotifications();
    }

    /**
     * Hide user dropdown
     */
    hideUserDropdown() {
        const dropdown = document.getElementById('userDropdown');
        if (dropdown) {
            dropdown.classList.remove('show');
            this.userDropdown = false;
        }
    }

    /**
     * Hide notifications panel
     */
    hideNotifications() {
        const panel = document.getElementById('notificationPanel');
        if (panel) {
            panel.classList.remove('show');
            this.notificationPanel = false;
        }
    }

    /**
     * Load notifications
     */
    async loadNotifications() {
        try {
            const response = await this.makeAuthenticatedRequest('/api/dashboard/notifications');

            if (response && response.success) {
                this.updateNotificationsUI(response.data.notifications);
            }
        } catch (error) {
            console.warn('Using demo notifications');
            this.updateNotificationsUI(this.getDemoNotifications());
        }
    }

    /**
     * Get demo notifications
     */
    getDemoNotifications() {
        return [
            {
                id: 1,
                type: 'appointment',
                title: 'Appointment Confirmed',
                message: 'Your appointment with Dr. Smith has been confirmed for January 15th at 10:00 AM',
                timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                read: false
            },
            {
                id: 2,
                type: 'result',
                title: 'Lab Results Available',
                message: 'Your blood test results are now available for viewing',
                timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
                read: false
            }
        ];
    }

    /**
     * Update notifications UI
     */
    updateNotificationsUI(notifications) {
        const notificationList = document.querySelector('.notification-list');
        if (!notificationList) return;

        if (notifications.length === 0) {
            notificationList.innerHTML = `
                <div class="text-center" style="padding: 2rem; color: var(--text-secondary);">
                    <i class="fas fa-bell-slash" style="font-size: 2rem; margin-bottom: 1rem;"></i>
                    <p>No notifications</p>
                </div>
            `;
            return;
        }

        notificationList.innerHTML = notifications.map(notification => `
            <div class="notification-item ${notification.read ? '' : 'unread'}" data-id="${notification.id}">
                <div class="notification-icon ${notification.type}">
                    <i class="fas fa-${this.getNotificationIcon(notification.type)}"></i>
                </div>
                <div class="notification-content">
                    <div class="notification-title">${notification.title}</div>
                    <div class="notification-message">${notification.message}</div>
                    <div class="notification-time">${this.formatTimeAgo(notification.timestamp)}</div>
                </div>
            </div>
        `).join('');
    }

    /**
     * Get notification icon based on type
     */
    getNotificationIcon(type) {
        const icons = {
            appointment: 'calendar-check',
            result: 'vial',
            message: 'envelope',
            system: 'cog',
            security: 'shield-alt'
        };
        return icons[type] || 'bell';
    }

    /**
     * Format timestamp to "time ago" format
     */
    formatTimeAgo(timestamp) {
        const now = new Date();
        const time = new Date(timestamp);
        const diffInSeconds = Math.floor((now - time) / 1000);

        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
        return `${Math.floor(diffInSeconds / 86400)} days ago`;
    }

    /**
     * Handle keyboard shortcuts
     */
    handleKeyboardShortcuts(event) {
        // Alt + number keys for navigation
        if (event.altKey) {
            const keyToSection = {
                '1': 'overview',
                '2': 'appointments',
                '3': 'records',
                '4': 'messages',
                '5': 'prescriptions'
            };

            const section = keyToSection[event.key];
            if (section) {
                event.preventDefault();
                this.showSection(section);

                // Update navigation
                const navLink = document.querySelector(`[data-section="${section}"]`);
                if (navLink) {
                    this.updateActiveNavigation(navLink);
                }
            }
        }

        // Escape key to close dropdowns
        if (event.key === 'Escape') {
            this.closeAllDropdowns();
        }
    }

    /**
     * Handle visibility change (tab switching)
     */
    handleVisibilityChange() {
        if (document.hidden) {
            console.log('🔒 Dashboard hidden - Pausing updates');
        } else {
            console.log('👁️ Dashboard visible - Resuming updates');
            this.checkAuthentication();
        }
    }

    /**
     * Handle before page unload
     */
    handleBeforeUnload() {
        console.log('🔄 Dashboard unloading - Cleaning up');

        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
    }

    /**
     * Show notification message
     */
    showNotification(message, type = 'info') {
        // Create notification element
        const notification = document.createElement('div');
        notification.className = `notification-toast ${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <i class="fas fa-${type === 'success' ? 'check-circle' :
                type === 'error' ? 'exclamation-circle' :
                    'info-circle'}"></i>
                <span>${message}</span>
            </div>
            <button class="close-notification">
                <i class="fas fa-times"></i>
            </button>
        `;

        // Add styles
        notification.style.cssText = `
            position: fixed;
            top: 1rem;
            right: 1rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-md);
            padding: 1rem;
            box-shadow: var(--shadow-lg);
            z-index: 1050;
            max-width: 300px;
            animation: slideInRight 0.3s ease-out;
        `;

        // Add to page
        document.body.appendChild(notification);

        // Auto remove after 5 seconds
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);

        // Manual close
        const closeBtn = notification.querySelector('.close-notification');
        closeBtn.addEventListener('click', () => notification.remove());
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showNotification(message, 'error');
    }

    /**
     * Logout user
     */
    async logout() {
        try {
            // Call logout API
            await this.makeAuthenticatedRequest('/api/auth/logout');
        } catch (error) {
            console.error('Logout API call failed:', error);
        } finally {
            // Clear session data
            sessionStorage.removeItem('authToken');
            sessionStorage.removeItem('userInfo');

            // Clear timers
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
            }

            // Redirect to login
            this.redirectToLogin();
        }
    }

    /**
     * Redirect to login page
     */
    redirectToLogin() {
        console.log('🔄 Redirecting to login...');

        // Clear any existing session data
        sessionStorage.removeItem('authToken');
        sessionStorage.removeItem('userInfo');
        sessionStorage.removeItem('loginData');

        // Redirect to root (which serves index.html - your login page)
        window.location.href = '/';
    }

    /**
     * Placeholder methods for section-specific data loading
     */
    async loadAppointmentsData() {
        console.log('📅 Loading appointments data...');
        // Implementation would load appointments from API
    }

    async loadRecordsData() {
        console.log('📄 Loading medical records data...');
        // Implementation would load records from API
    }

    async loadMessagesData() {
        console.log('💬 Loading messages data...');
        // Implementation would load messages from API
    }

    async loadPrescriptionsData() {
        console.log('💊 Loading prescriptions data...');
        // Implementation would load prescriptions from API
    }
}

// Global functions for onclick handlers
function navigateToSection(sectionName) {
    if (window.dashboardManager) {
        window.dashboardManager.showSection(sectionName);

        // Update navigation
        const navLink = document.querySelector(`[data-section="${sectionName}"]`);
        if (navLink) {
            window.dashboardManager.updateActiveNavigation(navLink);
        }
    }
}

function toggleNotifications() {
    if (window.dashboardManager) {
        window.dashboardManager.toggleNotifications();
    }
}

function toggleUserMenu() {
    if (window.dashboardManager) {
        window.dashboardManager.toggleUserMenu();
    }
}

function extendSession() {
    if (window.dashboardManager) {
        window.dashboardManager.extendSession();
    }
}

function handleLogout() {
    if (window.dashboardManager) {
        window.dashboardManager.logout();
    }
}

// Placeholder functions for various actions
function scheduleAppointment() {
    alert('Schedule Appointment functionality would be implemented here.');
}

function requestRecords() {
    alert('Request Records functionality would be implemented here.');
}

function composeMessage() {
    alert('Compose Message functionality would be implemented here.');
}

function requestRefill() {
    alert('Request Refill functionality would be implemented here.');
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.dashboardManager = new DashboardManager();
});

// Add CSS for notification toast
const style = document.createElement('style');
style.textContent = `
    .notification-toast {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
    }
    
    .notification-toast .notification-content {
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .notification-toast.success {
        border-left: 4px solid var(--success-color);
    }
    
    .notification-toast.error {
        border-left: 4px solid var(--danger-color);
    }
    
    .notification-toast.info {
        border-left: 4px solid var(--info-color);
    }
    
    .close-notification {
        background: none;
        border: none;
        color: var(--text-secondary);
        cursor: pointer;
        padding: 0.25rem;
        border-radius: var(--radius-sm);
        transition: var(--transition);
    }
    
    .close-notification:hover {
        color: var(--text-primary);
        background: var(--bg-secondary);
    }
    
    @keyframes slideInRight {
        from {
            opacity: 0;
            transform: translateX(100%);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
`;
document.head.appendChild(style);

console.log('🏥 Dashboard system loaded successfully');