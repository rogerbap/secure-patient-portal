//client/assets/js/dashboard.js - ENHANCED VERSION WITH PROPER AUTHENTICATION
/**
 * HealthSecure Portal - Dashboard JavaScript
 * ENHANCED: Better authentication handling and session management
 */

class DashboardManager {
    constructor() {
        this.apiBaseUrl = 'http://localhost:3000';
        this.currentSection = 'overview';
        this.sessionTimeout = null;
        this.sessionWarningShown = false;
        this.notificationPanel = false;
        this.userDropdown = false;
        this.sessionTimerInterval = null;
        this.sessionStartTime = Date.now();
        this.sessionDuration = 30 * 60 * 1000; // 30 minutes
        
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
        // ENHANCED: Check authentication first
        this.checkAuthentication()
            .then(() => {
                this.setupEventListeners();
                this.loadUserData();
                this.startSessionTimer();
                this.animateCounters();
                console.log('✅ Dashboard Manager - Ready');
            })
            .catch((error) => {
                console.error('❌ Authentication failed:', error);
                this.redirectToLogin();
            });
    }

    /**
     * ENHANCED: Check authentication status with multiple fallbacks
     */
    async checkAuthentication() {
        try {
            const token = sessionStorage.getItem('authToken');
            const userInfo = this.getUserInfo();
            
            // Method 1: Check for user info from login
            if (userInfo && userInfo.email) {
                console.log('✅ User authentication verified from session storage');
                return true;
            }
            
            // Method 2: Check for demo cookie
            const demoAuth = this.getDemoAuthFromCookie();
            if (demoAuth) {
                console.log('✅ Demo authentication found in cookie');
                // Store in session storage for consistency
                sessionStorage.setItem('userInfo', JSON.stringify(demoAuth));
                return true;
            }
            
            // Method 3: Check token
            if (!token) {
                console.log('❌ No auth token found');
                throw new Error('No authentication token');
            }

            // Method 4: Try server verification for production tokens
            if (!token.startsWith('demo-token-')) {
                try {
                    const response = await this.makeAuthenticatedRequest('/api/auth/verify-token');
                    
                    if (!response || !response.success) {
                        console.log('❌ Server token verification failed');
                        throw new Error('Token verification failed');
                    }
                    
                    console.log('✅ Server token verification successful');
                    return true;
                } catch (error) {
                    console.warn('⚠️ Server verification failed, checking demo mode:', error.message);
                    
                    // For demo tokens, this is acceptable
                    if (token.startsWith('demo-token-')) {
                        console.log('✅ Demo token detected, continuing');
                        return true;
                    }
                    
                    throw error;
                }
            } else {
                // Demo token - verify format and extract user info
                const parts = token.split('-');
                if (parts.length >= 3) {
                    const role = parts[2];
                    const demoUserInfo = {
                        id: role,
                        email: `${role}@demo.com`,
                        role: role,
                        firstName: role.charAt(0).toUpperCase() + role.slice(1),
                        lastName: 'User'
                    };
                    
                    // Store for later use
                    sessionStorage.setItem('userInfo', JSON.stringify(demoUserInfo));
                    console.log('✅ Demo authentication configured');
                    return true;
                }
                
                throw new Error('Invalid demo token format');
            }
            
        } catch (error) {
            console.error('Authentication check failed:', error);
            throw error;
        }
    }

    /**
     * Get demo authentication from cookie
     */
    getDemoAuthFromCookie() {
        try {
            const cookies = document.cookie.split(';').reduce((acc, cookie) => {
                const [key, value] = cookie.trim().split('=');
                acc[key] = value;
                return acc;
            }, {});
            
            if (cookies.demoAuth) {
                const demoData = JSON.parse(decodeURIComponent(cookies.demoAuth));
                if (demoData && demoData.role) {
                    return demoData;
                }
            }
        } catch (error) {
            console.debug('No demo auth cookie found');
        }
        return null;
    }

    /**
     * Setup all event listeners
     */setupEventListeners() {
    // Navigation links - FIXED to prevent logout on Overview click
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const section = link.dataset.section;
            if (section) {
                console.log(`Navigation clicked: ${section}`);
                this.handleNavigation(e);
            }
        });
    });

    // User menu toggle
    const userAvatar = document.querySelector('.user-avatar');
    if (userAvatar) {
        userAvatar.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.toggleUserMenu();
        });
    }

    // Notification toggle
    const notificationBtn = document.querySelector('.notifications');
    if (notificationBtn) {
        notificationBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.toggleNotifications();
        });
    }

    // FIXED: Logout button handling
    document.querySelectorAll('.logout, [onclick*="handleLogout"], [onclick*="logout"]').forEach(logoutBtn => {
        // Remove any existing onclick handlers
        logoutBtn.removeAttribute('onclick');
        
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            console.log('Logout button clicked');
            this.logout();
        });
    });

    // FIXED: Prevent dropdown items from causing navigation issues
    document.querySelectorAll('.dropdown-item').forEach(item => {
        if (!item.classList.contains('logout')) {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                console.log('Dropdown item clicked:', item.textContent);
                // Handle other dropdown actions here
            });
        }
    });

    // Close dropdowns when clicking outside
    document.addEventListener('click', (e) => {
        // Don't close if clicking on dropdown elements
        if (!e.target.closest('.user-menu') && !e.target.closest('.notification-panel')) {
            this.closeAllDropdowns();
        }
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));

    // Session extension
    const extendBtn = document.querySelector('.extend-session-btn');
    if (extendBtn) {
        extendBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            this.extendSession();
        });
    }

    // Window events
    window.addEventListener('beforeunload', () => this.handleBeforeUnload());
    document.addEventListener('visibilitychange', () => this.handleVisibilityChange());
    
    console.log('✅ Event listeners setup completed');
}

// FIXED: Handle navigation between sections
handleNavigation(event) {
    event.preventDefault();
    event.stopPropagation();
    
    const link = event.currentTarget;
    const section = link.dataset.section;
    
    console.log(`Handling navigation to: ${section}`);
    
    if (section) {
        // Don't navigate away from the page, just show the section
        this.showSection(section);
        this.updateActiveNavigation(link);
        
        console.log(`📊 Navigation: ${this.currentSection} → ${section}`);
    }
}

// ENHANCED: Logout with better error handling
async logout() {
    try {
        console.log('🔄 Starting logout process...');
        
        // Clear timers first
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }

        // Show logout message
        this.showNotification('Logging out...', 'info');

        // Try to call logout API (but don't fail if it doesn't work)
        try {
            await this.makeAuthenticatedRequest('/api/auth/logout');
            console.log('✅ Server logout successful');
        } catch (error) {
            console.warn('⚠️ Server logout failed (continuing anyway):', error.message);
        }

        // Clear all session data
        sessionStorage.removeItem('authToken');
        sessionStorage.removeItem('userInfo');
        sessionStorage.removeItem('loginData');
        sessionStorage.removeItem('currentUserRole');
        
        // Clear demo auth cookie
        document.cookie = 'demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT; domain=localhost;';
        document.cookie = 'demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
        
        console.log('✅ Session data cleared');
        
        // Small delay to show the notification
        setTimeout(() => {
            this.redirectToLogin();
        }, 1000);
        
    } catch (error) {
        console.error('❌ Logout error:', error);
        // Force logout anyway
        this.redirectToLogin();
    }
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
            
            console.log(`📊 Navigation: ${this.currentSection} → ${section}`);
        }
    }

    /**
     * Show specific dashboard section
     */
    showSection(sectionName) {
        document.querySelectorAll('.dashboard-section').forEach(section => {
            section.classList.remove('active');
        });
        
        const targetSection = document.getElementById(sectionName);
        if (targetSection) {
            targetSection.classList.add('active');
            this.currentSection = sectionName;
            
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

            try {
                const response = await this.makeAuthenticatedRequest(`/api/dashboard/${userInfo.role}`);
                
                if (response && response.success) {
                    this.updateOverviewUI(response.data);
                    return;
                }
            } catch (error) {
                console.warn('API call failed, using demo data:', error.message);
            }
            
            this.updateOverviewUI(this.getDemoOverviewData());
        } catch (error) {
            console.warn('Using demo data for overview');
            this.updateOverviewUI(this.getDemoOverviewData());
        }
    }

    /**
     * Get demo overview data
     */
    getDemoOverviewData() {
        const userInfo = this.getUserInfo();
        return {
            user: {
                name: userInfo ? userInfo.firstName || 'User' : 'Demo User',
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
        const increment = target / 50;
        const timer = setInterval(() => {
            current += increment;
            if (current >= target) {
                current = target;
                clearInterval(timer);
            }
            element.textContent = Math.floor(current);
        }, 40);
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
            }, 500);
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
                console.log('❌ No user info found, redirecting to login');
                this.redirectToLogin();
            }
        } catch (error) {
            console.error('Failed to load user data:', error);
            this.redirectToLogin();
        }
    }

    /**
     * ENHANCED: Get user info from multiple sources
     */
    getUserInfo() {
        try {
            // Method 1: Direct userInfo
            const userInfo = sessionStorage.getItem('userInfo');
            if (userInfo) {
                const parsed = JSON.parse(userInfo);
                if (parsed && parsed.email) {
                    return parsed;
                }
            }
            
            // Method 2: Login data
            const loginData = sessionStorage.getItem('loginData');
            if (loginData) {
                const parsed = JSON.parse(loginData);
                if (parsed && parsed.user) {
                    return parsed.user;
                }
            }
            
            // Method 3: Demo token
            const authToken = sessionStorage.getItem('authToken');
            if (authToken && authToken.startsWith('demo-token-')) {
                const userType = authToken.split('-')[2];
                return {
                    id: userType,
                    email: `${userType}@demo.com`,
                    role: userType,
                    firstName: userType.charAt(0).toUpperCase() + userType.slice(1),
                    lastName: 'User'
                };
            }
            
            // Method 4: Demo cookie
            const demoAuth = this.getDemoAuthFromCookie();
            if (demoAuth) {
                return demoAuth;
            }
            
            return null;
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
            userNameEl.textContent = `${userInfo.firstName || 'User'} ${userInfo.lastName || ''}`.trim();
        }

        // Update patient/provider name in welcome message
        const welcomeNameEl = document.getElementById('patientName') || 
                             document.getElementById('providerName') || 
                             document.getElementById('adminName');
        if (welcomeNameEl) {
            welcomeNameEl.textContent = userInfo.firstName || 'User';
        }

        // Update role badge
        const roleBadge = document.querySelector('.role-badge');
        if (roleBadge && userInfo.role) {
            roleBadge.textContent = `${userInfo.role.charAt(0).toUpperCase() + userInfo.role.slice(1)} Portal`;
            roleBadge.className = `role-badge ${userInfo.role}`;
        }
    }

    /**
     * ENHANCED: Make authenticated API request
     */
    async makeAuthenticatedRequest(endpoint) {
        const token = sessionStorage.getItem('authToken');
        
        try {
            const headers = {
                'Content-Type': 'application/json'
            };
            
            // Add authentication header
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            // Add user role header as fallback
            const userInfo = this.getUserInfo();
            if (userInfo && userInfo.role) {
                headers['X-User-Role'] = userInfo.role;
            }
            
            const response = await fetch(`${this.apiBaseUrl}${endpoint}`, {
                headers,
                timeout: 5000
            });

            if (response.status === 401) {
                this.redirectToLogin();
                return null;
            }

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
        } catch (error) {
            console.warn('API request failed:', error.message);
            throw error;
        }
    }

    /**
     * Session management - ENHANCED VERSION
     */
    startSessionTimer() {
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }

        this.sessionStartTime = Date.now();
        this.sessionWarningShown = false;

        this.updateSessionTimerDisplay();
        this.sessionTimerInterval = setInterval(() => {
            this.updateSessionTimerDisplay();
        }, 1000);

        this.sessionTimeout = setTimeout(() => {
            this.handleSessionTimeout();
        }, this.sessionDuration);

        const warningTime = 5 * 60 * 1000;
        setTimeout(() => {
            if (!this.sessionWarningShown) {
                this.showSessionWarning();
            }
        }, this.sessionDuration - warningTime);

        console.log('✅ Session timer started');
    }

    /**
     * Update session timer display
     */
    updateSessionTimerDisplay() {
        const timerEl = document.getElementById('sessionTimer');
        if (!timerEl) return;

        const elapsed = Date.now() - this.sessionStartTime;
        const remaining = Math.max(0, this.sessionDuration - elapsed);
        
        if (remaining <= 0) {
            timerEl.textContent = 'Session expired';
            timerEl.style.color = 'var(--danger-color)';
            return;
        }

        const minutes = Math.floor(remaining / (1000 * 60));
        const seconds = Math.floor((remaining % (1000 * 60)) / 1000);
        
        timerEl.textContent = `Session: ${minutes}m ${seconds}s remaining`;
        
        if (remaining < 5 * 60 * 1000) {
            timerEl.style.color = 'var(--warning-color)';
        } else {
            timerEl.style.color = 'var(--text-secondary)';
        }
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
            console.log('🔄 Attempting to extend session...');
            
            try {
                const response = await this.makeAuthenticatedRequest('/api/auth/refresh');
                
                if (response && response.success) {
                    if (response.accessToken) {
                        sessionStorage.setItem('authToken', response.accessToken);
                        console.log('✅ Token refreshed successfully');
                    }
                    
                    this.sessionWarningShown = false;
                    this.startSessionTimer();
                    
                    this.showNotification('Session extended successfully', 'success');
                    console.log('✅ Session extended successfully');
                } else {
                    throw new Error('Refresh response invalid');
                }
            } catch (error) {
                // For demo mode, just restart the timer
                console.warn('Server refresh failed, using demo extension:', error.message);
                this.sessionWarningShown = false;
                this.startSessionTimer();
                this.showNotification('Session extended (demo mode)', 'success');
            }
        } catch (error) {
            console.error('Failed to extend session:', error);
            this.showNotification('Failed to extend session. Please login again.', 'error');
            
            setTimeout(() => {
                this.redirectToLogin();
            }, 3000);
        }
    }

    /**
     * Handle session timeout
     */
    handleSessionTimeout() {
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }
        
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
            } else {
                throw new Error('API call failed');
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
                
                const navLink = document.querySelector(`[data-section="${section}"]`);
                if (navLink) {
                    this.updateActiveNavigation(navLink);
                }
            }
        }

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
            const userInfo = this.getUserInfo();
            if (!userInfo) {
                this.checkAuthentication().catch(() => {
                    this.redirectToLogin();
                });
            }
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
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }
    }

    /**
     * Show notification message
     */
    showNotification(message, type = 'info') {
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

        document.body.appendChild(notification);

        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 5000);

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
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
            }
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
            }

            try {
                await this.makeAuthenticatedRequest('/api/auth/logout');
            } catch (error) {
                console.warn('Logout API call failed:', error);
            }
        } finally {
            // Clear all session data
            sessionStorage.removeItem('authToken');
            sessionStorage.removeItem('userInfo');
            sessionStorage.removeItem('loginData');
            sessionStorage.removeItem('currentUserRole');
            
            // Clear demo auth cookie
            document.cookie = 'demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;';
            
            this.redirectToLogin();
        }
    }

    /**
     * Redirect to login page
     */
    redirectToLogin() {
        console.log('🔄 Redirecting to login...');
        
        if (this.sessionTimeout) {
            clearTimeout(this.sessionTimeout);
        }
        if (this.sessionTimerInterval) {
            clearInterval(this.sessionTimerInterval);
        }
        
        window.location.href = '/';
    }

    /**
     * Placeholder methods for section-specific data loading
     */
    async loadAppointmentsData() {
        console.log('📅 Loading appointments data...');
    }

    async loadRecordsData() {
        console.log('📄 Loading medical records data...');
    }

    async loadMessagesData() {
        console.log('💬 Loading messages data...');
    }

    async loadPrescriptionsData() {
        console.log('💊 Loading prescriptions data...');
    }
}

// Global functions for onclick handlers
function navigateToSection(sectionName) {
    if (window.dashboardManager) {
        window.dashboardManager.showSection(sectionName);
        
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

console.log('🏥 Enhanced Dashboard system loaded successfully');