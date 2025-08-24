//client/assets/js/dashboard.js
/**
 * HealthSecure Portal - Dashboard JavaScript
 * FIXED: Production-compatible version with proper event delegation and error handling
 */

class DashboardManager {
    constructor() {
        // Enhanced API base URL detection for production
        this.apiBaseUrl = this.getApiBaseUrl();
        this.currentSection = 'overview';
        this.sessionTimeout = null;
        this.sessionWarningShown = false;
        this.notificationPanel = false;
        this.userDropdown = false;
        this.sessionTimerInterval = null;
        this.sessionStartTime = Date.now();
        this.sessionDuration = 30 * 60 * 1000; // 30 minutes
        this.eventListeners = []; // Track event listeners for cleanup
        
        this.init();
    }

    /**
     * FIXED: Enhanced API base URL detection for production
     */
    getApiBaseUrl() {
        const hostname = window.location.hostname;
        const protocol = window.location.protocol;
        const port = window.location.port;
        
        console.log('🔍 Environment detection:', { hostname, protocol, port });
        
        // Production detection (Render, Heroku, etc.)
        if (hostname.includes('.onrender.com') || 
            hostname.includes('.herokuapp.com') ||
            hostname.includes('.vercel.app') ||
            hostname.includes('.netlify.app') ||
            (!hostname.includes('localhost') && !hostname.includes('127.0.0.1'))) {
            
            const apiUrl = `${protocol}//${hostname}`;
            console.log('🌐 Production environment detected, API URL:', apiUrl);
            return apiUrl;
        }
        
        // Local development
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            if (port === '8080') {
                // Frontend dev server on 8080, API on 3000
                const apiUrl = 'http://localhost:3000';
                console.log('🛠️ Dev server detected, API URL:', apiUrl);
                return apiUrl;
            } else {
                // Same server
                const apiUrl = `${protocol}//${hostname}:${port || 3000}`;
                console.log('🏠 Local server, API URL:', apiUrl);
                return apiUrl;
            }
        }
        
        // Fallback
        const fallbackUrl = `${protocol}//${hostname}`;
        console.log('🔄 Fallback API URL:', fallbackUrl);
        return fallbackUrl;
    }

    /**
     * Initialize the dashboard with enhanced error handling
     */
    init() {
        console.log('🏥 Dashboard Manager - Initializing...');
        console.log('🌐 API Base URL:', this.apiBaseUrl);
        
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            this.addEventListenerTracked(document, 'DOMContentLoaded', () => this.onDOMReady());
        } else {
            // DOM already loaded
            setTimeout(() => this.onDOMReady(), 100);
        }
    }

    /**
     * Handle DOM ready state with comprehensive setup
     */
    async onDOMReady() {
        try {
            console.log('📱 DOM Ready - Starting setup...');
            
            // Check authentication first
            await this.checkAuthentication();
            
            // Setup all event listeners
            this.setupEventListeners();
            
            // Load user data
            await this.loadUserData();
            
            // Start session management
            this.startSessionTimer();
            
            // Animate counters
            setTimeout(() => this.animateCounters(), 500);
            
            console.log('✅ Dashboard Manager - Ready');
            
        } catch (error) {
            console.error('❌ Dashboard setup failed:', error);
            this.handleSetupError(error);
        }
    }

    /**
     * Enhanced authentication check with multiple fallback methods
     */
    async checkAuthentication() {
        console.log('🔐 Checking authentication...');
        
        try {
            // Method 1: Check session storage user info
            const userInfo = this.getUserInfo();
            if (userInfo && userInfo.email) {
                console.log('✅ Authentication verified from session storage');
                return true;
            }
            
            // Method 2: Check demo cookie
            const demoAuth = this.getDemoAuthFromCookie();
            if (demoAuth && demoAuth.role) {
                console.log('✅ Demo authentication found in cookie');
                sessionStorage.setItem('userInfo', JSON.stringify(demoAuth));
                return true;
            }
            
            // Method 3: Check auth token
            const token = sessionStorage.getItem('authToken');
            if (token) {
                if (token.startsWith('demo-token-')) {
                    // Demo token - extract user info
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
                        
                        sessionStorage.setItem('userInfo', JSON.stringify(demoUserInfo));
                        console.log('✅ Demo authentication configured from token');
                        return true;
                    }
                } else {
                    // Try server verification for production tokens
                    try {
                        const response = await this.makeAuthenticatedRequest('/api/auth/verify-token');
                        if (response && response.success) {
                            console.log('✅ Server token verification successful');
                            return true;
                        }
                    } catch (verifyError) {
                        console.warn('⚠️ Server token verification failed:', verifyError.message);
                    }
                }
            }
            
            console.log('❌ No valid authentication found');
            throw new Error('No authentication found');
            
        } catch (error) {
            console.error('Authentication check failed:', error);
            throw error;
        }
    }

    /**
     * Enhanced event listener setup with better delegation
     */
    setupEventListeners() {
        console.log('🎯 Setting up event listeners...');
        
        // Use document-level event delegation for better production compatibility
        this.addEventListenerTracked(document, 'click', this.handleDocumentClick.bind(this));
        this.addEventListenerTracked(document, 'keydown', this.handleKeyboardShortcuts.bind(this));
        
        // Window events
        this.addEventListenerTracked(window, 'beforeunload', this.handleBeforeUnload.bind(this));
        this.addEventListenerTracked(document, 'visibilitychange', this.handleVisibilityChange.bind(this));
        
        // Close dropdowns when clicking outside (use capture phase)
        this.addEventListenerTracked(document, 'click', this.handleOutsideClick.bind(this), true);
        
        console.log('✅ Event listeners setup completed');
    }

    /**
     * FIXED: Centralized click handler with proper event delegation
     */
    handleDocumentClick(event) {
        const target = event.target;
        const closest = target.closest ? target.closest.bind(target) : () => null;
        
        try {
            // Navigation links
            const navLink = closest('.nav-link');
            if (navLink) {
                event.preventDefault();
                event.stopPropagation();
                const section = navLink.dataset.section;
                if (section) {
                    console.log(`🎯 Navigation clicked: ${section}`);
                    this.handleNavigation(section, navLink);
                }
                return;
            }

            // User avatar/menu toggle - FIXED with better selector
            const userAvatar = closest('.user-avatar');
            if (userAvatar) {
                event.preventDefault();
                event.stopPropagation();
                console.log('👤 User menu toggle clicked');
                this.toggleUserMenu();
                return;
            }

            // Notification button
            const notificationBtn = closest('.notifications');
            if (notificationBtn) {
                event.preventDefault();
                event.stopPropagation();
                console.log('🔔 Notification button clicked');
                this.toggleNotifications();
                return;
            }

            // Logout button - FIXED with multiple selectors
            const logoutBtn = closest('.logout') || 
                             closest('[onclick*="logout"]') ||
                             closest('[onclick*="handleLogout"]') ||
                             target.textContent?.toLowerCase().includes('logout') && closest('a, button');
            
            if (logoutBtn) {
                event.preventDefault();
                event.stopPropagation();
                console.log('🚪 Logout button clicked');
                this.logout();
                return;
            }

            // Session extension button
            const extendBtn = closest('.extend-session-btn');
            if (extendBtn) {
                event.preventDefault();
                event.stopPropagation();
                console.log('⏱️ Extend session clicked');
                this.extendSession();
                return;
            }

            // Action tiles and quick actions
            const actionTile = closest('.action-tile');
            if (actionTile) {
                event.preventDefault();
                event.stopPropagation();
                
                // Check for data attributes or onclick handlers
                const actionType = actionTile.dataset.action || 
                                 actionTile.getAttribute('onclick') ||
                                 actionTile.querySelector('.action-label')?.textContent?.toLowerCase();
                
                console.log('🎬 Action tile clicked:', actionType);
                this.handleActionTile(actionType, actionTile);
                return;
            }

            // View all buttons
            const viewAllBtn = closest('.view-all-btn');
            if (viewAllBtn) {
                event.preventDefault();
                console.log('👁️ View all button clicked');
                // Handle view all functionality here
                return;
            }

            // Generic button handling for any missed buttons
            const button = closest('button[onclick], a[onclick]');
            if (button) {
                const onclickAttr = button.getAttribute('onclick');
                if (onclickAttr) {
                    console.log('🔘 Generic onclick button:', onclickAttr);
                    
                    // Safely execute onclick functions
                    try {
                        if (onclickAttr.includes('logout') || onclickAttr.includes('handleLogout')) {
                            event.preventDefault();
                            event.stopPropagation();
                            this.logout();
                            return;
                        }
                        
                        if (onclickAttr.includes('toggleUserMenu')) {
                            event.preventDefault();
                            event.stopPropagation();
                            this.toggleUserMenu();
                            return;
                        }
                        
                        if (onclickAttr.includes('toggleNotifications')) {
                            event.preventDefault();
                            event.stopPropagation();
                            this.toggleNotifications();
                            return;
                        }
                        
                        if (onclickAttr.includes('extendSession')) {
                            event.preventDefault();
                            event.stopPropagation();
                            this.extendSession();
                            return;
                        }
                    } catch (execError) {
                        console.warn('⚠️ Error executing onclick:', execError);
                    }
                }
            }

        } catch (clickError) {
            console.warn('⚠️ Click handler error:', clickError);
        }
    }

    /**
     * Handle outside clicks to close dropdowns
     */
    handleOutsideClick(event) {
        const target = event.target;
        
        // Don't close if clicking inside dropdown elements
        if (target.closest('.user-menu') || target.closest('.notification-panel')) {
            return;
        }
        
        // Close all dropdowns
        this.closeAllDropdowns();
    }

    /**
     * Enhanced navigation handler
     */
    handleNavigation(section, linkElement) {
        console.log(`🧭 Navigating to section: ${section}`);
        
        try {
            // Show the section
            this.showSection(section);
            
            // Update active navigation
            this.updateActiveNavigation(linkElement);
            
            // Load section data
            this.loadSectionData(section);
            
        } catch (navError) {
            console.error('Navigation error:', navError);
            this.showError('Navigation failed. Please try again.');
        }
    }

    /**
     * Handle action tile clicks
     */
    handleActionTile(actionType, tileElement) {
        console.log(`🎭 Handling action: ${actionType}`);
        
        try {
            if (typeof actionType === 'string') {
                const action = actionType.toLowerCase();
                
                if (action.includes('appointment') || action.includes('schedule')) {
                    this.showSection('appointments');
                } else if (action.includes('message') || action.includes('compose')) {
                    this.showSection('messages');
                } else if (action.includes('record') || action.includes('download')) {
                    this.showSection('records');
                } else if (action.includes('prescription') || action.includes('refill')) {
                    this.showSection('prescriptions');
                } else if (action.includes('user') || action.includes('manage')) {
                    this.showSection('users');
                } else if (action.includes('security') || action.includes('logs')) {
                    this.showSection('security');
                } else if (action.includes('system') || action.includes('config')) {
                    this.showSection('system');
                } else if (action.includes('report') || action.includes('analytics')) {
                    this.showSection('reports');
                } else {
                    // Generic action notification
                    this.showNotification(`${actionType} functionality coming soon!`, 'info');
                }
            }
            
        } catch (actionError) {
            console.error('Action tile error:', actionError);
            this.showError('Action failed. Please try again.');
        }
    }

    /**
     * FIXED: Enhanced logout with better error handling and cleanup
     */
    async logout() {
        console.log('🔄 Starting logout process...');
        
        try {
            // Clear timers immediately
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
                this.sessionTimeout = null;
            }
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
                this.sessionTimerInterval = null;
            }

            // Show logout notification
            this.showNotification('Logging out...', 'info');

            // Try to call logout API (but don't fail if it doesn't work)
            try {
                const response = await this.makeAuthenticatedRequest('/api/auth/logout');
                if (response && response.success) {
                    console.log('✅ Server logout successful');
                }
            } catch (apiError) {
                console.warn('⚠️ Server logout failed (continuing anyway):', apiError.message);
            }

            // Clear all authentication data
            this.clearAuthenticationData();

            console.log('✅ Authentication data cleared');
            
            // Clean up event listeners
            this.cleanup();
            
            // Small delay to show notification
            setTimeout(() => {
                this.redirectToLogin();
            }, 1000);
            
        } catch (error) {
            console.error('❌ Logout error:', error);
            // Force logout anyway
            this.clearAuthenticationData();
            this.redirectToLogin();
        }
    }

    /**
     * Clear all authentication data
     */
    clearAuthenticationData() {
        try {
            // Clear session storage
            sessionStorage.removeItem('authToken');
            sessionStorage.removeItem('userInfo');
            sessionStorage.removeItem('loginData');
            sessionStorage.removeItem('currentUserRole');
            
            // Clear all demo cookies with multiple approaches for production compatibility
            const cookieNames = ['demoAuth'];
            const domains = [window.location.hostname, 'localhost', ''];
            const paths = ['/', '/dashboard', '/api'];
            
            cookieNames.forEach(name => {
                domains.forEach(domain => {
                    paths.forEach(path => {
                        // Clear with domain
                        if (domain) {
                            document.cookie = `${name}=; path=${path}; expires=Thu, 01 Jan 1970 00:00:01 GMT; domain=${domain};`;
                        }
                        // Clear without domain
                        document.cookie = `${name}=; path=${path}; expires=Thu, 01 Jan 1970 00:00:01 GMT;`;
                    });
                });
            });
            
            // Clear session if exists
            if (window.sessionStorage) {
                try {
                    sessionStorage.clear();
                } catch (storageError) {
                    console.warn('Session storage clear failed:', storageError);
                }
            }
            
            console.log('🧹 Authentication data cleared');
            
        } catch (error) {
            console.warn('⚠️ Error clearing authentication data:', error);
        }
    }

    /**
     * Enhanced user info retrieval with multiple fallback methods
     */
    getUserInfo() {
        try {
            // Method 1: Direct userInfo from session storage
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
            
            // Method 3: Demo token extraction
            const authToken = sessionStorage.getItem('authToken');
            if (authToken && authToken.startsWith('demo-token-')) {
                const parts = authToken.split('-');
                if (parts.length >= 3) {
                    const role = parts[2];
                    return {
                        id: role,
                        email: `${role}@demo.com`,
                        role: role,
                        firstName: role.charAt(0).toUpperCase() + role.slice(1),
                        lastName: 'User'
                    };
                }
            }
            
            // Method 4: Demo cookie
            const demoAuth = this.getDemoAuthFromCookie();
            if (demoAuth) {
                return demoAuth;
            }
            
            return null;
            
        } catch (error) {
            console.error('Error getting user info:', error);
            return null;
        }
    }

    /**
     * Get demo authentication from cookie with enhanced parsing
     */
    getDemoAuthFromCookie() {
        try {
            if (!document.cookie) return null;
            
            const cookies = document.cookie.split(';').reduce((acc, cookie) => {
                const [key, value] = cookie.trim().split('=');
                if (key && value) {
                    acc[key] = decodeURIComponent(value);
                }
                return acc;
            }, {});
            
            if (cookies.demoAuth) {
                const demoData = JSON.parse(cookies.demoAuth);
                if (demoData && demoData.role && demoData.email) {
                    console.log('🍪 Demo auth found in cookie:', demoData.role);
                    return demoData;
                }
            }
            
        } catch (error) {
            console.debug('Cookie parsing failed:', error);
        }
        
        return null;
    }

    /**
     * Enhanced authenticated API request with better error handling
     */
    async makeAuthenticatedRequest(endpoint, options = {}) {
        try {
            const token = sessionStorage.getItem('authToken');
            const userInfo = this.getUserInfo();
            
            const headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...options.headers
            };
            
            // Add authentication header
            if (token) {
                headers['Authorization'] = `Bearer ${token}`;
            }
            
            // Add user role header as fallback
            if (userInfo && userInfo.role) {
                headers['X-User-Role'] = userInfo.role;
            }
            
            const requestOptions = {
                method: 'GET',
                headers,
                credentials: 'include',
                ...options
            };
            
            console.log(`📡 API Request: ${this.apiBaseUrl}${endpoint}`);
            
            const response = await fetch(`${this.apiBaseUrl}${endpoint}`, requestOptions);
            
            // Handle authentication errors
            if (response.status === 401 || response.status === 403) {
                console.warn('🔒 Authentication failed, redirecting to login');
                this.redirectToLogin();
                return null;
            }
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log(`✅ API Response received for ${endpoint}`);
            return data;
            
        } catch (error) {
            console.warn(`⚠️ API request failed for ${endpoint}:`, error.message);
            throw error;
        }
    }

    /**
     * Enhanced redirect to login with production compatibility
     */
    redirectToLogin() {
        console.log('🔄 Redirecting to login...');
        
        try {
            // Clean up before redirect
            this.cleanup();
            
            // Enhanced redirect logic for different environments
            const hostname = window.location.hostname;
            const protocol = window.location.protocol;
            const port = window.location.port;
            
            let targetUrl;
            
            // Production environment
            if (hostname.includes('.onrender.com') || 
                hostname.includes('.herokuapp.com') ||
                hostname.includes('.vercel.app') ||
                hostname.includes('.netlify.app') ||
                (!hostname.includes('localhost') && !hostname.includes('127.0.0.1'))) {
                
                targetUrl = `${protocol}//${hostname}/`;
            }
            // Development with separate frontend server
            else if (hostname === 'localhost' && port === '8080') {
                targetUrl = 'http://localhost:8080/';
            }
            // Local development same server
            else {
                targetUrl = '/';
            }
            
            console.log(`🎯 Redirecting to: ${targetUrl}`);
            
            // Use replace to prevent back navigation
            window.location.replace(targetUrl);
            
        } catch (error) {
            console.error('❌ Redirect failed:', error);
            // Fallback
            window.location.href = '/';
        }
    }

    /**
     * Track event listeners for proper cleanup
     */
    addEventListenerTracked(element, event, handler, options = false) {
        element.addEventListener(event, handler, options);
        this.eventListeners.push({ element, event, handler, options });
    }

    /**
     * Clean up event listeners and timers
     */
    cleanup() {
        console.log('🧹 Cleaning up dashboard...');
        
        try {
            // Remove tracked event listeners
            this.eventListeners.forEach(({ element, event, handler, options }) => {
                try {
                    element.removeEventListener(event, handler, options);
                } catch (error) {
                    console.warn('Event listener cleanup failed:', error);
                }
            });
            this.eventListeners = [];
            
            // Clear timers
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
                this.sessionTimeout = null;
            }
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
                this.sessionTimerInterval = null;
            }
            
            // Close dropdowns
            this.closeAllDropdowns();
            
        } catch (error) {
            console.warn('Cleanup failed:', error);
        }
    }

    /**
     * Enhanced error handler for setup failures
     */
    handleSetupError(error) {
        console.error('Dashboard setup error:', error);
        
        // Check if it's an authentication error
        if (error.message.includes('authentication') || 
            error.message.includes('token') ||
            error.message.includes('unauthorized')) {
            
            console.log('🔒 Authentication error detected, redirecting to login');
            this.redirectToLogin();
            return;
        }
        
        // Show error notification
        this.showError('Dashboard initialization failed. Please refresh the page.');
        
        // Try to continue with limited functionality
        try {
            this.setupEventListeners();
        } catch (listenerError) {
            console.error('Even basic setup failed:', listenerError);
        }
    }

    // ... [Continue with all other methods from the original file] ...

    /**
     * Show specific dashboard section
     */
    showSection(sectionName) {
        try {
            console.log(`📱 Showing section: ${sectionName}`);
            
            // Hide all sections
            document.querySelectorAll('.dashboard-section').forEach(section => {
                section.classList.remove('active');
            });
            
            // Show target section
            const targetSection = document.getElementById(sectionName);
            if (targetSection) {
                targetSection.classList.add('active');
                this.currentSection = sectionName;
                
                // Load section data
                this.loadSectionData(sectionName);
            } else {
                console.warn(`Section not found: ${sectionName}`);
            }
            
        } catch (error) {
            console.error('Show section error:', error);
        }
    }

    /**
     * Update active navigation state
     */
    updateActiveNavigation(activeLink) {
        try {
            // Remove active class from all nav links
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            
            // Add active class to current link
            if (activeLink) {
                activeLink.classList.add('active');
            }
            
        } catch (error) {
            console.error('Navigation update error:', error);
        }
    }

    /**
     * Load section-specific data
     */
    async loadSectionData(sectionName) {
        try {
            console.log(`📊 Loading data for section: ${sectionName}`);
            
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
                case 'users':
                    await this.loadUsersData();
                    break;
                case 'security':
                    await this.loadSecurityData();
                    break;
                case 'system':
                    await this.loadSystemData();
                    break;
                case 'reports':
                    await this.loadReportsData();
                    break;
                default:
                    console.log(`No specific data loader for section: ${sectionName}`);
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

            // Try API call first
            try {
                const response = await this.makeAuthenticatedRequest(`/api/dashboard/${userInfo.role}`);
                if (response && response.success) {
                    this.updateOverviewUI(response.data);
                    return;
                }
            } catch (error) {
                console.warn('API call failed, using demo data:', error.message);
            }
            
            // Fallback to demo data
            this.updateOverviewUI(this.getDemoOverviewData());
            
        } catch (error) {
            console.warn('Using demo data for overview:', error);
            this.updateOverviewUI(this.getDemoOverviewData());
        }
    }

    /**
     * Get demo overview data based on user role
     */
    getDemoOverviewData() {
        const userInfo = this.getUserInfo();
        const role = userInfo?.role || 'patient';
        
        const demoData = {
            patient: {
                user: { name: userInfo?.firstName || 'Patient', memberSince: '2023-01-15' },
                summary: { upcomingAppointments: 2, pendingResults: 1, unreadMessages: 3, prescriptions: 4 }
            },
            provider: {
                user: { name: userInfo?.firstName || 'Doctor', memberSince: '2020-03-10' },
                summary: { todaysAppointments: 12, activePatients: 245, patientMessages: 8, pendingReviews: 15 }
            },
            admin: {
                user: { name: userInfo?.firstName || 'Admin', memberSince: '2019-01-01' },
                summary: { totalUsers: 1247, securityAlerts: 23, systemUptime: 99.8, totalRecords: 45678 }
            }
        };
        
        return demoData[role] || demoData.patient;
    }

    /**
     * Update overview UI with data
     */
    updateOverviewUI(data) {
        try {
            // Update user name
            const userNameElements = [
                document.getElementById('patientName'),
                document.getElementById('providerName'),
                document.getElementById('adminName')
            ].filter(Boolean);
            
            userNameElements.forEach(el => {
                if (data.user && data.user.name) {
                    el.textContent = data.user.name;
                }
            });

            // Update stat counters
            if (data.summary) {
                this.updateStatCounters(data.summary);
            }
            
        } catch (error) {
            console.error('Overview UI update error:', error);
        }
    }

    /**
     * Update stat counters with animation
     */
    updateStatCounters(summary) {
        try {
            const statCards = document.querySelectorAll('.stat-number[data-target]');
            
            statCards.forEach(card => {
                const target = parseInt(card.dataset.target) || 0;
                this.animateCounter(card, target);
            });
            
        } catch (error) {
            console.error('Stat counter update error:', error);
        }
    }

    /**
     * Animate counter to target value
     */
    animateCounter(element, target) {
        try {
            let current = 0;
            const increment = Math.max(1, Math.floor(target / 50));
            const timer = setInterval(() => {
                current += increment;
                if (current >= target) {
                    current = target;
                    clearInterval(timer);
                }
                element.textContent = current;
            }, 40);
            
        } catch (error) {
            console.error('Counter animation error:', error);
            // Fallback: just set the number
            element.textContent = target;
        }
    }

    /**
     * Animate all counters on page load
     */
    animateCounters() {
        try {
            const counters = document.querySelectorAll('.stat-number[data-target]');
            
            counters.forEach(counter => {
                const target = parseInt(counter.dataset.target) || 0;
                setTimeout(() => {
                    this.animateCounter(counter, target);
                }, Math.random() * 500);
            });
            
        } catch (error) {
            console.error('Counter animation setup error:', error);
        }
    }

    /**
     * Load and update user data in UI
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
     * Update user interface with user data
     */
    updateUserUI(userInfo) {
        try {
            // Update user name in header
            const userNameEl = document.getElementById('userName');
            if (userNameEl && userInfo.firstName && userInfo.lastName) {
                userNameEl.textContent = `${userInfo.firstName} ${userInfo.lastName}`.trim();
            }

            // Update role-specific names
            const roleElements = [
                document.getElementById('patientName'),
                document.getElementById('providerName'), 
                document.getElementById('adminName')
            ].filter(Boolean);
            
            roleElements.forEach(el => {
                if (userInfo.firstName) {
                    el.textContent = userInfo.firstName;
                }
            });

            // Update role badge
            const roleBadge = document.querySelector('.role-badge');
            if (roleBadge && userInfo.role) {
                const roleText = userInfo.role.charAt(0).toUpperCase() + userInfo.role.slice(1);
                roleBadge.textContent = `${roleText} Portal`;
                roleBadge.className = `role-badge ${userInfo.role}`;
            }
            
        } catch (error) {
            console.error('User UI update error:', error);
        }
    }

    /**
     * Enhanced session timer with better error handling
     */
    startSessionTimer() {
        try {
            // Clear existing timers
            if (this.sessionTimeout) clearTimeout(this.sessionTimeout);
            if (this.sessionTimerInterval) clearInterval(this.sessionTimerInterval);

            this.sessionStartTime = Date.now();
            this.sessionWarningShown = false;

            // Update timer display
            this.updateSessionTimerDisplay();
            this.sessionTimerInterval = setInterval(() => {
                this.updateSessionTimerDisplay();
            }, 1000);

            // Set session timeout
            this.sessionTimeout = setTimeout(() => {
                this.handleSessionTimeout();
            }, this.sessionDuration);

            // Set warning timeout (5 minutes before expiry)
            const warningTime = 5 * 60 * 1000;
            setTimeout(() => {
                if (!this.sessionWarningShown) {
                    this.showSessionWarning();
                }
            }, this.sessionDuration - warningTime);

            console.log('✅ Session timer started');
            
        } catch (error) {
            console.error('Session timer setup failed:', error);
        }
    }

    /**
     * Update session timer display
     */
    updateSessionTimerDisplay() {
        try {
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
            
            // Change color based on remaining time
            if (remaining < 5 * 60 * 1000) {
                timerEl.style.color = 'var(--warning-color)';
            } else {
                timerEl.style.color = 'var(--text-secondary)';
            }
            
        } catch (error) {
            console.error('Session timer update error:', error);
        }
    }

    /**
     * Show session warning dialog
     */
    showSessionWarning() {
        try {
            this.sessionWarningShown = true;
            
            const confirmed = confirm(
                'Your session will expire in 5 minutes. Would you like to extend your session?'
            );
            
            if (confirmed) {
                this.extendSession();
            }
            
        } catch (error) {
            console.error('Session warning error:', error);
        }
    }

    /**
     * Extend user session
     */
    async extendSession() {
        try {
            console.log('🔄 Attempting to extend session...');
            
            // Try server refresh
            try {
                const response = await this.makeAuthenticatedRequest('/api/auth/refresh', {
                    method: 'POST'
                });
                
                if (response && response.success) {
                    if (response.accessToken) {
                        sessionStorage.setItem('authToken', response.accessToken);
                        console.log('✅ Token refreshed successfully');
                    }
                    
                    this.sessionWarningShown = false;
                    this.startSessionTimer();
                    this.showNotification('Session extended successfully', 'success');
                    return;
                }
            } catch (error) {
                console.warn('Server refresh failed, using demo extension:', error.message);
            }
            
            // Demo mode fallback
            this.sessionWarningShown = false;
            this.startSessionTimer();
            this.showNotification('Session extended (demo mode)', 'success');
            
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
        try {
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
            }
            
            alert('Your session has expired. You will be redirected to the login page.');
            this.logout();
            
        } catch (error) {
            console.error('Session timeout handler error:', error);
            this.redirectToLogin();
        }
    }

    /**
     * Toggle user dropdown menu
     */
    toggleUserMenu() {
        try {
            const dropdown = document.getElementById('userDropdown');
            
            if (dropdown) {
                this.userDropdown = !this.userDropdown;
                
                if (this.userDropdown) {
                    dropdown.classList.add('show');
                    // Close notifications if open
                    this.notificationPanel = false;
                    this.hideNotifications();
                } else {
                    dropdown.classList.remove('show');
                }
            }
            
        } catch (error) {
            console.error('User menu toggle error:', error);
        }
    }

    /**
     * Toggle notifications panel
     */
    toggleNotifications() {
        try {
            const panel = document.getElementById('notificationPanel');
            
            if (panel) {
                this.notificationPanel = !this.notificationPanel;
                
                if (this.notificationPanel) {
                    panel.classList.add('show');
                    // Close user menu if open
                    this.userDropdown = false;
                    this.hideUserDropdown();
                    // Load notifications
                    this.loadNotifications();
                } else {
                    panel.classList.remove('show');
                }
            }
            
        } catch (error) {
            console.error('Notifications toggle error:', error);
        }
    }

    /**
     * Close all dropdown menus
     */
    closeAllDropdowns() {
        try {
            this.hideUserDropdown();
            this.hideNotifications();
        } catch (error) {
            console.error('Close dropdowns error:', error);
        }
    }

    /**
     * Hide user dropdown
     */
    hideUserDropdown() {
        try {
            const dropdown = document.getElementById('userDropdown');
            if (dropdown) {
                dropdown.classList.remove('show');
                this.userDropdown = false;
            }
        } catch (error) {
            console.error('Hide user dropdown error:', error);
        }
    }

    /**
     * Hide notifications panel
     */
    hideNotifications() {
        try {
            const panel = document.getElementById('notificationPanel');
            if (panel) {
                panel.classList.remove('show');
                this.notificationPanel = false;
            }
        } catch (error) {
            console.error('Hide notifications error:', error);
        }
    }

    /**
     * Load notifications from server or demo data
     */
    async loadNotifications() {
        try {
            let notifications = [];
            
            // Try API call first
            try {
                const response = await this.makeAuthenticatedRequest('/api/dashboard/notifications');
                if (response && response.success) {
                    notifications = response.data.notifications || [];
                } else {
                    throw new Error('API call failed');
                }
            } catch (error) {
                console.warn('Using demo notifications:', error.message);
                notifications = this.getDemoNotifications();
            }
            
            this.updateNotificationsUI(notifications);
            
        } catch (error) {
            console.error('Load notifications error:', error);
            this.updateNotificationsUI([]);
        }
    }

    /**
     * Get demo notifications based on user role
     */
    getDemoNotifications() {
        const userInfo = this.getUserInfo();
        const role = userInfo?.role || 'patient';
        
        const demoNotifications = {
            patient: [
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
            ],
            provider: [
                {
                    id: 1,
                    type: 'patient',
                    title: 'New Patient Registration',
                    message: 'Sarah Wilson has registered and requested an appointment',
                    timestamp: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(),
                    read: false
                },
                {
                    id: 2,
                    type: 'result',
                    title: 'Lab Results Ready',
                    message: 'John Patient\'s blood work results are available for review',
                    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
                    read: false
                }
            ],
            admin: [
                {
                    id: 1,
                    type: 'security',
                    title: 'High Risk Login Detected',
                    message: 'Multiple failed login attempts from suspicious IP address',
                    timestamp: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
                    read: false
                },
                {
                    id: 2,
                    type: 'system',
                    title: 'System Backup Completed',
                    message: 'Automated database backup completed successfully',
                    timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
                    read: false
                }
            ]
        };
        
        return demoNotifications[role] || demoNotifications.patient;
    }

    /**
     * Update notifications UI
     */
    updateNotificationsUI(notifications) {
        try {
            const notificationList = document.querySelector('.notification-list');
            if (!notificationList) return;

            if (notifications.length === 0) {
                notificationList.innerHTML = `
                    <div class="text-center" style="padding: 2rem; color: var(--text-secondary);">
                        <i class="fas fa-bell-slash" style="font-size: 2rem; margin-bottom: 1rem; opacity: 0.5;"></i>
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
                        <div class="notification-title">${this.escapeHtml(notification.title)}</div>
                        <div class="notification-message">${this.escapeHtml(notification.message)}</div>
                        <div class="notification-time">${this.formatTimeAgo(notification.timestamp)}</div>
                    </div>
                </div>
            `).join('');
            
        } catch (error) {
            console.error('Notifications UI update error:', error);
        }
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
            security: 'shield-alt',
            patient: 'user',
            alert: 'exclamation-triangle'
        };
        return icons[type] || 'bell';
    }

    /**
     * Format timestamp to "time ago" format
     */
    formatTimeAgo(timestamp) {
        try {
            const now = new Date();
            const time = new Date(timestamp);
            const diffInSeconds = Math.floor((now - time) / 1000);

            if (diffInSeconds < 60) return 'Just now';
            if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
            if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
            return `${Math.floor(diffInSeconds / 86400)} days ago`;
        } catch (error) {
            return 'Unknown time';
        }
    }

    /**
     * Escape HTML to prevent XSS
     */
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * Handle keyboard shortcuts
     */
    handleKeyboardShortcuts(event) {
        try {
            // Alt + number shortcuts for navigation
            if (event.altKey) {
                const keyToSection = {
                    '1': 'overview',
                    '2': 'appointments',
                    '3': 'records',
                    '4': 'messages',
                    '5': 'prescriptions',
                    '6': 'users',
                    '7': 'security',
                    '8': 'system',
                    '9': 'reports'
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

            // Escape key to close dropdowns
            if (event.key === 'Escape') {
                this.closeAllDropdowns();
            }
        } catch (error) {
            console.error('Keyboard shortcut error:', error);
        }
    }

    /**
     * Handle visibility change (tab switching)
     */
    handleVisibilityChange() {
        try {
            if (document.hidden) {
                console.log('🔒 Dashboard hidden - Pausing updates');
            } else {
                console.log('👁️ Dashboard visible - Resuming updates');
                // Check authentication when tab becomes visible
                const userInfo = this.getUserInfo();
                if (!userInfo) {
                    this.checkAuthentication().catch(() => {
                        this.redirectToLogin();
                    });
                }
            }
        } catch (error) {
            console.error('Visibility change error:', error);
        }
    }

    /**
     * Handle before page unload
     */
    handleBeforeUnload() {
        try {
            console.log('🔄 Dashboard unloading - Cleaning up');
            this.cleanup();
        } catch (error) {
            console.error('Before unload error:', error);
        }
    }

    /**
     * Show notification message with enhanced styling
     */
    showNotification(message, type = 'info') {
        try {
            // Remove existing notifications
            const existingNotifications = document.querySelectorAll('.notification-toast');
            existingNotifications.forEach(n => n.remove());

            const notification = document.createElement('div');
            notification.className = `notification-toast ${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <i class="fas fa-${type === 'success' ? 'check-circle' : 
                                      type === 'error' ? 'exclamation-circle' : 
                                      type === 'warning' ? 'exclamation-triangle' :
                                      'info-circle'}"></i>
                    <span>${this.escapeHtml(message)}</span>
                </div>
                <button class="close-notification">
                    <i class="fas fa-times"></i>
                </button>
            `;

            // Enhanced styling
            notification.style.cssText = `
                position: fixed;
                top: 1rem;
                right: 1rem;
                background: var(--bg-primary);
                border: 1px solid var(--border-color);
                border-radius: var(--radius-md);
                padding: 1rem;
                box-shadow: var(--shadow-lg);
                z-index: 10000;
                max-width: 350px;
                animation: slideInRight 0.3s ease-out;
                font-family: inherit;
            `;

            document.body.appendChild(notification);

            // Auto remove after 5 seconds
            const autoRemoveTimer = setTimeout(() => {
                if (notification.parentNode) {
                    notification.style.animation = 'slideOutRight 0.3s ease-in';
                    setTimeout(() => notification.remove(), 300);
                }
            }, 5000);

            // Manual close
            const closeBtn = notification.querySelector('.close-notification');
            closeBtn.addEventListener('click', () => {
                clearTimeout(autoRemoveTimer);
                notification.style.animation = 'slideOutRight 0.3s ease-in';
                setTimeout(() => notification.remove(), 300);
            });

        } catch (error) {
            console.error('Show notification error:', error);
            // Fallback to alert
            alert(message);
        }
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showNotification(message, 'error');
    }

    // Placeholder methods for section-specific data loading
    async loadAppointmentsData() {
        console.log('📅 Loading appointments data...');
        // Implementation would go here
    }

    async loadRecordsData() {
        console.log('📄 Loading medical records data...');
        // Implementation would go here
    }

    async loadMessagesData() {
        console.log('💬 Loading messages data...');
        // Implementation would go here
    }

    async loadPrescriptionsData() {
        console.log('💊 Loading prescriptions data...');
        // Implementation would go here
    }

    async loadUsersData() {
        console.log('👥 Loading users data...');
        // Implementation would go here
    }

    async loadSecurityData() {
        console.log('🔒 Loading security data...');
        // Implementation would go here
    }

    async loadSystemData() {
        console.log('⚙️ Loading system data...');
        // Implementation would go here
    }

    async loadReportsData() {
        console.log('📊 Loading reports data...');
        // Implementation would go here
    }
}

// Global functions for backwards compatibility and onclick handlers
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

// Action handlers for onclick compatibility
function scheduleAppointment() {
    if (window.dashboardManager) {
        window.dashboardManager.showSection('appointments');
    } else {
        alert('Schedule Appointment functionality - Please navigate to Appointments section.');
    }
}

function requestRecords() {
    if (window.dashboardManager) {
        window.dashboardManager.showSection('records');
    } else {
        alert('Request Records functionality - Please navigate to Medical Records section.');
    }
}

function composeMessage() {
    if (window.dashboardManager) {
        window.dashboardManager.showSection('messages');
    } else {
        alert('Compose Message functionality - Please navigate to Messages section.');
    }
}

function requestRefill() {
    if (window.dashboardManager) {
        window.dashboardManager.showSection('prescriptions');
    } else {
        alert('Request Refill functionality - Please navigate to Prescriptions section.');
    }
}

function refreshMetrics() {
    if (window.dashboardManager) {
        window.dashboardManager.loadOverviewData();
        window.dashboardManager.showNotification('Metrics refreshed!', 'success');
    }
}

// Initialize dashboard when DOM is ready with error handling
(function initializeDashboard() {
    try {
        // Wait for DOM to be fully loaded
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', createDashboardManager);
        } else {
            // DOM already loaded
            createDashboardManager();
        }
        
        function createDashboardManager() {
            try {
                window.dashboardManager = new DashboardManager();
                console.log('🏥 Dashboard Manager initialized successfully');
            } catch (error) {
                console.error('❌ Dashboard Manager initialization failed:', error);
                
                // Show error to user
                setTimeout(() => {
                    const errorMsg = 'Dashboard initialization failed. Please refresh the page or contact support if the problem persists.';
                    if (confirm(errorMsg + '\n\nWould you like to refresh the page now?')) {
                        window.location.reload();
                    }
                }, 1000);
            }
        }
        
    } catch (initError) {
        console.error('❌ Dashboard initialization script failed:', initError);
    }
})();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.dashboardManager) {
        window.dashboardManager.cleanup();
    }
});

// Add necessary CSS for animations and notifications
const styleSheet = document.createElement('style');
styleSheet.textContent = `
    /* Notification toast animations */
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
    
    @keyframes slideOutRight {
        from {
            opacity: 1;
            transform: translateX(0);
        }
        to {
            opacity: 0;
            transform: translateX(100%);
        }
    }
    
    /* Notification toast styling */
    .notification-toast {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 1rem;
        font-size: 0.9rem;
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
    
    .notification-toast.warning {
        border-left: 4px solid var(--warning-color);
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
        font-size: 0.8rem;
    }
    
    .close-notification:hover {
        color: var(--text-primary);
        background: var(--bg-secondary);
    }
    
    /* Enhanced dropdown animations */
    .user-dropdown {
        transition: all 0.2s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .user-dropdown.show {
        animation: fadeInDown 0.2s ease-out;
    }
    
    @keyframes fadeInDown {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    /* Loading states */
    .loading {
        opacity: 0.6;
        pointer-events: none;
        position: relative;
    }
    
    .loading::after {
        content: '';
        position: absolute;
        top: 50%;
        left: 50%;
        width: 20px;
        height: 20px;
        margin: -10px 0 0 -10px;
        border: 2px solid var(--primary-color);
        border-top: 2px solid transparent;
        border-radius: 50%;
        animation: spin 1s linear infinite;
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
`;

document.head.appendChild(styleSheet);

console.log('🏥 Enhanced Dashboard system loaded successfully');