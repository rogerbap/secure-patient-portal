//client/assets/js/dashboard.js - FIXED VERSION WITH DROPDOWN FIX
/**
 * HealthSecure Portal - Dashboard JavaScript
 * FIXED: Proper user dropdown functionality for production environments
 * FIXED: Enhanced error handling and event delegation
 * FIXED: Better DOM readiness checks and element validation
 */

class DashboardManager {
    constructor() {
        // FIXED: Improved API base URL detection
        this.apiBaseUrl = this.getApiBaseUrl();
        this.currentSection = 'overview';
        this.sessionTimeout = null;
        this.sessionWarningShown = false;
        this.notificationPanel = false;
        this.userDropdown = false;
        this.sessionTimerInterval = null;
        this.sessionStartTime = Date.now();
        this.sessionDuration = 30 * 60 * 1000; // 30 minutes
        
        // FIXED: Bind methods to maintain context
        this.toggleUserMenu = this.toggleUserMenu.bind(this);
        this.toggleNotifications = this.toggleNotifications.bind(this);
        this.handleDocumentClick = this.handleDocumentClick.bind(this);
        this.handleNavigation = this.handleNavigation.bind(this);
        this.logout = this.logout.bind(this);
        
        this.init();
    }

    /**
     * FIXED: Get API base URL dynamically with better logic
     */
    getApiBaseUrl() {
        const hostname = window.location.hostname;
        const port = window.location.port;
        const protocol = window.location.protocol;
        
        console.log('🔍 Detecting API base URL:', { hostname, port, protocol });
        
        // For localhost development
        if (hostname === 'localhost' || hostname === '127.0.0.1') {
            // If we're on port 8080 (frontend dev server), API is on port 3000
            if (port === '8080') {
                const apiUrl = 'http://localhost:3000';
                console.log('📡 Frontend dev server detected, API URL:', apiUrl);
                return apiUrl;
            }
            // If we're on port 3000 (same server), use same origin
            else if (port === '3000' || !port) {
                const apiUrl = `${protocol}//${hostname}:3000`;
                console.log('📡 Same server detected, API URL:', apiUrl);
                return apiUrl;
            }
            // Other localhost ports, try 3000
            else {
                const apiUrl = 'http://localhost:3000';
                console.log('📡 Other localhost port, trying API URL:', apiUrl);
                return apiUrl;
            }
        }
        
        // For production (Render, Heroku, etc.), use same origin without port
        const apiUrl = `${protocol}//${hostname}`;
        console.log('📡 Production environment detected, API URL:', apiUrl);
        return apiUrl;
    }

    /**
     * Initialize the dashboard
     */
    init() {
        console.log('🏥 Dashboard Manager - Initializing...');
        console.log('🌐 API Base URL:', this.apiBaseUrl);
        
        // FIXED: Better DOM ready detection
        this.waitForDOM().then(() => {
            this.onDOMReady();
        }).catch(error => {
            console.error('❌ DOM ready failed:', error);
            // Fallback - try to initialize anyway
            setTimeout(() => this.onDOMReady(), 1000);
        });
    }

    /**
     * FIXED: Better DOM ready detection
     */
    waitForDOM() {
        return new Promise((resolve) => {
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', resolve, { once: true });
            } else {
                resolve();
            }
        });
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
     * FIXED: Setup all event listeners with better error handling
     */
    setupEventListeners() {
        try {
            // FIXED: Navigation links - prevent logout on Overview click
            this.setupNavigationListeners();
            
            // FIXED: User menu toggle with better element detection
            this.setupUserMenuListeners();

            // FIXED: Notification toggle
            this.setupNotificationListeners();

            // FIXED: Logout button handling with better delegation
            this.setupLogoutListeners();

            // FIXED: Close dropdowns when clicking outside - with proper delegation
            this.setupDocumentClickHandler();

            // Keyboard shortcuts
            document.addEventListener('keydown', (e) => this.handleKeyboardShortcuts(e));

            // Session extension
            this.setupSessionExtensionListener();

            // Window events
            window.addEventListener('beforeunload', () => this.handleBeforeUnload());
            document.addEventListener('visibilitychange', () => this.handleVisibilityChange());
            
            console.log('✅ Event listeners setup completed');
        } catch (error) {
            console.error('❌ Event listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup navigation event listeners
     */
    setupNavigationListeners() {
        try {
            // Use event delegation for navigation links
            document.addEventListener('click', (e) => {
                const navLink = e.target.closest('.nav-link');
                if (navLink && navLink.dataset.section) {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    const section = navLink.dataset.section;
                    console.log(`Navigation clicked: ${section}`);
                    this.handleNavigation(e);
                }
            });
        } catch (error) {
            console.error('❌ Navigation listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup user menu listeners with multiple fallback methods
     */
    setupUserMenuListeners() {
        try {
            // Method 1: Direct element event listener
            const userAvatar = document.querySelector('.user-avatar');
            if (userAvatar) {
                console.log('✅ User avatar found, attaching click listener');
                
                // Remove any existing listeners
                userAvatar.removeEventListener('click', this.toggleUserMenu);
                
                // Add new listener
                userAvatar.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('🖱️ User avatar clicked via direct listener');
                    this.toggleUserMenu();
                });
                
                // Also add the onclick attribute as fallback
                userAvatar.setAttribute('onclick', 'window.dashboardManager.toggleUserMenu(); return false;');
            } else {
                console.warn('⚠️ User avatar element not found');
            }

            // Method 2: Event delegation for user menu
            document.addEventListener('click', (e) => {
                if (e.target.closest('.user-avatar')) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('🖱️ User avatar clicked via delegation');
                    this.toggleUserMenu();
                }
            });

            // Method 3: Setup global function fallback
            window.toggleUserMenu = () => {
                console.log('🖱️ User menu toggled via global function');
                this.toggleUserMenu();
            };
            
        } catch (error) {
            console.error('❌ User menu listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup notification listeners
     */
    setupNotificationListeners() {
        try {
            const notificationBtn = document.querySelector('.notifications');
            if (notificationBtn) {
                notificationBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.toggleNotifications();
                });
            }

            // Event delegation backup
            document.addEventListener('click', (e) => {
                if (e.target.closest('.notifications')) {
                    e.preventDefault();
                    e.stopPropagation();
                    this.toggleNotifications();
                }
            });

            // Global function
            window.toggleNotifications = () => {
                this.toggleNotifications();
            };
        } catch (error) {
            console.error('❌ Notification listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup logout listeners with comprehensive delegation
     */
    setupLogoutListeners() {
        try {
            // Method 1: Find and bind logout elements directly
            const logoutElements = document.querySelectorAll('.logout, [onclick*="handleLogout"], [onclick*="logout"]');
            logoutElements.forEach(logoutBtn => {
                // Remove any existing onclick handlers
                logoutBtn.removeAttribute('onclick');
                
                // Remove existing listeners
                logoutBtn.removeEventListener('click', this.logout);
                
                // Add new listener
                logoutBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('🚪 Logout button clicked (direct)');
                    this.logout();
                });
            });

            // Method 2: Event delegation for logout
            document.addEventListener('click', (e) => {
                const logoutElement = e.target.closest('.logout');
                if (logoutElement) {
                    e.preventDefault();
                    e.stopPropagation();
                    console.log('🚪 Logout clicked via delegation');
                    this.logout();
                }
            });

            // Method 3: Global function fallback
            window.handleLogout = () => {
                console.log('🚪 Logout via global function');
                this.logout();
            };

            console.log('✅ Logout listeners setup completed');
        } catch (error) {
            console.error('❌ Logout listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup session extension listener
     */
    setupSessionExtensionListener() {
        try {
            const extendBtn = document.querySelector('.extend-session-btn');
            if (extendBtn) {
                extendBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.extendSession();
                });
            }

            // Global function
            window.extendSession = () => {
                this.extendSession();
            };
        } catch (error) {
            console.error('❌ Session extension listener setup failed:', error);
        }
    }

    /**
     * FIXED: Setup document click handler to close dropdowns
     */
    setupDocumentClickHandler() {
        try {
            // Remove existing listener if any
            document.removeEventListener('click', this.handleDocumentClick);
            
            // Add new listener
            document.addEventListener('click', this.handleDocumentClick);
        } catch (error) {
            console.error('❌ Document click handler setup failed:', error);
        }
    }

    /**
     * FIXED: Handle document clicks to close dropdowns
     */
    handleDocumentClick(e) {
        try {
            // Don't close if clicking on dropdown elements or their children
            const isUserMenuClick = e.target.closest('.user-menu') || e.target.closest('.user-dropdown');
            const isNotificationClick = e.target.closest('.notification-panel') || e.target.closest('.notifications');
            
            if (!isUserMenuClick && !isNotificationClick) {
                this.closeAllDropdowns();
            }
        } catch (error) {
            console.error('❌ Document click handler error:', error);
        }
    }

    // FIXED: Handle navigation between sections
    handleNavigation(event) {
        try {
            event.preventDefault();
            event.stopPropagation();
            
            const link = event.currentTarget || event.target.closest('.nav-link');
            const section = link?.dataset?.section;
            
            console.log(`Handling navigation to: ${section}`);
            
            if (section) {
                // Don't navigate away from the page, just show the section
                this.showSection(section);
                this.updateActiveNavigation(link);
                
                console.log(`📊 Navigation: ${this.currentSection} → ${section}`);
            }
        } catch (error) {
            console.error('❌ Navigation handling failed:', error);
        }
    }

    // FIXED: Enhanced logout with better error handling
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
            
            // Clear demo auth cookie with multiple approaches
            const cookieOptions = [
                'demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;',
                'demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT; domain=localhost;',
                `demoAuth=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT; domain=${window.location.hostname};`
            ];
            
            cookieOptions.forEach(option => {
                document.cookie = option;
            });
            
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
     * FIXED: Toggle user dropdown menu with better error handling
     */
    toggleUserMenu() {
        try {
            console.log('🔄 Toggling user menu, current state:', this.userDropdown);
            
            const dropdown = document.getElementById('userDropdown') || document.querySelector('.user-dropdown');
            
            if (!dropdown) {
                console.error('❌ User dropdown element not found');
                return;
            }

            this.userDropdown = !this.userDropdown;
            
            if (this.userDropdown) {
                console.log('✅ Opening user dropdown');
                dropdown.classList.add('show');
                // Close notifications if open
                this.notificationPanel = false;
                this.hideNotifications();
            } else {
                console.log('✅ Closing user dropdown');
                dropdown.classList.remove('show');
            }
            
            console.log('✅ User menu toggled successfully, new state:', this.userDropdown);
            
        } catch (error) {
            console.error('❌ Toggle user menu error:', error);
        }
    }

    /**
     * Toggle notifications panel
     */
    toggleNotifications() {
        try {
            const panel = document.getElementById('notificationPanel') || document.querySelector('.notification-panel');
            
            if (!panel) {
                console.error('❌ Notification panel element not found');
                return;
            }

            this.notificationPanel = !this.notificationPanel;
            
            if (this.notificationPanel) {
                panel.classList.add('show');
                this.userDropdown = false;
                this.hideUserDropdown();
                this.loadNotifications();
            } else {
                panel.classList.remove('show');
            }
        } catch (error) {
            console.error('❌ Toggle notifications error:', error);
        }
    }

    /**
     * FIXED: Close all dropdown menus
     */
    closeAllDropdowns() {
        try {
            this.hideUserDropdown();
            this.hideNotifications();
        } catch (error) {
            console.error('❌ Close dropdowns error:', error);
        }
    }

    /**
     * FIXED: Hide user dropdown
     */
    hideUserDropdown() {
        try {
            const dropdown = document.getElementById('userDropdown') || document.querySelector('.user-dropdown');
            if (dropdown) {
                dropdown.classList.remove('show');
                this.userDropdown = false;
            }
        } catch (error) {
            console.error('❌ Hide user dropdown error:', error);
        }
    }

    /**
     * FIXED: Hide notifications panel
     */
    hideNotifications() {
        try {
            const panel = document.getElementById('notificationPanel') || document.querySelector('.notification-panel');
            if (panel) {
                panel.classList.remove('show');
                this.notificationPanel = false;
            }
        } catch (error) {
            console.error('❌ Hide notifications error:', error);
        }
    }

    /**
     * Show specific dashboard section
     */
    showSection(sectionName) {
        try {
            document.querySelectorAll('.dashboard-section').forEach(section => {
                section.classList.remove('active');
            });
            
            const targetSection = document.getElementById(sectionName);
            if (targetSection) {
                targetSection.classList.add('active');
                this.currentSection = sectionName;
                
                this.loadSectionData(sectionName);
            }
        } catch (error) {
            console.error('❌ Show section error:', error);
        }
    }

    /**
     * Update active navigation state
     */
    updateActiveNavigation(activeLink) {
        try {
            document.querySelectorAll('.nav-link').forEach(link => {
                link.classList.remove('active');
            });
            
            if (activeLink) {
                activeLink.classList.add('active');
            }
        } catch (error) {
            console.error('❌ Update navigation error:', error);
        }
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
        try {
            // Update user name
            const userNameEl = document.getElementById('patientName');
            if (userNameEl && data.user) {
                userNameEl.textContent = data.user.name?.split(' ')[0] || 'User';
            }

            // Update stat counters
            if (data.summary) {
                this.updateStatCounters(data.summary);
            }
        } catch (error) {
            console.error('❌ Update overview UI error:', error);
        }
    }

    /**
     * Update stat counters with animation
     */
    updateStatCounters(summary) {
        try {
            const statCards = document.querySelectorAll('.stat-number');
            
            statCards.forEach(card => {
                const target = parseInt(card.dataset.target) || 0;
                this.animateCounter(card, target);
            });
        } catch (error) {
            console.error('❌ Update stat counters error:', error);
        }
    }

    /**
     * Animate counter to target value
     */
    animateCounter(element, target) {
        try {
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
        } catch (error) {
            console.error('❌ Animate counter error:', error);
        }
    }

    /**
     * Animate all counters on page load
     */
    animateCounters() {
        try {
            const counters = document.querySelectorAll('.stat-number');
            
            counters.forEach(counter => {
                const target = parseInt(counter.dataset.target) || 0;
                setTimeout(() => {
                    this.animateCounter(counter, target);
                }, 500);
            });
        } catch (error) {
            console.error('❌ Animate counters error:', error);
        }
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
        try {
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
        } catch (error) {
            console.error('❌ Update user UI error:', error);
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
        try {
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
        } catch (error) {
            console.error('❌ Session timer error:', error);
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
            
            if (remaining < 5 * 60 * 1000) {
                timerEl.style.color = 'var(--warning-color)';
            } else {
                timerEl.style.color = 'var(--text-secondary)';
            }
        } catch (error) {
            console.error('❌ Update session timer error:', error);
        }
    }

    /**
     * Show session warning
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
            console.error('❌ Session warning error:', error);
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
        try {
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
            }
            
            alert('Your session has expired. You will be redirected to the login page.');
            this.logout();
        } catch (error) {
            console.error('❌ Session timeout handling error:', error);
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
        try {
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
        } catch (error) {
            console.error('❌ Update notifications UI error:', error);
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
            security: 'shield-alt'
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
     * Handle keyboard shortcuts
     */
    handleKeyboardShortcuts(event) {
        try {
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
        } catch (error) {
            console.error('❌ Keyboard shortcuts error:', error);
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
                const userInfo = this.getUserInfo();
                if (!userInfo) {
                    this.checkAuthentication().catch(() => {
                        this.redirectToLogin();
                    });
                }
            }
        } catch (error) {
            console.error('❌ Visibility change error:', error);
        }
    }

    /**
     * Handle before page unload
     */
    handleBeforeUnload() {
        try {
            console.log('🔄 Dashboard unloading - Cleaning up');
            
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
            }
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
            }
        } catch (error) {
            console.error('❌ Before unload error:', error);
        }
    }

    /**
     * Show notification message
     */
    showNotification(message, type = 'info') {
        try {
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
            if (closeBtn) {
                closeBtn.addEventListener('click', () => notification.remove());
            }
        } catch (error) {
            console.error('❌ Show notification error:', error);
        }
    }

    /**
     * Show error message
     */
    showError(message) {
        this.showNotification(message, 'error');
    }

    /**
     * FIXED: Redirect to login page - Enhanced to handle different environments
     */
    redirectToLogin() {
        try {
            console.log('🔄 Redirecting to login...');
            
            if (this.sessionTimeout) {
                clearTimeout(this.sessionTimeout);
            }
            if (this.sessionTimerInterval) {
                clearInterval(this.sessionTimerInterval);
            }
            
            // Clear authentication data
            sessionStorage.removeItem('authToken');
            sessionStorage.removeItem('userInfo');
            sessionStorage.removeItem('loginData');
            
            // FIXED: Better redirect logic for different environments
            const hostname = window.location.hostname;
            const port = window.location.port;
            
            // For localhost development with separate frontend server
            if (hostname === 'localhost' && port === '8080') {
                // Redirect to frontend dev server root
                window.location.href = 'http://localhost:8080/';
            }
            // For localhost development on same server
            else if (hostname === 'localhost' && (port === '3000' || !port)) {
                // Redirect to same server root
                window.location.href = '/';
            }
            // For production environments
            else {
                // Redirect to root of current domain
                window.location.href = '/';
            }
        } catch (error) {
            console.error('❌ Redirect to login error:', error);
            // Force redirect as fallback
            window.location.href = '/';
        }
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

// FIXED: Global functions for onclick handlers with error handling
function navigateToSection(sectionName) {
    try {
        if (window.dashboardManager) {
            window.dashboardManager.showSection(sectionName);
            
            const navLink = document.querySelector(`[data-section="${sectionName}"]`);
            if (navLink) {
                window.dashboardManager.updateActiveNavigation(navLink);
            }
        }
    } catch (error) {
        console.error('❌ Navigate to section error:', error);
    }
}

function toggleNotifications() {
    try {
        if (window.dashboardManager) {
            window.dashboardManager.toggleNotifications();
        }
    } catch (error) {
        console.error('❌ Toggle notifications error:', error);
    }
}

function toggleUserMenu() {
    try {
        console.log('🔄 Global toggleUserMenu called');
        if (window.dashboardManager) {
            window.dashboardManager.toggleUserMenu();
        }
    } catch (error) {
        console.error('❌ Toggle user menu error:', error);
    }
}

function extendSession() {
    try {
        if (window.dashboardManager) {
            window.dashboardManager.extendSession();
        }
    } catch (error) {
        console.error('❌ Extend session error:', error);
    }
}

function handleLogout() {
    try {
        console.log('🚪 Global handleLogout called');
        if (window.dashboardManager) {
            window.dashboardManager.logout();
        }
    } catch (error) {
        console.error('❌ Handle logout error:', error);
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

// FIXED: Initialize dashboard when DOM is ready with multiple methods
function initializeDashboard() {
    try {
        console.log('🏥 Initializing dashboard manager...');
        window.dashboardManager = new DashboardManager();
        
        // Ensure global functions are available
        window.toggleUserMenu = toggleUserMenu;
        window.toggleNotifications = toggleNotifications;
        window.handleLogout = handleLogout;
        window.extendSession = extendSession;
        
        console.log('✅ Dashboard manager initialized successfully');
    } catch (error) {
        console.error('❌ Dashboard initialization failed:', error);
    }
}

// Multiple initialization methods for reliability
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeDashboard, { once: true });
} else {
    initializeDashboard();
}

// Backup initialization
setTimeout(() => {
    if (!window.dashboardManager) {
        console.warn('⚠️ Dashboard manager not initialized, attempting backup initialization...');
        initializeDashboard();
    }
}, 2000);

// Another backup for production issues
window.addEventListener('load', () => {
    if (!window.dashboardManager) {
        console.warn('⚠️ Dashboard manager still not initialized, final attempt...');
        initializeDashboard();
    }
}, { once: true });

console.log('🏥 Enhanced Dashboard system loaded successfully');

// Add CSS for notification toast if not already present
if (!document.querySelector('style[data-dashboard-styles]')) {
    const style = document.createElement('style');
    style.setAttribute('data-dashboard-styles', 'true');
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
        
        /* FIXED: Ensure dropdown is properly styled and clickable */
        .user-dropdown {
            position: absolute;
            top: 100%;
            right: 0;
            margin-top: 0.5rem;
            background: var(--bg-primary);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-lg);
            min-width: 200px;
            opacity: 0;
            visibility: hidden;
            transform: translateY(-10px);
            transition: var(--transition);
            z-index: 1001;
            pointer-events: none;
        }
        
        .user-dropdown.show {
            opacity: 1;
            visibility: visible;
            transform: translateY(0);
            pointer-events: auto;
        }
        
        .dropdown-item {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.75rem 1rem;
            color: var(--text-secondary);
            text-decoration: none;
            transition: var(--transition);
            cursor: pointer;
            border: none;
            background: none;
            width: 100%;
            text-align: left;
        }
        
        .dropdown-item:hover {
            background: var(--bg-secondary);
            color: var(--text-primary);
        }
        
        .dropdown-item.logout {
            color: var(--danger-color);
            border-top: 1px solid var(--border-color);
        }
        
        .dropdown-item.logout:hover {
            background: rgba(239, 68, 68, 0.05);
        }
    `;
    document.head.appendChild(style);
}

console.log('🏥 Enhanced Dashboard system with dropdown fix loaded successfully');