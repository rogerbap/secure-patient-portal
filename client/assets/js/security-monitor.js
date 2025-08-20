//client/assets/js/security-monitor.js
/**
 * Security Monitor
 * 
 * Provides real-time security monitoring, threat detection,
 * and user behavior analysis for the healthcare portal.
 */

class SecurityMonitor {
    constructor() {
        this.isEnabled = true;
        this.threats = [];
        this.metrics = {
            pageLoads: 0,
            userActions: 0,
            securityEvents: 0,
            riskScore: 0
        };
        
        this.init();
    }

    /**
     * Initialize security monitoring
     */
    init() {
        if (!this.isEnabled) return;
        
        console.log('🔒 Security Monitor - Initializing...');
        
        this.setupEventListeners();
        this.startPeriodicChecks();
        this.monitorPageActivity();
        
        console.log('✅ Security Monitor - Active');
    }

    /**
     * Setup security event listeners
     */
    setupEventListeners() {
        // Monitor navigation events
        window.addEventListener('beforeunload', () => {
            this.logSecurityEvent('PAGE_UNLOAD', {
                page: window.location.pathname,
                sessionTime: this.getSessionTime()
            });
        });

        // Monitor visibility changes
        document.addEventListener('visibilitychange', () => {
            this.logSecurityEvent('VISIBILITY_CHANGE', {
                hidden: document.hidden,
                page: window.location.pathname
            });
        });

        // Monitor focus events
        window.addEventListener('focus', () => {
            this.logSecurityEvent('WINDOW_FOCUS', { focused: true });
        });

        window.addEventListener('blur', () => {
            this.logSecurityEvent('WINDOW_BLUR', { focused: false });
        });

        // Monitor keyboard events for suspicious patterns
        document.addEventListener('keydown', (e) => {
            this.analyzeKeyboardPattern(e);
        });

        // Monitor mouse events for bot detection
        document.addEventListener('mousemove', (e) => {
            this.analyzeMousePattern(e);
        });

        // Monitor form submissions
        document.addEventListener('submit', (e) => {
            this.logSecurityEvent('FORM_SUBMIT', {
                formId: e.target.id,
                action: e.target.action
            });
        });
    }

    /**
     * Start periodic security checks
     */
    startPeriodicChecks() {
        // Check every 30 seconds
        setInterval(() => {
            this.performSecurityScan();
        }, 30000);

        // Update metrics every 5 seconds
        setInterval(() => {
            this.updateSecurityMetrics();
        }, 5000);
    }

    /**
     * Monitor page activity
     */
    monitorPageActivity() {
        this.metrics.pageLoads++;
        this.logSecurityEvent('PAGE_LOAD', {
            page: window.location.pathname,
            referrer: document.referrer,
            userAgent: navigator.userAgent
        });
    }

    /**
     * Analyze keyboard patterns for suspicious activity
     */
    analyzeKeyboardPattern(event) {
        // Track rapid key sequences that might indicate automation
        if (!this.keyTimings) {
            this.keyTimings = [];
        }

        const now = Date.now();
        this.keyTimings.push(now);

        // Keep only last 10 key presses
        if (this.keyTimings.length > 10) {
            this.keyTimings.shift();
        }

        // Check for suspiciously fast typing (potential bot)
        if (this.keyTimings.length >= 5) {
            const avgInterval = (this.keyTimings[this.keyTimings.length - 1] - this.keyTimings[0]) / (this.keyTimings.length - 1);
            
            if (avgInterval < 50) { // Less than 50ms between keys
                this.flagThreat('SUSPICIOUS_TYPING_SPEED', {
                    averageInterval: avgInterval,
                    suspiciousThreshold: 50
                });
            }
        }
    }

    /**
     * Analyze mouse patterns for bot detection
     */
    analyzeMousePattern(event) {
        if (!this.mousePositions) {
            this.mousePositions = [];
        }

        const position = { x: event.clientX, y: event.clientY, time: Date.now() };
        this.mousePositions.push(position);

        // Keep only last 20 positions
        if (this.mousePositions.length > 20) {
            this.mousePositions.shift();
        }

        // Check for perfectly straight lines (potential automation)
        if (this.mousePositions.length >= 3) {
            const recent = this.mousePositions.slice(-3);
            const deltaX1 = recent[1].x - recent[0].x;
            const deltaY1 = recent[1].y - recent[0].y;
            const deltaX2 = recent[2].x - recent[1].x;
            const deltaY2 = recent[2].y - recent[1].y;

            // Check if movement is perfectly linear
            if (deltaX1 !== 0 && deltaY1 !== 0 && deltaX2 !== 0 && deltaY2 !== 0) {
                const slope1 = deltaY1 / deltaX1;
                const slope2 = deltaY2 / deltaX2;
                
                if (Math.abs(slope1 - slope2) < 0.01) {
                    this.flagThreat('SUSPICIOUS_MOUSE_PATTERN', {
                        pattern: 'Perfect linear movement detected'
                    });
                }
            }
        }
    }

    /**
     * Perform comprehensive security scan
     */
    performSecurityScan() {
        const threats = [];

        // Check for multiple tabs/windows
        if (this.detectMultipleTabs()) {
            threats.push({
                type: 'MULTIPLE_TABS',
                severity: 'low',
                description: 'Multiple tabs detected'
            });
        }

        // Check for developer tools
        if (this.detectDevTools()) {
            threats.push({
                type: 'DEVELOPER_TOOLS',
                severity: 'medium',
                description: 'Developer tools may be open'
            });
        }

        // Check for automated tools
        if (this.detectAutomation()) {
            threats.push({
                type: 'AUTOMATION_DETECTED',
                severity: 'high',
                description: 'Automated browsing detected'
            });
        }

        // Check session integrity
        if (this.checkSessionIntegrity()) {
            threats.push({
                type: 'SESSION_ANOMALY',
                severity: 'medium',
                description: 'Session integrity concerns'
            });
        }

        // Process any new threats
        threats.forEach(threat => {
            this.flagThreat(threat.type, threat);
        });
    }

    /**
     * Detect multiple tabs (simplified)
     */
    detectMultipleTabs() {
        // Use localStorage to detect multiple tabs
        const tabId = sessionStorage.getItem('tabId') || Math.random().toString(36);
        sessionStorage.setItem('tabId', tabId);
        
        const activeTabs = JSON.parse(localStorage.getItem('activeTabs') || '[]');
        const now = Date.now();
        
        // Clean old tabs
        const recentTabs = activeTabs.filter(tab => now - tab.lastSeen < 5000);
        
        // Add current tab
        const currentTab = recentTabs.find(tab => tab.id === tabId);
        if (currentTab) {
            currentTab.lastSeen = now;
        } else {
            recentTabs.push({ id: tabId, lastSeen: now });
        }
        
        localStorage.setItem('activeTabs', JSON.stringify(recentTabs));
        
        return recentTabs.length > 1;
    }

    /**
     * Detect developer tools (simplified)
     */
    detectDevTools() {
        // Check if console has been used
        let devtools = false;
        
        const threshold = 160;
        if (window.outerHeight - window.innerHeight > threshold || 
            window.outerWidth - window.innerWidth > threshold) {
            devtools = true;
        }
        
        return devtools;
    }

    /**
     * Detect automation tools
     */
    detectAutomation() {
        // Check for common automation indicators
        const indicators = [
            window.navigator.webdriver,
            window.phantom,
            window._phantom,
            window.callPhantom,
            window.Buffer,
            window.emit,
            window.spawn
        ];
        
        return indicators.some(indicator => indicator !== undefined);
    }

    /**
     * Check session integrity
     */
    checkSessionIntegrity() {
        // Simple session validation
        const sessionStart = sessionStorage.getItem('sessionStart');
        if (!sessionStart) {
            sessionStorage.setItem('sessionStart', Date.now().toString());
            return false;
        }
        
        const sessionAge = Date.now() - parseInt(sessionStart);
        const maxAge = 24 * 60 * 60 * 1000; // 24 hours
        
        return sessionAge > maxAge;
    }

    /**
     * Flag a security threat
     */
    flagThreat(type, details) {
        const threat = {
            type,
            details,
            timestamp: new Date().toISOString(),
            page: window.location.pathname,
            severity: details.severity || 'medium'
        };
        
        this.threats.push(threat);
        this.metrics.securityEvents++;
        
        this.logSecurityEvent('THREAT_DETECTED', threat);
        
        // Auto-response for high severity threats
        if (threat.severity === 'high') {
            this.handleHighSeverityThreat(threat);
        }
    }

    /**
     * Handle high severity threats
     */
    handleHighSeverityThreat(threat) {
        console.warn('🚨 High severity security threat detected:', threat);
        
        // In a real implementation, this would:
        // 1. Alert security team
        // 2. Increase monitoring
        // 3. Potentially lock account
        // 4. Log detailed forensics
        
        // For demo, just update risk score
        this.metrics.riskScore += 25;
    }

    /**
     * Log security event
     */
    logSecurityEvent(eventType, details) {
        const event = {
            type: eventType,
            details,
            timestamp: new Date().toISOString(),
            url: window.location.href,
            sessionId: this.getSessionId()
        };
        
        // Log to console in development
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            console.log(`🔒 Security Event: ${eventType}`, details);
        }
        
        // Send to server (implement as needed)
        this.sendSecurityEvent(event);
    }

    /**
     * Send security event to server
     */
    async sendSecurityEvent(event) {
        try {
            // Only send critical events to avoid spam
            const criticalEvents = [
                'THREAT_DETECTED',
                'SUSPICIOUS_TYPING_SPEED',
                'AUTOMATION_DETECTED',
                'DEVELOPER_TOOLS'
            ];
            
            if (criticalEvents.includes(event.type)) {
                // In a real implementation, send to security API
                // await fetch('/api/security/events', {
                //     method: 'POST',
                //     headers: { 'Content-Type': 'application/json' },
                //     body: JSON.stringify(event)
                // });
            }
        } catch (error) {
            console.error('Failed to send security event:', error);
        }
    }

    /**
     * Update security metrics
     */
    updateSecurityMetrics() {
        // Calculate risk score based on various factors
        let riskScore = 0;
        
        // Base risk from threats
        riskScore += this.threats.length * 5;
        
        // Risk from session age
        const sessionAge = this.getSessionTime();
        if (sessionAge > 8 * 60 * 60 * 1000) { // 8 hours
            riskScore += 10;
        }
        
        // Risk from page activity
        if (this.metrics.pageLoads > 50) {
            riskScore += 5;
        }
        
        this.metrics.riskScore = Math.min(riskScore, 100);
    }

    /**
     * Get current session time
     */
    getSessionTime() {
        const sessionStart = sessionStorage.getItem('sessionStart');
        if (!sessionStart) {
            return 0;
        }
        return Date.now() - parseInt(sessionStart);
    }

    /**
     * Get session ID
     */
    getSessionId() {
        let sessionId = sessionStorage.getItem('securitySessionId');
        if (!sessionId) {
            sessionId = 'sec_' + Math.random().toString(36).substr(2, 9);
            sessionStorage.setItem('securitySessionId', sessionId);
        }
        return sessionId;
    }

    /**
     * Get security status
     */
    getSecurityStatus() {
        return {
            isEnabled: this.isEnabled,
            threats: this.threats,
            metrics: this.metrics,
            riskLevel: this.getRiskLevel(),
            lastScan: new Date().toISOString()
        };
    }

    /**
     * Get risk level based on score
     */
    getRiskLevel() {
        if (this.metrics.riskScore < 25) return 'LOW';
        if (this.metrics.riskScore < 60) return 'MEDIUM';
        return 'HIGH';
    }

    /**
     * Clear security data (for testing)
     */
    clearSecurityData() {
        this.threats = [];
        this.metrics = {
            pageLoads: 0,
            userActions: 0,
            securityEvents: 0,
            riskScore: 0
        };
        this.keyTimings = [];
        this.mousePositions = [];
        
        console.log('🔒 Security data cleared');
    }

    /**
     * Disable security monitoring
     */
    disable() {
        this.isEnabled = false;
        console.log('🔒 Security Monitor - Disabled');
    }

    /**
     * Enable security monitoring
     */
    enable() {
        this.isEnabled = true;
        this.init();
    }
}

// Initialize security monitor
const securityMonitor = new SecurityMonitor();

// Global access for debugging
window.securityMonitor = securityMonitor;

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityMonitor;
}

console.log('🔒 Security monitoring system loaded successfully');