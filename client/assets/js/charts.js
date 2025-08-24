//client/assets/js/charts.js - UPDATED VERSION
/**
 * Chart Implementation for HealthSecure Portal
 * FIXED: Better admin dashboard detection and chart placement
 */

class ChartManager {
    constructor() {
        this.charts = {};
        this.chartColors = {
            primary: '#2563eb',
            secondary: '#10b981',
            warning: '#f59e0b',
            danger: '#ef4444',
            info: '#3b82f6',
            success: '#10b981'
        };
        
        this.loadChartJS();
    }

    /**
     * Load Chart.js library dynamically
     */
    async loadChartJS() {
        if (typeof Chart !== 'undefined') {
            this.init();
            return;
        }

        try {
            const script = document.createElement('script');
            script.src = 'https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js';
            script.onload = () => {
                console.log('✅ Chart.js loaded successfully');
                this.init();
            };
            script.onerror = () => {
                console.warn('⚠️ Failed to load Chart.js, using fallback');
                this.createFallbackCharts();
            };
            document.head.appendChild(script);
        } catch (error) {
            console.error('Failed to load Chart.js:', error);
            this.createFallbackCharts();
        }
    }

    /**
     * Initialize charts after Chart.js is loaded
     */
    init() {
        console.log('📊 Initializing Chart Manager...');
        
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setupCharts());
        } else {
            this.setupCharts();
        }
    }

    /**
     * Setup all charts based on current page
     */
    setupCharts() {
        try {
            // Wait a bit for DOM to be fully ready
            setTimeout(() => {
                this.detectAndSetupCharts();
            }, 500);
            
        } catch (error) {
            console.error('Failed to setup charts:', error);
            this.createFallbackCharts();
        }
    }

    /**
     * Detect dashboard type and setup appropriate charts
     */
    detectAndSetupCharts() {
        const currentPath = window.location.pathname;
        const title = document.title.toLowerCase();
        
        console.log(`📊 Detecting dashboard type - Path: ${currentPath}, Title: ${title}`);
        
        if (currentPath.includes('admin') || title.includes('admin')) {
            console.log('📊 Setting up Admin charts...');
            this.setupAdminCharts();
        } else if (currentPath.includes('provider') || title.includes('provider')) {
            console.log('📊 Setting up Provider charts...');
            this.setupProviderCharts();
        } else if (currentPath.includes('patient') || title.includes('patient')) {
            console.log('📊 Setting up Patient charts...');
            this.setupPatientCharts();
        } else {
            console.log('📊 Dashboard type unknown, trying all chart types...');
            this.setupAdminCharts();
            this.setupProviderCharts();
            this.setupPatientCharts();
        }
    }

    /**
     * Setup Admin Dashboard Charts
     */
    setupAdminCharts() {
        console.log('🔧 Setting up admin charts...');
        
        // Find all chart placeholders
        const placeholders = document.querySelectorAll('.chart-placeholder');
        console.log(`📊 Found ${placeholders.length} chart placeholders for admin`);
        
        placeholders.forEach((placeholder, index) => {
            const parentCard = placeholder.closest('.analytics-card, .metric-card');
            const cardTitle = parentCard ? parentCard.querySelector('h4')?.textContent?.toLowerCase() : '';
            
            console.log(`📊 Admin placeholder ${index}: "${cardTitle}"`);
            
            if (cardTitle.includes('performance') || cardTitle.includes('server')) {
                this.createSystemPerformanceChart(placeholder);
            } else if (cardTitle.includes('security') || cardTitle.includes('risk')) {
                this.createSecurityMetricsChart(placeholder);
            } else if (cardTitle.includes('activity') || cardTitle.includes('user')) {
                this.createUserActivityChart(placeholder);
            } else if (cardTitle.includes('health') || cardTitle.includes('radar')) {
                this.createSystemHealthChart(placeholder);
            } else {
                // Default chart for unknown admin placeholders
                this.createSystemPerformanceChart(placeholder);
            }
        });
    }

    /**
     * Setup Provider Dashboard Charts  
     */
    setupProviderCharts() {
        console.log('🔧 Setting up provider charts...');
        
        const placeholders = document.querySelectorAll('.chart-placeholder');
        console.log(`📊 Found ${placeholders.length} chart placeholders for provider`);
        
        placeholders.forEach((placeholder, index) => {
            const parentCard = placeholder.closest('.analytics-card');
            const cardTitle = parentCard ? parentCard.querySelector('h4')?.textContent?.toLowerCase() : '';
            
            console.log(`📊 Provider placeholder ${index}: "${cardTitle}"`);
            
            if (cardTitle.includes('volume') || cardTitle.includes('patient')) {
                this.createPatientVolumeChart(placeholder);
            } else if (cardTitle.includes('appointment') || cardTitle.includes('types')) {
                this.createAppointmentTypesChart(placeholder);
            } else {
                this.createPatientVolumeChart(placeholder);
            }
        });

        // Also check for metrics sections that need charts
        this.createAppointmentTypesChartInMetrics();
    }

    /**
     * Setup Patient Dashboard Charts
     */
    setupPatientCharts() {
        console.log('🔧 Setting up patient charts...');
        this.createHealthTrendsChart();
    }

    /**
     * Create System Performance Chart
     */
    createSystemPerformanceChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for system performance chart');
            return;
        }

        const canvas = this.createCanvas('systemPerformanceChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        this.charts.systemPerformance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: 'CPU Usage (%)',
                    data: [25, 28, 45, 65, 55, 35],
                    borderColor: this.chartColors.primary,
                    backgroundColor: this.chartColors.primary + '20',
                    tension: 0.4
                }, {
                    label: 'Memory Usage (%)',
                    data: [45, 48, 52, 58, 62, 55],
                    borderColor: this.chartColors.warning,
                    backgroundColor: this.chartColors.warning + '20',
                    tension: 0.4
                }, {
                    label: 'Disk Usage (%)',
                    data: [62, 62, 63, 64, 65, 65],
                    borderColor: this.chartColors.info,
                    backgroundColor: this.chartColors.info + '20',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'System Performance (24 Hours)'
                    },
                    legend: {
                        position: 'bottom'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                }
            }
        });

        console.log('✅ System performance chart created');
    }

    /**
     * Create Security Metrics Chart
     */
    createSecurityMetricsChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for security metrics chart');
            return;
        }

        const canvas = this.createCanvas('securityMetricsChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        this.charts.securityMetrics = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk', 'Medium Risk', 'High Risk', 'Critical'],
                datasets: [{
                    data: [75, 20, 4, 1],
                    backgroundColor: [
                        this.chartColors.success,
                        this.chartColors.warning,
                        this.chartColors.danger,
                        '#dc2626'
                    ],
                    borderWidth: 2,
                    borderColor: '#ffffff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Security Risk Distribution'
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        console.log('✅ Security metrics chart created');
    }

    /**
     * Create User Activity Chart
     */
    createUserActivityChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for user activity chart');
            return;
        }

        const canvas = this.createCanvas('userActivityChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        // Generate last 7 days data
        const labels = [];
        const loginData = [];
        const registrationData = [];
        
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            labels.push(date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
            loginData.push(Math.floor(Math.random() * 100) + 50);
            registrationData.push(Math.floor(Math.random() * 20) + 5);
        }
        
        this.charts.userActivity = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Daily Logins',
                    data: loginData,
                    backgroundColor: this.chartColors.primary + '80',
                    borderColor: this.chartColors.primary,
                    borderWidth: 1
                }, {
                    label: 'New Registrations',
                    data: registrationData,
                    backgroundColor: this.chartColors.secondary + '80',
                    borderColor: this.chartColors.secondary,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'User Activity (7 Days)'
                    },
                    legend: {
                        position: 'bottom'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        console.log('✅ User activity chart created');
    }

    /**
     * Create System Health Chart
     */
    createSystemHealthChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for system health chart');
            return;
        }

        const canvas = this.createCanvas('systemHealthChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        this.charts.systemHealth = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['API Response', 'Database', 'Security', 'Storage', 'Network', 'Memory'],
                datasets: [{
                    label: 'Health Score',
                    data: [95, 98, 92, 88, 94, 85],
                    borderColor: this.chartColors.success,
                    backgroundColor: this.chartColors.success + '30',
                    pointBackgroundColor: this.chartColors.success,
                    pointBorderColor: '#ffffff',
                    pointBorderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'System Health Overview'
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: {
                            callback: function(value) {
                                return value + '%';
                            }
                        }
                    }
                }
            }
        });

        console.log('✅ System health chart created');
    }

    /**
     * Create Patient Volume Chart
     */
    createPatientVolumeChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for patient volume chart');
            return;
        }

        const canvas = this.createCanvas('patientVolumeChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'];
        const patientData = [180, 195, 210, 205, 225, 240];
        
        this.charts.patientVolume = new Chart(ctx, {
            type: 'line',
            data: {
                labels: months,
                datasets: [{
                    label: 'Active Patients',
                    data: patientData,
                    borderColor: this.chartColors.primary,
                    backgroundColor: this.chartColors.primary + '20',
                    tension: 0.4,
                    fill: true
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Patient Volume Trend'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: false,
                        min: 150
                    }
                }
            }
        });

        console.log('✅ Patient volume chart created');
    }

    /**
     * Create Appointment Types Chart
     */
    createAppointmentTypesChart(container) {
        if (!container) {
            console.warn('⚠️ No container provided for appointment types chart');
            return;
        }

        const canvas = this.createCanvas('appointmentTypesChart_' + Date.now());
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        this.charts.appointmentTypes = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Routine Checkups', 'Follow-ups', 'Urgent Care', 'Consultations'],
                datasets: [{
                    data: [65, 25, 10, 8],
                    backgroundColor: [
                        this.chartColors.primary,
                        this.chartColors.secondary,
                        this.chartColors.warning,
                        this.chartColors.info
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Appointment Distribution'
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        console.log('✅ Appointment types chart created');
    }

    /**
     * Create Appointment Types Chart in Metrics Section
     */
    createAppointmentTypesChartInMetrics() {
        const metricsContainer = document.querySelector('.analytics-metrics');
        if (!metricsContainer) return;

        const chartDiv = document.createElement('div');
        chartDiv.style.height = '200px';
        chartDiv.style.marginTop = '1rem';
        
        const canvas = this.createCanvas('appointmentTypesMetricsChart');
        chartDiv.appendChild(canvas);
        
        metricsContainer.parentNode.insertBefore(chartDiv, metricsContainer.nextSibling);

        const ctx = canvas.getContext('2d');
        
        this.charts.appointmentTypesMetrics = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: ['Routine Checkups', 'Follow-ups', 'Urgent Care', 'Consultations'],
                datasets: [{
                    data: [65, 25, 10, 8],
                    backgroundColor: [
                        this.chartColors.primary,
                        this.chartColors.secondary,
                        this.chartColors.warning,
                        this.chartColors.info
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }

    /**
     * Create Health Trends Chart (Patient)
     */
    createHealthTrendsChart() {
        const healthCard = document.querySelector('.health-summary');
        if (!healthCard) return;

        const chartContainer = document.createElement('div');
        chartContainer.style.marginTop = '1rem';
        chartContainer.style.height = '200px';
        
        const canvas = this.createCanvas('healthTrendsChart');
        chartContainer.appendChild(canvas);
        healthCard.appendChild(chartContainer);

        const ctx = canvas.getContext('2d');
        
        this.charts.healthTrends = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
                datasets: [{
                    label: 'Blood Pressure (Systolic)',
                    data: [125, 122, 128, 120, 118, 115],
                    borderColor: this.chartColors.danger,
                    backgroundColor: this.chartColors.danger + '20',
                    tension: 0.4
                }, {
                    label: 'Heart Rate',
                    data: [72, 68, 75, 70, 69, 67],
                    borderColor: this.chartColors.primary,
                    backgroundColor: this.chartColors.primary + '20',
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Health Trends (6 Months)'
                    }
                }
            }
        });
    }

    /**
     * Create canvas element for charts
     */
    createCanvas(id) {
        const canvas = document.createElement('canvas');
        canvas.id = id;
        canvas.style.maxHeight = '400px';
        return canvas;
    }

    /**
     * Create fallback charts when Chart.js fails to load
     */
    createFallbackCharts() {
        console.log('📊 Creating fallback charts...');
        
        const placeholders = document.querySelectorAll('.chart-placeholder');
        placeholders.forEach(placeholder => {
            placeholder.innerHTML = `
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; background: #f8fafc; border-radius: 8px; border: 2px dashed #cbd5e1;">
                    <i class="fas fa-chart-bar" style="font-size: 3rem; color: #94a3b8; margin-bottom: 1rem;"></i>
                    <p style="color: #64748b; text-align: center; margin: 0;">
                        <strong>Chart Unavailable</strong><br>
                        Chart.js could not be loaded.<br>
                        <small>Check your internet connection.</small>
                    </p>
                </div>
            `;
        });
    }

    /**
     * Destroy all charts (for cleanup)
     */
    destroyAllCharts() {
        Object.keys(this.charts).forEach(key => {
            if (this.charts[key]) {
                this.charts[key].destroy();
                delete this.charts[key];
            }
        });
    }
}

// Initialize chart manager
const chartManager = new ChartManager();
window.chartManager = chartManager;

window.addEventListener('beforeunload', () => {
    if (window.chartManager) {
        window.chartManager.destroyAllCharts();
    }
});

console.log('📊 Enhanced Chart system loaded successfully');