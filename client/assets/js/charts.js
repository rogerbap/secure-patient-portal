//client/assets/js/charts.js - NEW FILE
/**
 * Chart Implementation for HealthSecure Portal
 * Provides interactive charts for analytics across all dashboard types
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
            // Load Chart.js from CDN
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
        
        // Wait for DOM to be ready
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
            // Determine which dashboard we're on
            const currentPath = window.location.pathname;
            
            if (currentPath.includes('admin')) {
                this.setupAdminCharts();
            } else if (currentPath.includes('provider')) {
                this.setupProviderCharts();
            } else if (currentPath.includes('patient')) {
                this.setupPatientCharts();
            }
            
            console.log('✅ Charts initialized successfully');
        } catch (error) {
            console.error('Failed to setup charts:', error);
            this.createFallbackCharts();
        }
    }

    /**
     * Setup Admin Dashboard Charts
     */
    setupAdminCharts() {
        // System Performance Chart
        this.createSystemPerformanceChart();
        
        // Security Metrics Chart
        this.createSecurityMetricsChart();
        
        // User Activity Chart
        this.createUserActivityChart();
        
        // System Health Chart
        this.createSystemHealthChart();
    }

    /**
     * Setup Provider Dashboard Charts
     */
    setupProviderCharts() {
        // Patient Volume Chart
        this.createPatientVolumeChart();
        
        // Appointment Types Chart
        this.createAppointmentTypesChart();
        
        // Monthly Activity Chart
        this.createMonthlyActivityChart();
    }

    /**
     * Setup Patient Dashboard Charts (if any)
     */
    setupPatientCharts() {
        // Health Trends Chart (if container exists)
        this.createHealthTrendsChart();
    }

    /**
     * Create System Performance Chart (Admin)
     */
    createSystemPerformanceChart() {
        const container = document.querySelector('.chart-placeholder');
        if (!container) return;

        const canvas = this.createCanvas('systemPerformanceChart');
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
                        text: 'System Performance (Last 24 Hours)'
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
    }

    /**
     * Create Security Metrics Chart (Admin)
     */
    createSecurityMetricsChart() {
        const containers = document.querySelectorAll('.analytics-chart');
        if (containers.length < 2) return;

        const container = containers[1]; // Second chart container
        const canvas = this.createCanvas('securityMetricsChart');
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
    }

    /**
     * Create User Activity Chart (Admin)
     */
    createUserActivityChart() {
        // Find analytics container
        const analyticsCard = document.querySelector('.analytics-card');
        if (!analyticsCard) return;

        const canvas = this.createCanvas('userActivityChart');
        
        // Replace placeholder content
        const placeholder = analyticsCard.querySelector('.chart-placeholder');
        if (placeholder) {
            placeholder.innerHTML = '';
            placeholder.appendChild(canvas);
        }

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
                        text: 'User Activity (Last 7 Days)'
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
    }

    /**
     * Create System Health Chart (Admin)
     */
    createSystemHealthChart() {
        // Look for system metrics container
        const systemContainer = document.querySelector('.system-metrics .metric-card .chart-placeholder');
        if (!systemContainer) return;

        const canvas = this.createCanvas('systemHealthChart');
        systemContainer.innerHTML = '';
        systemContainer.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        this.charts.systemHealth = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: ['API Response', 'Database', 'Security', 'Storage', 'Network', 'Memory'],
                datasets: [{
                    label: 'Current Status',
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
                        text: 'System Health Score'
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
    }

    /**
     * Create Patient Volume Chart (Provider)
     */
    createPatientVolumeChart() {
        const container = document.querySelector('.analytics-chart .chart-placeholder');
        if (!container) return;

        const canvas = this.createCanvas('patientVolumeChart');
        container.innerHTML = '';
        container.appendChild(canvas);

        const ctx = canvas.getContext('2d');
        
        // Generate monthly data
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
    }

    /**
     * Create Appointment Types Chart (Provider)
     */
    createAppointmentTypesChart() {
        const metricsContainer = document.querySelector('.analytics-metrics');
        if (!metricsContainer) return;

        // Create a canvas for the chart
        const chartDiv = document.createElement('div');
        chartDiv.style.height = '200px';
        chartDiv.style.marginTop = '1rem';
        
        const canvas = this.createCanvas('appointmentTypesChart');
        chartDiv.appendChild(canvas);
        
        // Insert after the metrics
        metricsContainer.parentNode.insertBefore(chartDiv, metricsContainer.nextSibling);

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
    }

    /**
     * Create Monthly Activity Chart (Provider)
     */
    createMonthlyActivityChart() {
        // This would go in the provider analytics section
        const analyticsContainer = document.querySelector('.analytics-container');
        if (!analyticsContainer) return;

        const chartContainer = document.createElement('div');
        chartContainer.className = 'analytics-card';
        chartContainer.style.marginTop = '2rem';
        
        const canvas = this.createCanvas('monthlyActivityChart');
        canvas.style.height = '300px';
        
        chartContainer.innerHTML = '<h4>Monthly Activity Overview</h4>';
        chartContainer.appendChild(canvas);
        analyticsContainer.appendChild(chartContainer);

        const ctx = canvas.getContext('2d');
        
        this.charts.monthlyActivity = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
                datasets: [{
                    label: 'Appointments',
                    data: [45, 52, 48, 61],
                    backgroundColor: this.chartColors.primary + '80'
                }, {
                    label: 'Consultations',
                    data: [12, 15, 18, 14],
                    backgroundColor: this.chartColors.secondary + '80'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Weekly Activity This Month'
                    }
                }
            }
        });
    }

    /**
     * Create Health Trends Chart (Patient)
     */
    createHealthTrendsChart() {
        // Only create if we're on patient dashboard and have a suitable container
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
                <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 200px; background: #f8fafc; border-radius: 8px; border: 2px dashed #cbd5e1;">
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

    /**
     * Update chart data (for real-time updates)
     */
    updateChartData(chartName, newData) {
        if (this.charts[chartName]) {
            this.charts[chartName].data.datasets[0].data = newData;
            this.charts[chartName].update();
        }
    }
}

// Initialize chart manager
const chartManager = new ChartManager();

// Make it globally available
window.chartManager = chartManager;

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (window.chartManager) {
        window.chartManager.destroyAllCharts();
    }
});

console.log('📊 Chart system loaded successfully');