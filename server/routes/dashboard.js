//server/routes/dashboard.js - ENHANCED WITH ROLE-BASED ROUTING
const express = require('express');
const path = require('path');
const router = express.Router();
const { authenticateToken, authorizeRoles } = require('../middleware/auth');
const { globalRateLimit } = require('../middleware/rateLimit');
const logger = require('../utils/logger');

/**
 * @route   GET /api/dashboard/patient
 * @desc    Get patient dashboard data
 * @access  Private (Patient role)
 */
router.get('/patient', 
  authenticateToken,
  authorizeRoles('patient'),
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Demo patient dashboard data
      const dashboardData = {
        user: {
          name: req.user.firstName || 'Patient',
          role: 'patient',
          lastLogin: new Date().toISOString()
        },
        summary: {
          upcomingAppointments: 2,
          pendingResults: 1,
          unreadMessages: 3,
          prescriptions: 4
        },
        recentActivity: [
          {
            type: 'appointment',
            title: 'Annual Physical Scheduled',
            date: new Date().toISOString(),
            status: 'confirmed'
          },
          {
            type: 'result',
            title: 'Lab Results Available',
            date: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            status: 'available'
          }
        ]
      };

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (error) {
      logger.error('Patient dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load patient dashboard'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/provider
 * @desc    Get provider dashboard data
 * @access  Private (Provider role)
 */
router.get('/provider', 
  authenticateToken,
  authorizeRoles(['provider', 'admin']),
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Demo provider dashboard data
      const dashboardData = {
        user: {
          name: req.user.firstName || 'Doctor',
          role: 'provider',
          lastLogin: new Date().toISOString()
        },
        summary: {
          todaysAppointments: 12,
          activePatients: 245,
          patientMessages: 8,
          pendingReviews: 15
        },
        schedule: [
          {
            time: '9:00 AM',
            patient: 'John Patient',
            type: 'Annual Physical',
            room: 'Room 204',
            status: 'confirmed'
          },
          {
            time: '10:30 AM',
            patient: 'Mary Johnson',
            type: 'Follow-up',
            room: 'Room 204',
            status: 'confirmed'
          },
          {
            time: '2:00 PM',
            patient: 'Robert Brown',
            type: 'Telehealth',
            room: 'Virtual',
            status: 'scheduled'
          }
        ],
        recentActivity: [
          {
            type: 'patient_registration',
            title: 'New Patient Registration',
            date: new Date().toISOString(),
            details: 'Sarah Wilson requested appointment'
          },
          {
            type: 'lab_results',
            title: 'Lab Results Ready',
            date: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
            details: 'John Patient blood work available'
          }
        ]
      };

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (error) {
      logger.error('Provider dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load provider dashboard'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/admin
 * @desc    Get admin dashboard data
 * @access  Private (Admin role)
 */
router.get('/admin', 
  authenticateToken,
  authorizeRoles('admin'),
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Demo admin dashboard data
      const dashboardData = {
        user: {
          name: req.user.firstName || 'Admin',
          role: 'admin',
          lastLogin: new Date().toISOString()
        },
        summary: {
          totalUsers: 1247,
          securityAlerts: 23,
          systemUptime: 99.8,
          totalRecords: 45678
        },
        systemHealth: {
          api: 'operational',
          database: 'healthy',
          security: 'active',
          backup: 'current'
        },
        recentActivity: [
          {
            type: 'user_registration',
            title: 'New User Registration',
            date: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
            details: 'sarah.wilson@email.com registered'
          },
          {
            type: 'security_alert',
            title: 'High Risk Login Detected',
            date: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString(),
            details: 'Suspicious activity from IP 192.168.1.100'
          },
          {
            type: 'system_backup',
            title: 'System Backup Completed',
            date: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
            details: 'Database backup successful'
          }
        ],
        securityLogs: [
          {
            severity: 'HIGH',
            event: 'Suspicious Login Pattern',
            user: 'suspicious@demo.com',
            ip: '192.168.1.100',
            time: new Date(Date.now() - 4 * 60 * 60 * 1000).toISOString()
          },
          {
            severity: 'MEDIUM',
            event: 'New Location Login',
            user: 'patient@demo.com',
            ip: '192.168.1.50',
            time: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString()
          }
        ]
      };

      res.json({
        success: true,
        data: dashboardData
      });

    } catch (error) {
      logger.error('Admin dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load admin dashboard'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/notifications
 * @desc    Get user notifications
 * @access  Private
 */
router.get('/notifications', 
  authenticateToken,
  globalRateLimit,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const userRole = req.user.role;
      
      let notifications = [];
      
      // Role-based notifications
      switch (userRole) {
        case 'patient':
          notifications = [
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
          break;
          
        case 'provider':
          notifications = [
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
          ];
          break;
          
        case 'admin':
          notifications = [
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
            },
            {
              id: 3,
              type: 'user',
              title: 'New User Registration',
              message: 'New provider registration pending approval',
              timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
              read: true
            }
          ];
          break;
      }

      res.json({
        success: true,
        data: {
          notifications,
          unreadCount: notifications.filter(n => !n.read).length
        }
      });

    } catch (error) {
      logger.error('Notifications error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load notifications'
      });
    }
  }
);

/**
 * @route   POST /api/dashboard/notifications/:id/mark-read
 * @desc    Mark notification as read
 * @access  Private
 */
router.post('/notifications/:id/mark-read', 
  authenticateToken,
  async (req, res) => {
    try {
      const notificationId = req.params.id;
      const userId = req.user.id;
      
      // In a real implementation, this would update the database
      logger.info('Notification marked as read', {
        userId,
        notificationId
      });

      res.json({
        success: true,
        message: 'Notification marked as read'
      });

    } catch (error) {
      logger.error('Mark notification read error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to mark notification as read'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/stats
 * @desc    Get dashboard statistics
 * @access  Private
 */
router.get('/stats', 
  authenticateToken,
  async (req, res) => {
    try {
      const userRole = req.user.role;
      let stats = {};
      
      switch (userRole) {
        case 'patient':
          stats = {
            upcomingAppointments: 2,
            pendingResults: 1,
            unreadMessages: 3,
            activePrescriptions: 4
          };
          break;
          
        case 'provider':
          stats = {
            todaysAppointments: 12,
            activePatients: 245,
            patientMessages: 8,
            pendingReviews: 15
          };
          break;
          
        case 'admin':
          stats = {
            totalUsers: 1247,
            securityAlerts: 23,
            systemUptime: 99.8,
            totalRecords: 45678
          };
          break;
      }

      res.json({
        success: true,
        data: stats
      });

    } catch (error) {
      logger.error('Dashboard stats error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load dashboard statistics'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/analytics
 * @desc    Get analytics and metrics data
 * @access  Private (Admin and Provider)
 */
router.get('/analytics', 
  authenticateToken,
  authorizeRoles(['admin', 'provider']),
  async (req, res) => {
    try {
      const { timeRange = '24h' } = req.query;
      const userRole = req.user.role;
      
      // Calculate time range in milliseconds
      const timeRangeMs = parseTimeRange(timeRange);
      const since = new Date(Date.now() - timeRangeMs);
      
      let analyticsData = {};
      
      if (userRole === 'admin') {
        // Admin gets full system analytics
        analyticsData = {
          systemMetrics: await getSystemMetrics(since),
          securityMetrics: await getSecurityMetrics(since),
          userMetrics: await getUserMetrics(since),
          performanceMetrics: await getPerformanceMetrics(since),
          complianceMetrics: await getComplianceMetrics(since)
        };
      } else if (userRole === 'provider') {
        // Provider gets patient-focused analytics
        analyticsData = {
          patientMetrics: await getPatientMetrics(since, req.user.id),
          appointmentMetrics: await getAppointmentMetrics(since, req.user.id),
          securityOverview: await getSecurityOverview(since)
        };
      }
      
      res.json({
        success: true,
        data: {
          ...analyticsData,
          timeRange,
          generatedAt: new Date().toISOString(),
          userRole
        }
      });

    } catch (error) {
      logger.error('Analytics error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load analytics data'
      });
    }
  }
);

/**
 * @route   GET /api/dashboard/metrics/real-time
 * @desc    Get real-time system metrics
 * @access  Private (Admin only)
 */
router.get('/metrics/real-time', 
  authenticateToken,
  authorizeRoles('admin'),
  async (req, res) => {
    try {
      const realTimeMetrics = {
        timestamp: new Date().toISOString(),
        system: {
          uptime: Math.floor(process.uptime()),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage()
        },
        activeUsers: await getActiveUserCount(),
        currentLoad: await getCurrentSystemLoad(),
        securityAlerts: await getRecentSecurityAlerts(5), // Last 5 minutes
        apiRequests: await getApiRequestCount(5) // Last 5 minutes
      };

      res.json({
        success: true,
        data: realTimeMetrics
      });

    } catch (error) {
      logger.error('Real-time metrics error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load real-time metrics'
      });
    }
  }
);

// Helper functions for analytics data

async function getSystemMetrics(since) {
  try {
    return {
      totalUsers: 1247, // Demo data - replace with actual DB query
      activeUsers: await getActiveUserCount(),
      newRegistrations: Math.floor(Math.random() * 50) + 10,
      systemUptime: Math.floor(process.uptime()),
      apiRequests: Math.floor(Math.random() * 10000) + 5000,
      averageResponseTime: Math.floor(Math.random() * 100) + 50,
      errorRate: (Math.random() * 2).toFixed(2),
      databaseConnections: Math.floor(Math.random() * 20) + 5
    };
  } catch (error) {
    logger.error('System metrics error:', error);
    return {};
  }
}

async function getSecurityMetrics(since) {
  try {
    return {
      totalLoginAttempts: Math.floor(Math.random() * 500) + 200,
      successfulLogins: Math.floor(Math.random() * 400) + 150,
      failedLogins: Math.floor(Math.random() * 100) + 20,
      highRiskLogins: Math.floor(Math.random() * 50) + 5,
      securityAlerts: Math.floor(Math.random() * 25) + 3,
      blockedIPs: Math.floor(Math.random() * 15) + 2,
      riskDistribution: {
        low: 75,
        medium: 20,
        high: 5
      },
      topThreatTypes: [
        { type: 'Brute Force', count: 12 },
        { type: 'Suspicious Location', count: 8 },
        { type: 'New Device', count: 6 },
        { type: 'Rapid Requests', count: 4 }
      ]
    };
  } catch (error) {
    logger.error('Security metrics error:', error);
    return {};
  }
}

async function getUserMetrics(since) {
  try {
    return {
      totalUsers: 1247,
      activeUsers: 324,
      usersByRole: {
        patients: 1156,
        providers: 78,
        admins: 13
      },
      usersByStatus: {
        active: 1198,
        inactive: 49
      },
      registrationTrend: [
        { date: '2024-01-15', count: 45 },
        { date: '2024-01-16', count: 52 },
        { date: '2024-01-17', count: 38 },
        { date: '2024-01-18', count: 41 },
        { date: '2024-01-19', count: 47 },
        { date: '2024-01-20', count: 55 },
        { date: '2024-01-21', count: 43 }
      ],
      loginActivity: generateLoginActivityData()
    };
  } catch (error) {
    logger.error('User metrics error:', error);
    return {};
  }
}

async function getPerformanceMetrics(since) {
  try {
    return {
      averageResponseTime: Math.floor(Math.random() * 100) + 50,
      apiEndpointPerformance: [
        { endpoint: '/api/auth/login', avgTime: 245, requests: 1234 },
        { endpoint: '/api/dashboard/patient', avgTime: 156, requests: 2341 },
        { endpoint: '/api/dashboard/provider', avgTime: 198, requests: 567 },
        { endpoint: '/api/security/logs', avgTime: 312, requests: 123 },
        { endpoint: '/api/health', avgTime: 23, requests: 4567 }
      ],
      memoryUsage: {
        rss: Math.floor(process.memoryUsage().rss / 1024 / 1024),
        heapTotal: Math.floor(process.memoryUsage().heapTotal / 1024 / 1024),
        heapUsed: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024),
        external: Math.floor(process.memoryUsage().external / 1024 / 1024)
      },
      systemLoad: {
        cpu: (Math.random() * 80).toFixed(1),
        memory: (Math.random() * 60 + 20).toFixed(1),
        disk: (Math.random() * 40 + 30).toFixed(1)
      }
    };
  } catch (error) {
    logger.error('Performance metrics error:', error);
    return {};
  }
}

async function getComplianceMetrics(since) {
  try {
    return {
      auditLogEntries: Math.floor(Math.random() * 5000) + 2000,
      dataAccessEvents: Math.floor(Math.random() * 1000) + 500,
      hipaaCompliantSessions: 98.7,
      encryptedDataTransfers: 100,
      securityIncidents: 0,
      complianceScore: 96.8,
      auditTrailIntegrity: 100,
      dataRetentionCompliance: 98.2,
      accessControlCompliance: 99.1,
      recentAuditEvents: [
        { event: 'Patient data accessed', user: 'Dr. Smith', timestamp: new Date(Date.now() - 15 * 60 * 1000) },
        { event: 'Admin login', user: 'Admin User', timestamp: new Date(Date.now() - 32 * 60 * 1000) },
        { event: 'Password changed', user: 'John Patient', timestamp: new Date(Date.now() - 45 * 60 * 1000) },
        { event: 'High risk login detected', user: 'Suspicious User', timestamp: new Date(Date.now() - 67 * 60 * 1000) }
      ]
    };
  } catch (error) {
    logger.error('Compliance metrics error:', error);
    return {};
  }
}

async function getPatientMetrics(since, providerId) {
  try {
    return {
      totalPatients: 245,
      activePatients: 198,
      newPatients: 12,
      appointmentsToday: 8,
      upcomingAppointments: 15,
      pendingResults: 6,
      patientsByRisk: {
        low: 201,
        medium: 39,
        high: 5
      }
    };
  } catch (error) {
    logger.error('Patient metrics error:', error);
    return {};
  }
}

async function getAppointmentMetrics(since, providerId) {
  try {
    return {
      totalAppointments: 156,
      completedAppointments: 142,
      cancelledAppointments: 8,
      noShowAppointments: 6,
      averageAppointmentDuration: 45,
      appointmentsByType: {
        routine: 89,
        followUp: 34,
        urgent: 23,
        telehealth: 10
      }
    };
  } catch (error) {
    logger.error('Appointment metrics error:', error);
    return {};
  }
}

async function getSecurityOverview(since) {
  try {
    return {
      securityLevel: 'Normal',
      recentAlerts: 3,
      riskScore: 23,
      lastSecurityScan: new Date(Date.now() - 2 * 60 * 60 * 1000)
    };
  } catch (error) {
    logger.error('Security overview error:', error);
    return {};
  }
}

async function getActiveUserCount() {
  try {
    // In a real implementation, this would count active sessions
    return Math.floor(Math.random() * 100) + 250;
  } catch (error) {
    return 0;
  }
}

async function getCurrentSystemLoad() {
  try {
    return {
      cpu: (Math.random() * 50 + 10).toFixed(1),
      memory: (Math.random() * 40 + 30).toFixed(1),
      activeConnections: Math.floor(Math.random() * 50) + 10
    };
  } catch (error) {
    return {};
  }
}

async function getRecentSecurityAlerts(minutesBack) {
  try {
    return Math.floor(Math.random() * 5);
  } catch (error) {
    return 0;
  }
}

async function getApiRequestCount(minutesBack) {
  try {
    return Math.floor(Math.random() * 500) + 100;
  } catch (error) {
    return 0;
  }
}

function generateLoginActivityData() {
  const data = [];
  for (let i = 23; i >= 0; i--) {
    const hour = new Date(Date.now() - i * 60 * 60 * 1000).getHours();
    data.push({
      hour: `${hour.toString().padStart(2, '0')}:00`,
      logins: Math.floor(Math.random() * 50) + 10,
      uniqueUsers: Math.floor(Math.random() * 30) + 5
    });
  }
  return data;
}

function parseTimeRange(timeRange) {
  const units = {
    'm': 60 * 1000,
    'h': 60 * 60 * 1000,
    'd': 24 * 60 * 60 * 1000,
    'w': 7 * 24 * 60 * 60 * 1000
  };
  
  const match = timeRange.match(/^(\d+)([mhdw])$/);
  if (match) {
    const [, value, unit] = match;
    return parseInt(value) * units[unit];
  }
  return 24 * 60 * 60 * 1000; // Default to 24 hours
}

module.exports = router;