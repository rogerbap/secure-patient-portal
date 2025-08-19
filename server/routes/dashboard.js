const express = require('express');
const router = express.Router();

// Import middleware
const { authenticateToken, authorizeRoles, validateSession } = require('../middleware/auth');
const { globalRateLimit } = require('../middleware/rateLimit');
const auditService = require('../services/auditService');

/**
 * @route   GET /api/dashboard/patient
 * @desc    Get patient dashboard data
 * @access  Private (Patient role)
 */
router.get('/patient', 
  authenticateToken,
  validateSession,
  authorizeRoles('patient'),
  globalRateLimit,
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      // Mock patient dashboard data
      const dashboardData = {
        user: {
          id: userId,
          name: `${req.user.firstName} ${req.user.lastName}`,
          email: req.user.email,
          memberSince: '2023-01-15'
        },
        summary: {
          upcomingAppointments: 2,
          pendingResults: 1,
          unreadMessages: 3,
          prescriptions: 4
        },
        recentActivity: [
          {
            id: 1,
            type: 'appointment',
            title: 'Annual Physical Exam',
            date: '2024-01-15T10:00:00Z',
            provider: 'Dr. Sarah Smith',
            status: 'confirmed'
          },
          {
            id: 2,
            type: 'result',
            title: 'Blood Test Results',
            date: '2024-01-10T14:30:00Z',
            provider: 'Dr. Sarah Smith',
            status: 'available'
          },
          {
            id: 3,
            type: 'message',
            title: 'Prescription Refill Approved',
            date: '2024-01-08T09:15:00Z',
            provider: 'Dr. Sarah Smith',
            status: 'unread'
          }
        ],
        quickActions: [
          { id: 'schedule', title: 'Schedule Appointment', icon: 'calendar-plus' },
          { id: 'messages', title: 'View Messages', icon: 'envelope' },
          { id: 'records', title: 'Medical Records', icon: 'file-medical' },
          { id: 'prescriptions', title: 'Prescriptions', icon: 'pills' }
        ],
        healthMetrics: {
          lastVisit: '2024-01-05',
          nextAppointment: '2024-01-15',
          activeConditions: ['Hypertension', 'Type 2 Diabetes'],
          allergies: ['Penicillin', 'Shellfish']
        }
      };

      // Log dashboard access
      await auditService.logUserAction({
        userId,
        action: 'DASHBOARD_ACCESS',
        details: { dashboardType: 'patient' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: dashboardData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Patient dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load dashboard data'
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
  validateSession,
  authorizeRoles(['provider', 'admin']),
  globalRateLimit,
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      const dashboardData = {
        user: {
          id: userId,
          name: `${req.user.firstName} ${req.user.lastName}`,
          email: req.user.email,
          department: 'Internal Medicine',
          license: 'MD-12345'
        },
        summary: {
          todaysAppointments: 8,
          pendingReviews: 12,
          unreadMessages: 5,
          activePatients: 156
        },
        todaysSchedule: [
          {
            id: 1,
            time: '09:00',
            patient: 'John Doe',
            type: 'Follow-up',
            duration: 30,
            status: 'confirmed'
          },
          {
            id: 2,
            time: '09:30',
            patient: 'Jane Smith',
            type: 'Annual Physical',
            duration: 60,
            status: 'confirmed'
          },
          {
            id: 3,
            time: '10:30',
            patient: 'Bob Johnson',
            type: 'Consultation',
            duration: 45,
            status: 'pending'
          }
        ],
        pendingTasks: [
          { id: 1, type: 'prescription', patient: 'Alice Brown', priority: 'high' },
          { id: 2, type: 'review', patient: 'Charlie Wilson', priority: 'medium' },
          { id: 3, type: 'referral', patient: 'Diana Lee', priority: 'low' }
        ],
        quickActions: [
          { id: 'schedule', title: 'View Schedule', icon: 'calendar' },
          { id: 'patients', title: 'Patient List', icon: 'users' },
          { id: 'prescriptions', title: 'Prescriptions', icon: 'prescription' },
          { id: 'reports', title: 'Clinical Reports', icon: 'chart-bar' }
        ]
      };

      await auditService.logUserAction({
        userId,
        action: 'DASHBOARD_ACCESS',
        details: { dashboardType: 'provider' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: dashboardData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Provider dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load dashboard data'
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
  validateSession,
  authorizeRoles('admin'),
  globalRateLimit,
  async (req, res) => {
    try {
      const userId = req.user.id;
      
      const dashboardData = {
        user: {
          id: userId,
          name: `${req.user.firstName} ${req.user.lastName}`,
          email: req.user.email,
          department: 'IT Administration'
        },
        systemStats: {
          totalUsers: 1247,
          activeUsers: 892,
          todaysLogins: 156,
          securityAlerts: 3,
          systemUptime: '99.8%',
          avgResponseTime: '145ms'
        },
        securityOverview: {
          highRiskLogins: 2,
          failedAttempts: 8,
          lockedAccounts: 1,
          suspiciousActivity: 3
        },
        userStats: {
          patients: 1089,
          providers: 145,
          admins: 13,
          newRegistrations: 5
        },
        recentAlerts: [
          {
            id: 1,
            type: 'security',
            message: 'High-risk login detected from unusual location',
            time: '2024-01-12T14:30:00Z',
            severity: 'high'
          },
          {
            id: 2,
            type: 'system',
            message: 'Database backup completed successfully',
            time: '2024-01-12T02:00:00Z',
            severity: 'info'
          }
        ],
        quickActions: [
          { id: 'users', title: 'User Management', icon: 'users-cog' },
          { id: 'security', title: 'Security Logs', icon: 'shield-alt' },
          { id: 'system', title: 'System Settings', icon: 'cogs' },
          { id: 'reports', title: 'System Reports', icon: 'chart-line' }
        ]
      };

      await auditService.logUserAction({
        userId,
        action: 'DASHBOARD_ACCESS',
        details: { dashboardType: 'admin' },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: dashboardData,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      console.error('Admin dashboard error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load dashboard data'
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
  validateSession,
  globalRateLimit,
  async (req, res) => {
    try {
      const userId = req.user.id;
      const { page = 1, limit = 10 } = req.query;
      
      // Mock notifications based on user role
      const roleBasedNotifications = {
        patient: [
          {
            id: 1,
            type: 'appointment',
            title: 'Upcoming Appointment Reminder',
            message: 'You have an appointment with Dr. Smith tomorrow at 10:00 AM',
            timestamp: '2024-01-11T16:00:00Z',
            read: false,
            priority: 'medium'
          },
          {
            id: 2,
            type: 'result',
            title: 'Test Results Available',
            message: 'Your blood test results are now available in your portal',
            timestamp: '2024-01-10T14:30:00Z',
            read: false,
            priority: 'high'
          }
        ],
        provider: [
          {
            id: 1,
            type: 'schedule',
            title: 'Schedule Updated',
            message: 'New appointment added for tomorrow at 2:00 PM',
            timestamp: '2024-01-11T17:00:00Z',
            read: false,
            priority: 'medium'
          }
        ],
        admin: [
          {
            id: 1,
            type: 'security',
            title: 'Security Alert',
            message: 'Multiple failed login attempts detected',
            timestamp: '2024-01-11T18:00:00Z',
            read: false,
            priority: 'high'
          }
        ]
      };

      const notifications = roleBasedNotifications[req.user.role] || [];
      
      res.json({
        success: true,
        data: {
          notifications,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total: notifications.length,
            totalPages: Math.ceil(notifications.length / limit)
          }
        }
      });

    } catch (error) {
      console.error('Notifications error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to load notifications'
      });
    }
  }
);

/**
 * @route   POST /api/dashboard/notifications/:id/read
 * @desc    Mark notification as read
 * @access  Private
 */
router.post('/notifications/:id/read', 
  authenticateToken,
  validateSession,
  async (req, res) => {
    try {
      const notificationId = req.params.id;
      const userId = req.user.id;

      // In a real implementation, you would update the notification in the database
      await auditService.logUserAction({
        userId,
        action: 'NOTIFICATION_READ',
        details: { notificationId },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: 'Notification marked as read'
      });

    } catch (error) {
      console.error('Mark notification read error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update notification'
      });
    }
  }
);

module.exports = router;