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

module.exports = router;