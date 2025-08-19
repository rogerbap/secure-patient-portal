
const express = require('express');
const router = express.Router();

// Import services and middleware
const { authenticateToken, authorizeRoles, optionalAuth } = require('../middleware/auth');
const { globalRateLimit } = require('../middleware/rateLimit');
const riskAssessmentService = require('../services/riskAssessmentService');
const auditService = require('../services/auditService');
const SecurityLog = require('../models/securityLog');
const logger = require('../utils/logger');

/**
 * @route   POST /api/security/assess-risk
 * @desc    Perform risk assessment for login attempt
 * @access  Public (used during authentication)
 */
router.post('/assess-risk', 
  globalRateLimit,
  async (req, res) => {
    try {
      const { userId, ipAddress, userAgent } = req.body;
      
      if (!userId || !ipAddress || !userAgent) {
        return res.status(400).json({
          success: false,
          message: 'Missing required parameters for risk assessment'
        });
      }

      const riskAssessment = await riskAssessmentService.assessLoginRisk({
        userId,
        ipAddress,
        userAgent,
        timestamp: new Date()
      });

      res.json({
        success: true,
        riskAssessment,
        timestamp: new Date().toISOString()
      });

    } catch (error) {
      logger.error('Risk assessment error:', error);
      res.status(500).json({
        success: false,
        message: 'Risk assessment failed',
        riskAssessment: {
          riskScore: 100,
          riskLevel: 'HIGH',
          requiresAdditionalVerification: true
        }
      });
    }
  }
);

/**
 * @route   GET /api/security/logs
 * @desc    Get security logs (admin only)
 * @access  Private (Admin)
 */
router.get('/logs', 
  authenticateToken,
  authorizeRoles('admin'),
  globalRateLimit,
  async (req, res) => {
    try {
      const { 
        page = 1, 
        limit = 50, 
        severity, 
        eventType, 
        startDate, 
        endDate,
        userId 
      } = req.query;

      const offset = (page - 1) * limit;
      const whereClause = {};

      // Apply filters
      if (severity) {
        whereClause.severity = severity;
      }
      
      if (eventType) {
        whereClause.eventType = eventType;
      }
      
      if (userId) {
        whereClause.userId = userId;
      }
      
      if (startDate || endDate) {
        whereClause.createdAt = {};
        if (startDate) {
          whereClause.createdAt[SecurityLog.sequelize.Sequelize.Op.gte] = new Date(startDate);
        }
        if (endDate) {
          whereClause.createdAt[SecurityLog.sequelize.Sequelize.Op.lte] = new Date(endDate);
        }
      }

      const { rows: logs, count: total } = await SecurityLog.findAndCountAll({
        where: whereClause,
        order: [['createdAt', 'DESC']],
        limit: parseInt(limit),
        offset: parseInt(offset),
        attributes: [
          'id', 'eventType', 'severity', 'userId', 'ipAddress', 
          'location', 'details', 'createdAt', 'investigated', 'resolved'
        ]
      });

      // Log admin access to security logs
      await auditService.logUserAction({
        userId: req.user.id,
        action: 'SECURITY_LOGS_ACCESSED',
        details: { 
          filters: { severity, eventType, startDate, endDate, userId },
          resultsCount: logs.length 
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: {
          logs,
          pagination: {
            page: parseInt(page),
            limit: parseInt(limit),
            total,
            totalPages: Math.ceil(total / limit)
          }
        }
      });

    } catch (error) {
      logger.error('Security logs retrieval error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve security logs'
      });
    }
  }
);

/**
 * @route   GET /api/security/logs/user/:userId
 * @desc    Get user-specific security logs
 * @access  Private (Users can view their own, admins can view any)
 */
router.get('/logs/user/:userId', 
  authenticateToken,
  globalRateLimit,
  async (req, res) => {
    try {
      const targetUserId = req.params.userId;
      const requestingUserId = req.user.id;
      const requestingUserRole = req.user.role;

      // Check authorization - users can only view their own logs, admins can view any
      if (requestingUserRole !== 'admin' && requestingUserId !== targetUserId) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to view these security logs'
        });
      }

      const { page = 1, limit = 20 } = req.query;
      const offset = (page - 1) * limit;

      const logs = await SecurityLog.findAll({
        where: { userId: targetUserId },
        order: [['createdAt', 'DESC']],
        limit: parseInt(limit),
        offset: parseInt(offset),
        attributes: [
          'id', 'eventType', 'severity', 'ipAddress', 
          'location', 'details', 'createdAt'
        ]
      });

      // Log the access
      await auditService.logUserAction({
        userId: requestingUserId,
        action: 'USER_SECURITY_LOGS_ACCESSED',
        details: { 
          targetUserId,
          logsCount: logs.length 
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        data: {
          logs,
          userId: targetUserId
        }
      });

    } catch (error) {
      logger.error('User security logs error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve user security logs'
      });
    }
  }
);

/**
 * @route   GET /api/security/statistics
 * @desc    Get security statistics
 * @access  Private (Admin and Provider)
 */
router.get('/statistics', 
  authenticateToken,
  authorizeRoles(['admin', 'provider']),
  globalRateLimit,
  async (req, res) => {
    try {
      const { timeRange = '24h' } = req.query;
      
      const statistics = await auditService.getAuditStatistics({ timeRange });
      const riskStatistics = await riskAssessmentService.getRiskStatistics();

      res.json({
        success: true,
        data: {
          audit: statistics,
          risk: riskStatistics,
          timeRange,
          generatedAt: new Date().toISOString()
        }
      });

    } catch (error) {
      logger.error('Security statistics error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve security statistics'
      });
    }
  }
);

/**
 * @route   POST /api/security/investigate/:logId
 * @desc    Mark security log as investigated
 * @access  Private (Admin only)
 */
router.post('/investigate/:logId', 
  authenticateToken,
  authorizeRoles('admin'),
  async (req, res) => {
    try {
      const { logId } = req.params;
      const { notes } = req.body;
      const investigatorId = req.user.id;

      const securityLog = await SecurityLog.findByPk(logId);
      
      if (!securityLog) {
        return res.status(404).json({
          success: false,
          message: 'Security log not found'
        });
      }

      await securityLog.update({
        investigated: true,
        investigatedBy: investigatorId,
        investigationNotes: notes || 'Investigated by security team'
      });

      // Log the investigation action
      await auditService.logUserAction({
        userId: investigatorId,
        action: 'SECURITY_LOG_INVESTIGATED',
        details: { 
          logId,
          originalEventType: securityLog.eventType,
          originalSeverity: securityLog.severity,
          notes 
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: 'Security log marked as investigated'
      });

    } catch (error) {
      logger.error('Security investigation error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update investigation status'
      });
    }
  }
);

/**
 * @route   POST /api/security/resolve/:logId
 * @desc    Mark security log as resolved
 * @access  Private (Admin only)
 */
router.post('/resolve/:logId', 
  authenticateToken,
  authorizeRoles('admin'),
  async (req, res) => {
    try {
      const { logId } = req.params;
      const { resolution } = req.body;
      const resolverId = req.user.id;

      const securityLog = await SecurityLog.findByPk(logId);
      
      if (!securityLog) {
        return res.status(404).json({
          success: false,
          message: 'Security log not found'
        });
      }

      await securityLog.update({
        resolved: true,
        resolvedAt: new Date(),
        resolvedBy: resolverId,
        investigationNotes: securityLog.investigationNotes + 
          `\n\nResolution: ${resolution || 'Resolved by security team'}`
      });

      // Log the resolution action
      await auditService.logUserAction({
        userId: resolverId,
        action: 'SECURITY_LOG_RESOLVED',
        details: { 
          logId,
          originalEventType: securityLog.eventType,
          originalSeverity: securityLog.severity,
          resolution 
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: 'Security log marked as resolved'
      });

    } catch (error) {
      logger.error('Security resolution error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to update resolution status'
      });
    }
  }
);

/**
 * @route   GET /api/security/risk-history/:userId
 * @desc    Get risk assessment history for user
 * @access  Private (Users can view their own, admins can view any)
 */
router.get('/risk-history/:userId', 
  authenticateToken,
  globalRateLimit,
  async (req, res) => {
    try {
      const targetUserId = req.params.userId;
      const requestingUserId = req.user.id;
      const requestingUserRole = req.user.role;

      // Check authorization
      if (requestingUserRole !== 'admin' && requestingUserId !== targetUserId) {
        return res.status(403).json({
          success: false,
          message: 'Insufficient permissions to view risk history'
        });
      }

      const { limit = 10 } = req.query;
      
      const riskHistory = await riskAssessmentService.getRiskHistory(targetUserId, parseInt(limit));

      res.json({
        success: true,
        data: {
          riskHistory,
          userId: targetUserId
        }
      });

    } catch (error) {
      logger.error('Risk history error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve risk history'
      });
    }
  }
);

/**
 * @route   POST /api/security/report-incident
 * @desc    Report security incident
 * @access  Private
 */
router.post('/report-incident', 
  authenticateToken,
  globalRateLimit,
  async (req, res) => {
    try {
      const { incidentType, description, severity = 'medium' } = req.body;
      const reporterId = req.user.id;

      if (!incidentType || !description) {
        return res.status(400).json({
          success: false,
          message: 'Incident type and description are required'
        });
      }

      // Log the incident report
      await auditService.logSecurityEvent({
        eventType: 'SECURITY_INCIDENT_REPORTED',
        severity,
        userId: reporterId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          incidentType,
          description,
          reportedBy: reporterId
        }
      });

      // Log user action
      await auditService.logUserAction({
        userId: reporterId,
        action: 'SECURITY_INCIDENT_REPORTED',
        details: { incidentType, severity },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      res.json({
        success: true,
        message: 'Security incident reported successfully'
      });

    } catch (error) {
      logger.error('Incident reporting error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to report security incident'
      });
    }
  }
);

/**
 * @route   GET /api/security/system-status
 * @desc    Get overall system security status
 * @access  Public (limited information) / Private (detailed information)
 */
router.get('/system-status', 
  optionalAuth,
  globalRateLimit,
  async (req, res) => {
    try {
      const isAuthenticated = !!req.user;
      const isAdmin = req.user?.role === 'admin';

      // Basic status for all users
      const basicStatus = {
        securityLevel: 'OPERATIONAL',
        lastScanTime: new Date().toISOString(),
        activeMonitoring: true,
        timestamp: new Date().toISOString()
      };

      // Enhanced status for authenticated users
      if (isAuthenticated) {
        const recentAlerts = await SecurityLog.count({
          where: {
            severity: ['high', 'critical'],
            createdAt: {
              [SecurityLog.sequelize.Sequelize.Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000)
            }
          }
        });

        basicStatus.recentAlerts = recentAlerts;
        basicStatus.userSecurityLevel = 'PROTECTED';
      }

      // Detailed status for admins
      if (isAdmin) {
        const statistics = await auditService.getAuditStatistics({ timeRange: '24h' });
        basicStatus.detailedStats = statistics;
        basicStatus.systemHealth = {
          riskEngine: 'OPERATIONAL',
          auditLogging: 'OPERATIONAL',
          rateLimit: 'OPERATIONAL',
          authentication: 'OPERATIONAL'
        };
      }

      res.json({
        success: true,
        data: basicStatus
      });

    } catch (error) {
      logger.error('System status error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to retrieve system status'
      });
    }
  }
);


module.exports = router;