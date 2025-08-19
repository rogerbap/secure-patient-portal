//server/services/auditService.js
/**
 * Audit Service
 * 
 * Provides comprehensive audit logging services for HIPAA compliance
 * and security monitoring. Tracks all user actions, system events,
 * and data access patterns in healthcare applications.
 */

const SecurityLog = require('../models/securityLog');
const logger = require('../utils/logger');
const geoip = require('geoip-lite');

class AuditService {
  constructor() {
    this.isEnabled = process.env.AUDIT_LOG_ENABLED !== 'false';
  }

  /**
   * Log user action for audit trail
   * @param {Object} params - Action parameters
   * @param {string} params.userId - User ID
   * @param {string} params.action - Action performed
   * @param {Object} params.details - Additional details
   * @param {string} params.ipAddress - Client IP address
   * @param {string} params.userAgent - User agent string
   * @param {string} params.sessionId - Session ID
   */
  async logUserAction(params) {
    if (!this.isEnabled) return;

    try {
      const {
        userId,
        action,
        details = {},
        ipAddress,
        userAgent,
        sessionId,
        endpoint,
        httpMethod,
        statusCode,
        responseTime
      } = params;

      // Get geographic information from IP
      const location = this.getLocationFromIP(ipAddress);

      // Determine severity based on action type
      const severity = this.determineSeverity(action);

      // Create security log entry
      await SecurityLog.create({
        userId,
        eventType: action,
        severity,
        ipAddress,
        userAgent,
        location,
        sessionId,
        endpoint,
        httpMethod,
        statusCode,
        responseTime,
        details: {
          ...details,
          auditTrail: true,
          timestamp: new Date().toISOString(),
          actionCategory: this.getActionCategory(action)
        }
      });

      // Log to file system as well
      logger.audit(action, {
        userId,
        ipAddress,
        userAgent,
        details,
        location
      });

      // Check if action requires additional monitoring
      await this.checkForSuspiciousActivity(userId, action, ipAddress);

    } catch (error) {
      logger.error('Failed to log user action:', error);
      // Don't throw error to avoid breaking the main application flow
    }
  }

  /**
   * Log security event
   * @param {Object} params - Event parameters
   */
  async logSecurityEvent(params) {
    if (!this.isEnabled) return;

    try {
      const {
        eventType,
        severity = 'medium',
        userId,
        ipAddress,
        userAgent,
        details = {},
        endpoint,
        sessionId
      } = params;

      const location = this.getLocationFromIP(ipAddress);

      await SecurityLog.create({
        userId,
        eventType,
        severity,
        ipAddress,
        userAgent,
        location,
        sessionId,
        endpoint,
        details: {
          ...details,
          securityEvent: true,
          timestamp: new Date().toISOString()
        }
      });

      // Log high severity events immediately
      if (severity === 'high' || severity === 'critical') {
        logger.security(severity, eventType, {
          userId,
          ipAddress,
          details
        });

        // Trigger alerts for critical events
        await this.triggerSecurityAlert(eventType, params);
      }

    } catch (error) {
      logger.error('Failed to log security event:', error);
    }
  }

  /**
   * Log data access for HIPAA compliance
   * @param {Object} params - Data access parameters
   */
  async logDataAccess(params) {
    if (!this.isEnabled) return;

    try {
      const {
        userId,
        dataType,
        operation, // CREATE, READ, UPDATE, DELETE
        recordId,
        patientId,
        ipAddress,
        userAgent,
        details = {}
      } = params;

      const eventType = `DATA_${operation}`;
      const location = this.getLocationFromIP(ipAddress);

      await SecurityLog.create({
        userId,
        eventType,
        severity: this.getDataAccessSeverity(operation, dataType),
        ipAddress,
        userAgent,
        location,
        details: {
          ...details,
          dataType,
          operation,
          recordId,
          patientId,
          dataAccess: true,
          timestamp: new Date().toISOString(),
          complianceLevel: 'HIPAA'
        }
      });

      // Special handling for sensitive data access
      if (this.isSensitiveData(dataType)) {
        await this.logSensitiveDataAccess({
          userId,
          dataType,
          operation,
          recordId,
          patientId,
          ipAddress
        });
      }

    } catch (error) {
      logger.error('Failed to log data access:', error);
    }
  }

  /**
   * Log authentication attempts
   * @param {Object} params - Authentication parameters
   */
  async logAuthenticationAttempt(params) {
    if (!this.isEnabled) return;

    try {
      const {
        email,
        success,
        userId,
        ipAddress,
        userAgent,
        failureReason,
        riskScore,
        riskFactors
      } = params;

      const eventType = success ? 'USER_LOGIN' : 'LOGIN_FAILED';
      const severity = success ? 'low' : 'medium';
      const location = this.getLocationFromIP(ipAddress);

      await SecurityLog.create({
        userId,
        eventType,
        severity,
        ipAddress,
        userAgent,
        location,
        riskScore,
        riskFactors,
        details: {
          email,
          success,
          failureReason,
          timestamp: new Date().toISOString(),
          authenticationAttempt: true
        }
      });

      // Track failed attempts for brute force detection
      if (!success) {
        await this.trackFailedAttempts(email, ipAddress);
      }

    } catch (error) {
      logger.error('Failed to log authentication attempt:', error);
    }
  }

  /**
   * Get user's audit trail
   * @param {string} userId - User ID
   * @param {Object} options - Query options
   * @returns {Array} Audit trail entries
   */
  async getUserAuditTrail(userId, options = {}) {
    try {
      const {
        limit = 100,
        offset = 0,
        startDate,
        endDate,
        eventTypes,
        severity
      } = options;

      const whereClause = { userId };

      // Add date range filter
      if (startDate || endDate) {
        whereClause.createdAt = {};
        if (startDate) whereClause.createdAt[SecurityLog.sequelize.Sequelize.Op.gte] = startDate;
        if (endDate) whereClause.createdAt[SecurityLog.sequelize.Sequelize.Op.lte] = endDate;
      }

      // Add event type filter
      if (eventTypes && eventTypes.length > 0) {
        whereClause.eventType = {
          [SecurityLog.sequelize.Sequelize.Op.in]: eventTypes
        };
      }

      // Add severity filter
      if (severity) {
        whereClause.severity = severity;
      }

      return await SecurityLog.findAll({
        where: whereClause,
        order: [['createdAt', 'DESC']],
        limit,
        offset,
        attributes: [
          'id',
          'eventType',
          'severity',
          'ipAddress',
          'location',
          'details',
          'createdAt'
        ]
      });

    } catch (error) {
      logger.error('Failed to get user audit trail:', error);
      return [];
    }
  }

  /**
   * Get system audit statistics
   * @param {Object} options - Query options
   * @returns {Object} Audit statistics
   */
  async getAuditStatistics(options = {}) {
    try {
      const {
        timeRange = '24h',
        groupBy = 'hour'
      } = options;

      const timeRangeMs = this.parseTimeRange(timeRange);
      const since = new Date(Date.now() - timeRangeMs);

      const totalEvents = await SecurityLog.count({
        where: {
          createdAt: {
            [SecurityLog.sequelize.Sequelize.Op.gte]: since
          }
        }
      });

      const eventsBySeverity = await SecurityLog.findAll({
        attributes: [
          'severity',
          [SecurityLog.sequelize.fn('COUNT', '*'), 'count']
        ],
        where: {
          createdAt: {
            [SecurityLog.sequelize.Sequelize.Op.gte]: since
          }
        },
        group: ['severity']
      });

      const eventsByType = await SecurityLog.findAll({
        attributes: [
          'eventType',
          [SecurityLog.sequelize.fn('COUNT', '*'), 'count']
        ],
        where: {
          createdAt: {
            [SecurityLog.sequelize.Sequelize.Op.gte]: since
          }
        },
        group: ['eventType'],
        order: [[SecurityLog.sequelize.fn('COUNT', '*'), 'DESC']],
        limit: 10
      });

      return {
        timeRange,
        totalEvents,
        eventsBySeverity: eventsBySeverity.map(item => ({
          severity: item.severity,
          count: parseInt(item.get('count'))
        })),
        topEventTypes: eventsByType.map(item => ({
          eventType: item.eventType,
          count: parseInt(item.get('count'))
        }))
      };

    } catch (error) {
      logger.error('Failed to get audit statistics:', error);
      return null;
    }
  }

  /**
   * Generate compliance report
   * @param {Object} options - Report options
   * @returns {Object} Compliance report
   */
  async generateComplianceReport(options = {}) {
    try {
      const {
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000), // 30 days
        endDate = new Date(),
        includeDataAccess = true,
        includeAuthentication = true,
        includeSecurityEvents = true
      } = options;

      const report = {
        reportPeriod: {
          startDate,
          endDate
        },
        summary: {},
        details: {}
      };

      // Data access events for HIPAA compliance
      if (includeDataAccess) {
        const dataAccessEvents = await SecurityLog.findAll({
          where: {
            eventType: {
              [SecurityLog.sequelize.Sequelize.Op.in]: [
                'DATA_CREATE', 'DATA_READ', 'DATA_UPDATE', 'DATA_DELETE'
              ]
            },
            createdAt: {
              [SecurityLog.sequelize.Sequelize.Op.between]: [startDate, endDate]
            }
          },
          order: [['createdAt', 'DESC']]
        });

        report.details.dataAccess = dataAccessEvents.map(event => ({
          timestamp: event.createdAt,
          userId: event.userId,
          operation: event.details.operation,
          dataType: event.details.dataType,
          patientId: event.details.patientId,
          ipAddress: event.ipAddress
        }));

        report.summary.dataAccessEvents = dataAccessEvents.length;
      }

      // Authentication events
      if (includeAuthentication) {
        const authEvents = await SecurityLog.findAll({
          where: {
            eventType: {
              [SecurityLog.sequelize.Sequelize.Op.in]: [
                'USER_LOGIN', 'USER_LOGOUT', 'LOGIN_FAILED'
              ]
            },
            createdAt: {
              [SecurityLog.sequelize.Sequelize.Op.between]: [startDate, endDate]
            }
          },
          order: [['createdAt', 'DESC']]
        });

        report.summary.authenticationEvents = authEvents.length;
        report.summary.failedLogins = authEvents.filter(e => e.eventType.includes('FAILED')).length;
      }

      // Security events
      if (includeSecurityEvents) {
        const securityEvents = await SecurityLog.findAll({
          where: {
            severity: {
              [SecurityLog.sequelize.Sequelize.Op.in]: ['high', 'critical']
            },
            createdAt: {
              [SecurityLog.sequelize.Sequelize.Op.between]: [startDate, endDate]
            }
          },
          order: [['createdAt', 'DESC']]
        });

        report.summary.highSeverityEvents = securityEvents.length;
        report.details.securityEvents = securityEvents.map(event => ({
          timestamp: event.createdAt,
          eventType: event.eventType,
          severity: event.severity,
          userId: event.userId,
          ipAddress: event.ipAddress,
          details: event.details
        }));
      }

      return report;

    } catch (error) {
      logger.error('Failed to generate compliance report:', error);
      return null;
    }
  }

  /**
   * Helper Methods
   */

  getLocationFromIP(ipAddress) {
    if (!ipAddress) return null;

    try {
      const geo = geoip.lookup(ipAddress);
      if (geo) {
        return {
          country: geo.country,
          region: geo.region,
          city: geo.city,
          ll: geo.ll, // latitude, longitude
          timezone: geo.timezone
        };
      }
    } catch (error) {
      logger.debug('Failed to get location from IP:', error);
    }

    return null;
  }

  determineSeverity(action) {
    const highSeverityActions = [
      'USER_ROLE_CHANGED',
      'PERMISSIONS_MODIFIED',
      'DATA_DELETE',
      'ACCOUNT_LOCKED',
      'PASSWORD_RESET_COMPLETED'
    ];

    const mediumSeverityActions = [
      'USER_LOGIN',
      'DATA_UPDATE',
      'PROFILE_UPDATED',
      'PASSWORD_CHANGED'
    ];

    if (highSeverityActions.includes(action)) return 'high';
    if (mediumSeverityActions.includes(action)) return 'medium';
    return 'low';
  }

  getActionCategory(action) {
    if (action.includes('LOGIN') || action.includes('LOGOUT')) return 'authentication';
    if (action.includes('DATA_')) return 'data_access';
    if (action.includes('PASSWORD') || action.includes('PROFILE')) return 'account_management';
    if (action.includes('ROLE') || action.includes('PERMISSION')) return 'authorization';
    return 'general';
  }

  getDataAccessSeverity(operation, dataType) {
    if (operation === 'DELETE') return 'high';
    if (this.isSensitiveData(dataType)) return 'medium';
    return 'low';
  }

  isSensitiveData(dataType) {
    const sensitiveTypes = [
      'medical_record',
      'prescription',
      'mental_health',
      'substance_abuse',
      'genetic_information',
      'payment_info'
    ];
    return sensitiveTypes.includes(dataType);
  }

  async logSensitiveDataAccess(params) {
    // Additional logging for sensitive data access
    logger.security('medium', 'SENSITIVE_DATA_ACCESS', params);
  }

  async checkForSuspiciousActivity(userId, action, ipAddress) {
    // Check for rapid successive actions
    const recentActions = await SecurityLog.count({
      where: {
        userId,
        createdAt: {
          [SecurityLog.sequelize.Sequelize.Op.gte]: new Date(Date.now() - 5 * 60 * 1000) // Last 5 minutes
        }
      }
    });

    if (recentActions > 50) {
      await this.logSecurityEvent({
        eventType: 'SUSPICIOUS_ACTIVITY',
        severity: 'high',
        userId,
        ipAddress,
        details: {
          reason: 'Rapid successive actions detected',
          actionCount: recentActions,
          timeWindow: '5 minutes'
        }
      });
    }
  }

  async trackFailedAttempts(email, ipAddress) {
    const failedAttempts = await SecurityLog.count({
      where: {
        eventType: {
          [SecurityLog.sequelize.Sequelize.Op.like]: 'LOGIN_FAILED%'
        },
        [SecurityLog.sequelize.Sequelize.Op.or]: [
          { 'details.email': email },
          { ipAddress }
        ],
        createdAt: {
          [SecurityLog.sequelize.Sequelize.Op.gte]: new Date(Date.now() - 60 * 60 * 1000) // Last hour
        }
      }
    });

    if (failedAttempts >= 5) {
      await this.logSecurityEvent({
        eventType: 'BRUTE_FORCE_DETECTED',
        severity: 'high',
        ipAddress,
        details: {
          email,
          failedAttempts,
          timeWindow: '1 hour'
        }
      });
    }
  }

  async triggerSecurityAlert(eventType, params) {
    // In a real implementation, this would send alerts via email, SMS, etc.
    logger.warn(`Security Alert: ${eventType}`, params);
  }

  parseTimeRange(timeRange) {
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
}

// Create singleton instance
const auditService = new AuditService();

module.exports = auditService;