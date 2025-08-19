//server/models/SecurityLog.js
/**
 * Security Log Model
 * 
 * Defines the SecurityLog database model for comprehensive audit trails
 * and security event tracking. Essential for HIPAA compliance and
 * security monitoring in healthcare applications.
 */

const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');

const SecurityLog = sequelize.define('SecurityLog', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  // User information (nullable for system events)
  userId: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'User ID if event is user-related'
  },
  
  // Event classification
  eventType: {
    type: DataTypes.ENUM(
      'USER_LOGIN',
      'USER_LOGOUT', 
      'USER_REGISTERED',
      'LOGIN_FAILED_INVALID_PASSWORD',
      'LOGIN_FAILED_USER_NOT_FOUND',
      'LOGIN_ATTEMPT_LOCKED_ACCOUNT',
      'LOGIN_ATTEMPT_INACTIVE_ACCOUNT',
      'HIGH_RISK_LOGIN_DETECTED',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'PASSWORD_CHANGED',
      'PASSWORD_RESET_REQUESTED',
      'PASSWORD_RESET_COMPLETED',
      'EMAIL_VERIFICATION_SENT',
      'EMAIL_VERIFIED',
      'PROFILE_UPDATED',
      'TWO_FACTOR_ENABLED',
      'TWO_FACTOR_DISABLED',
      'TWO_FACTOR_VERIFICATION_FAILED',
      'RISK_ASSESSMENT',
      'SUSPICIOUS_ACTIVITY',
      'DATA_ACCESS',
      'DATA_MODIFICATION',
      'DATA_DELETION',
      'UNAUTHORIZED_ACCESS_ATTEMPT',
      'RATE_LIMIT_EXCEEDED',
      'SESSION_EXPIRED',
      'SESSION_CREATED',
      'SESSION_DESTROYED',
      'API_KEY_CREATED',
      'API_KEY_REVOKED',
      'SYSTEM_ERROR',
      'SECURITY_SCAN',
      'BACKUP_CREATED',
      'BACKUP_RESTORED',
      'CONFIGURATION_CHANGED',
      'USER_ROLE_CHANGED',
      'PERMISSIONS_MODIFIED'
    ),
    allowNull: false,
    comment: 'Type of security event'
  },
  
  // Event severity
  severity: {
    type: DataTypes.ENUM('low', 'medium', 'high', 'critical'),
    allowNull: false,
    defaultValue: 'low',
    comment: 'Security event severity level'
  },
  
  // Network information
  ipAddress: {
    type: DataTypes.STRING(45), // Supports IPv6
    allowNull: true,
    comment: 'Client IP address'
  },
  
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Client user agent string'
  },
  
  // Geographic information (from IP lookup)
  location: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Geographic location data from IP'
  },
  
  // Event details and context
  details: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Additional event details and metadata'
  },
  
  // Session information
  sessionId: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Session identifier if applicable'
  },
  
  // Request information
  requestId: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'Unique request identifier for correlation'
  },
  
  endpoint: {
    type: DataTypes.STRING(500),
    allowNull: true,
    comment: 'API endpoint accessed'
  },
  
  httpMethod: {
    type: DataTypes.ENUM('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'),
    allowNull: true,
    comment: 'HTTP method used'
  },
  
  statusCode: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'HTTP response status code'
  },
  
  // Risk assessment data
  riskScore: {
    type: DataTypes.INTEGER,
    allowNull: true,
    validate: {
      min: 0,
      max: 100
    },
    comment: 'Risk score if applicable (0-100)'
  },
  
  riskFactors: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Risk factors that contributed to the score'
  },
  
  // Response information
  responseTime: {
    type: DataTypes.INTEGER,
    allowNull: true,
    comment: 'Response time in milliseconds'
  },
  
  // Error information
  errorCode: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Error code if event represents an error'
  },
  
  errorMessage: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Error message if applicable'
  },
  
  // Alert and notification status
  alertSent: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether an alert was sent for this event'
  },
  
  alertRecipients: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Recipients of security alerts'
  },
  
  // Investigation status
  investigated: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether this event has been investigated'
  },
  
  investigatedBy: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'User ID who investigated this event'
  },
  
  investigationNotes: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'Notes from security investigation'
  },
  
  // Resolution status
  resolved: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether this security event is resolved'
  },
  
  resolvedAt: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the event was resolved'
  },
  
  resolvedBy: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'User ID who resolved this event'
  },
  
  // Correlation with other events
  correlationId: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'ID to correlate related security events'
  },
  
  parentEventId: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'Parent event ID for event chains'
  }
}, {
  // Model options
  tableName: 'security_logs',
  timestamps: true,
  paranoid: false, // Don't soft delete security logs
  underscored: true,
  
  // Indexes for performance
  indexes: [
    {
      fields: ['event_type']
    },
    {
      fields: ['user_id']
    },
    {
      fields: ['severity']
    },
    {
      fields: ['ip_address']
    },
    {
      fields: ['created_at']
    },
    {
      fields: ['alert_sent']
    },
    {
      fields: ['investigated']
    },
    {
      fields: ['resolved']
    },
    {
      fields: ['correlation_id']
    },
    {
      fields: ['risk_score']
    },
    // Composite indexes for common queries
    {
      fields: ['user_id', 'event_type', 'created_at']
    },
    {
      fields: ['severity', 'resolved', 'created_at']
    }
  ],
  
  // Model hooks
  hooks: {
    beforeCreate: async (log, options) => {
      // Generate correlation ID if not provided
      if (!log.correlationId && options.correlationId) {
        log.correlationId = options.correlationId;
      }
      
      // Set request ID if provided in options
      if (!log.requestId && options.requestId) {
        log.requestId = options.requestId;
      }
    },
    
    afterCreate: async (log, options) => {
      // Auto-alert for high severity events
      if (log.severity === 'high' || log.severity === 'critical') {
        // In a real implementation, this would trigger alert notifications
        console.log(`High severity security event created: ${log.eventType}`);
      }
    }
  }
});

/**
 * Instance Methods
 */

// Check if event requires investigation
SecurityLog.prototype.requiresInvestigation = function() {
  const investigationEvents = [
    'HIGH_RISK_LOGIN_DETECTED',
    'SUSPICIOUS_ACTIVITY',
    'UNAUTHORIZED_ACCESS_ATTEMPT',
    'LOGIN_FAILED_INVALID_PASSWORD'
  ];
  
  return investigationEvents.includes(this.eventType) || 
         this.severity === 'high' || 
         this.severity === 'critical';
};

// Get event age in hours
SecurityLog.prototype.getAgeInHours = function() {
  return Math.floor((new Date() - this.createdAt) / (1000 * 60 * 60));
};

// Check if event is recent (last 24 hours)
SecurityLog.prototype.isRecent = function() {
  return this.getAgeInHours() < 24;
};

// Generate event summary
SecurityLog.prototype.getSummary = function() {
  return {
    id: this.id,
    eventType: this.eventType,
    severity: this.severity,
    userId: this.userId,
    ipAddress: this.ipAddress,
    timestamp: this.createdAt,
    riskScore: this.riskScore,
    resolved: this.resolved
  };
};

/**
 * Class Methods (Static)
 */

// Find events by user
SecurityLog.findByUser = function(userId, limit = 50) {
  return this.findAll({
    where: { userId },
    order: [['createdAt', 'DESC']],
    limit
  });
};

// Find unresolved high-severity events
SecurityLog.findUnresolvedHighSeverity = function() {
  return this.findAll({
    where: {
      severity: ['high', 'critical'],
      resolved: false
    },
    order: [['createdAt', 'DESC']]
  });
};

// Find events by IP address
SecurityLog.findByIP = function(ipAddress, timeWindow = 24) {
  const since = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  
  return this.findAll({
    where: {
      ipAddress,
      createdAt: {
        [sequelize.Sequelize.Op.gte]: since
      }
    },
    order: [['createdAt', 'DESC']]
  });
};

// Get security statistics
SecurityLog.getStatistics = async function(timeWindow = 24) {
  const since = new Date(Date.now() - timeWindow * 60 * 60 * 1000);
  
  const totalEvents = await this.count({
    where: {
      createdAt: {
        [sequelize.Sequelize.Op.gte]: since
      }
    }
  });
  
  const highSeverityEvents = await this.count({
    where: {
      severity: ['high', 'critical'],
      createdAt: {
        [sequelize.Sequelize.Op.gte]: since
      }
    }
  });
  
  const unresolvedEvents = await this.count({
    where: {
      resolved: false,
      createdAt: {
        [sequelize.Sequelize.Op.gte]: since
      }
    }
  });
  
  return {
    totalEvents,
    highSeverityEvents,
    unresolvedEvents,
    timeWindow: `${timeWindow} hours`
  };
};

// Create correlation between events
SecurityLog.correlateEvents = async function(eventIds, correlationId) {
  return this.update(
    { correlationId },
    {
      where: {
        id: {
          [sequelize.Sequelize.Op.in]: eventIds
        }
      }
    }
  );
};

module.exports = SecurityLog;