/**
 * Winston Logger Configuration
 * 
 * Provides structured logging for the Secure Patient Portal with multiple
 * transport layers, log levels, and HIPAA-compliant audit trails.
 */

const winston = require('winston');
const path = require('path');

// Define log levels and colors
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4
};

const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white'
};

winston.addColors(logColors);

// Custom format for console output
const consoleFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.colorize({ all: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let metaStr = Object.keys(meta).length ? JSON.stringify(meta, null, 2) : '';
    return `${timestamp} [${level}]: ${message} ${metaStr}`;
  })
);

// Custom format for file output
const fileFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Ensure logs directory exists
const fs = require('fs');
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Create transports array
const transports = [
  // Console transport for development
  new winston.transports.Console({
    level: process.env.NODE_ENV === 'production' ? 'info' : 'debug',
    format: consoleFormat
  })
];

// Add file transports in production or when enabled
if (process.env.NODE_ENV === 'production' || process.env.LOG_FILE_ENABLED === 'true') {
  transports.push(
    // General application logs
    new winston.transports.File({
      filename: path.join(logsDir, 'app.log'),
      level: 'info',
      format: fileFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    
    // Error logs
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      format: fileFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 5
    }),
    
    // Security audit logs
    new winston.transports.File({
      filename: path.join(logsDir, 'security.log'),
      level: 'warn',
      format: fileFormat,
      maxsize: 10485760, // 10MB
      maxFiles: 10 // Keep more security logs
    })
  );
}

// Create the logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels: logLevels,
  format: fileFormat,
  defaultMeta: {
    service: 'secure-patient-portal',
    environment: process.env.NODE_ENV || 'development'
  },
  transports,
  
  // Handle uncaught exceptions and rejections
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log'),
      format: fileFormat
    })
  ],
  
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log'),
      format: fileFormat
    })
  ]
});

// Add HTTP request logging for Express
logger.http = (message, meta = {}) => {
  logger.log('http', message, meta);
};

// Security-specific logging methods
logger.security = (level, event, details = {}) => {
  const securityLog = {
    event,
    timestamp: new Date().toISOString(),
    details,
    severity: level
  };
  
  logger.log(level, `SECURITY_EVENT: ${event}`, securityLog);
};

// Audit logging for HIPAA compliance
logger.audit = (action, details = {}) => {
  const auditLog = {
    action,
    timestamp: new Date().toISOString(),
    details,
    type: 'AUDIT'
  };
  
  logger.info(`AUDIT: ${action}`, auditLog);
};

// Performance logging
logger.performance = (operation, duration, details = {}) => {
  const perfLog = {
    operation,
    duration,
    timestamp: new Date().toISOString(),
    details,
    type: 'PERFORMANCE'
  };
  
  logger.info(`PERFORMANCE: ${operation} completed in ${duration}ms`, perfLog);
};

// Database operation logging
logger.database = (operation, table, details = {}) => {
  const dbLog = {
    operation,
    table,
    timestamp: new Date().toISOString(),
    details,
    type: 'DATABASE'
  };
  
  logger.debug(`DATABASE: ${operation} on ${table}`, dbLog);
};

// User action logging
logger.userAction = (userId, action, details = {}) => {
  const userLog = {
    userId,
    action,
    timestamp: new Date().toISOString(),
    details,
    type: 'USER_ACTION'
  };
  
  logger.info(`USER_ACTION: ${action} by user ${userId}`, userLog);
};

module.exports = logger;