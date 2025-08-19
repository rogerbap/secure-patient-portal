/**
 * Health Check Routes
 * 
 * Provides system health monitoring, status checks, and diagnostic endpoints
 * for the healthcare portal infrastructure.
 * 
 * @author Your Name
 * @version 1.0.0
 */

const express = require('express');
const router = express.Router();
const { sequelize } = require('../config/database');
const logger = require('../utils/logger');

/**
 * @route   GET /api/health
 * @desc    Basic health check endpoint
 * @access  Public
 */
router.get('/', async (req, res) => {
  try {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: Math.floor(process.uptime()),
      features: {
        riskAssessment: process.env.RISK_ASSESSMENT_ENABLED !== 'false',
        authentication: true,
        rateLimit: true,
        auditLogging: process.env.AUDIT_LOG_ENABLED !== 'false'
      }
    };

    res.status(200).json(healthStatus);
    
  } catch (error) {
    logger.error('Health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Health check failed'
    });
  }
});

/**
 * @route   GET /api/health/detailed
 * @desc    Detailed health check with system metrics
 * @access  Public
 */
router.get('/detailed', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const checks = {
      database: await checkDatabase(),
      memory: checkMemory(),
      disk: checkDisk(),
      services: await checkServices()
    };

    const allHealthy = Object.values(checks).every(check => check.status === 'healthy');
    const responseTime = Date.now() - startTime;

    const detailedHealth = {
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: {
        seconds: Math.floor(process.uptime()),
        human: formatUptime(process.uptime())
      },
      checks,
      system: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        pid: process.pid
      }
    };

    const statusCode = allHealthy ? 200 : 503;
    res.status(statusCode).json(detailedHealth);
    
  } catch (error) {
    logger.error('Detailed health check failed:', error);
    res.status(503).json({
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Detailed health check failed',
      responseTime: `${Date.now() - startTime}ms`
    });
  }
});

/**
 * @route   GET /api/health/ready
 * @desc    Readiness probe for Kubernetes/Docker
 * @access  Public
 */
router.get('/ready', async (req, res) => {
  try {
    // Check if application is ready to serve traffic
    const dbCheck = await checkDatabase();
    
    if (dbCheck.status === 'healthy') {
      res.status(200).json({
        status: 'ready',
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(503).json({
        status: 'not ready',
        reason: 'Database not available',
        timestamp: new Date().toISOString()
      });
    }
    
  } catch (error) {
    logger.error('Readiness check failed:', error);
    res.status(503).json({
      status: 'not ready',
      reason: 'Service unavailable',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @route   GET /api/health/live
 * @desc    Liveness probe for Kubernetes/Docker
 * @access  Public
 */
router.get('/live', (req, res) => {
  // Simple liveness check - if we can respond, we're alive
  res.status(200).json({
    status: 'alive',
    timestamp: new Date().toISOString(),
    uptime: Math.floor(process.uptime())
  });
});

/**
 * @route   GET /api/health/metrics
 * @desc    Prometheus-style metrics endpoint
 * @access  Public
 */
router.get('/metrics', async (req, res) => {
  try {
    const memUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    // Generate Prometheus-style metrics
    const metrics = [
      `# HELP nodejs_memory_usage_bytes Memory usage in bytes`,
      `# TYPE nodejs_memory_usage_bytes gauge`,
      `nodejs_memory_usage_bytes{type="rss"} ${memUsage.rss}`,
      `nodejs_memory_usage_bytes{type="heapTotal"} ${memUsage.heapTotal}`,
      `nodejs_memory_usage_bytes{type="heapUsed"} ${memUsage.heapUsed}`,
      `nodejs_memory_usage_bytes{type="external"} ${memUsage.external}`,
      ``,
      `# HELP nodejs_uptime_seconds Process uptime in seconds`,
      `# TYPE nodejs_uptime_seconds counter`,
      `nodejs_uptime_seconds ${process.uptime()}`,
      ``,
      `# HELP nodejs_cpu_usage_micros CPU usage in microseconds`,
      `# TYPE nodejs_cpu_usage_micros counter`,
      `nodejs_cpu_usage_micros{type="user"} ${cpuUsage.user}`,
      `nodejs_cpu_usage_micros{type="system"} ${cpuUsage.system}`,
      ``
    ].join('\n');

    res.set('Content-Type', 'text/plain');
    res.send(metrics);
    
  } catch (error) {
    logger.error('Metrics generation failed:', error);
    res.status(500).send('# Metrics unavailable');
  }
});

/**
 * Helper Functions
 */

/**
 * Check database connectivity
 */
async function checkDatabase() {
  try {
    await sequelize.authenticate();
    
    // Additional check - simple query
    const [results] = await sequelize.query('SELECT 1 as test');
    
    if (results && results[0] && results[0].test === 1) {
      return {
        status: 'healthy',
        message: 'Database connection successful',
        dialect: sequelize.getDialect(),
        database: sequelize.getDatabaseName()
      };
    } else {
      return {
        status: 'unhealthy',
        message: 'Database query failed'
      };
    }
    
  } catch (error) {
    logger.error('Database health check failed:', error);
    return {
      status: 'unhealthy',
      message: 'Database connection failed',
      error: error.message
    };
  }
}

/**
 * Check memory usage
 */
function checkMemory() {
  try {
    const memUsage = process.memoryUsage();
    const totalMem = memUsage.rss + memUsage.heapTotal + memUsage.external;
    const maxMem = 512 * 1024 * 1024; // 512MB threshold
    
    const isHealthy = totalMem < maxMem;
    
    return {
      status: isHealthy ? 'healthy' : 'warning',
      usage: {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)}MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)}MB`,
        total: `${Math.round(totalMem / 1024 / 1024)}MB`
      },
      threshold: `${Math.round(maxMem / 1024 / 1024)}MB`,
      message: isHealthy ? 'Memory usage normal' : 'High memory usage detected'
    };
    
  } catch (error) {
    logger.error('Memory check failed:', error);
    return {
      status: 'unhealthy',
      message: 'Memory check failed',
      error: error.message
    };
  }
}

/**
 * Check disk space (simplified)
 */
function checkDisk() {
  try {
    // In a real implementation, you would check actual disk space
    // For now, we'll return a healthy status
    return {
      status: 'healthy',
      message: 'Disk space adequate',
      note: 'Detailed disk monitoring not implemented'
    };
    
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Disk check failed',
      error: error.message
    };
  }
}

/**
 * Check external services
 */
async function checkServices() {
  try {
    const services = {
      authentication: checkAuthService(),
      riskAssessment: checkRiskService(),
      auditLogging: checkAuditService()
    };

    const allHealthy = Object.values(services).every(service => service.status === 'healthy');

    return {
      status: allHealthy ? 'healthy' : 'degraded',
      services,
      message: allHealthy ? 'All services operational' : 'Some services degraded'
    };
    
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Service check failed',
      error: error.message
    };
  }
}

/**
 * Check authentication service
 */
function checkAuthService() {
  try {
    // Check if JWT secrets are configured
    const jwtSecret = process.env.JWT_SECRET;
    const refreshSecret = process.env.JWT_REFRESH_SECRET;
    
    if (jwtSecret && refreshSecret) {
      return {
        status: 'healthy',
        message: 'Authentication service operational'
      };
    } else {
      return {
        status: 'warning',
        message: 'Authentication secrets not fully configured'
      };
    }
    
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Authentication service check failed',
      error: error.message
    };
  }
}

/**
 * Check risk assessment service
 */
function checkRiskService() {
  try {
    const enabled = process.env.RISK_ASSESSMENT_ENABLED !== 'false';
    
    return {
      status: enabled ? 'healthy' : 'disabled',
      message: enabled ? 'Risk assessment enabled' : 'Risk assessment disabled',
      enabled
    };
    
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Risk assessment check failed',
      error: error.message
    };
  }
}

/**
 * Check audit logging service
 */
function checkAuditService() {
  try {
    const enabled = process.env.AUDIT_LOG_ENABLED !== 'false';
    
    return {
      status: enabled ? 'healthy' : 'disabled',
      message: enabled ? 'Audit logging enabled' : 'Audit logging disabled',
      enabled
    };
    
  } catch (error) {
    return {
      status: 'unhealthy',
      message: 'Audit service check failed',
      error: error.message
    };
  }
}

/**
 * Format uptime in human-readable format
 */
function formatUptime(uptimeSeconds) {
  const days = Math.floor(uptimeSeconds / 86400);
  const hours = Math.floor((uptimeSeconds % 86400) / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  const seconds = Math.floor(uptimeSeconds % 60);
  
  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0) parts.push(`${seconds}s`);
  
  return parts.join(' ') || '0s';
}

module.exports = router;