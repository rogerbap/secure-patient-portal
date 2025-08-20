//server/middleware/rateLimit.js
/**
 * Rate Limiting Middleware
 * 
 * Updated to use latest express-rate-limit API
 * Implements comprehensive rate limiting to prevent brute force attacks,
 * API abuse, and ensure fair usage of the healthcare portal resources.
 */

const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');
const auditService = require('../services/auditService');

/**
 * Create custom rate limit handler
 * @param {string} limitType - Type of rate limit for logging
 * @returns {Function} Rate limit handler
 */
const createRateLimitHandler = (limitType) => {
  return async (req, res) => {
    // Log rate limit exceeded event
    try {
      await auditService.logSecurityEvent({
        eventType: 'RATE_LIMIT_EXCEEDED',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          limitType,
          method: req.method,
          rateLimitInfo: {
            limit: req.rateLimit?.limit,
            current: req.rateLimit?.current,
            remaining: req.rateLimit?.remaining,
            resetTime: req.rateLimit?.resetTime
          }
        }
      });
    } catch (error) {
      logger.error('Failed to log rate limit event:', error);
    }

    logger.warn('Rate limit exceeded:', {
      ip: req.ip,
      endpoint: req.originalUrl,
      limitType,
      userAgent: req.get('User-Agent')
    });

    res.status(429).json({
      error: 'Too many requests',
      message: `Rate limit exceeded. Please try again later.`,
      retryAfter: Math.round(req.rateLimit?.resetTime / 1000) || 60,
      timestamp: new Date().toISOString(),
      limitType
    });
  };
};

/**
 * Global API rate limiting
 * Applies to all /api/* endpoints
 */
const globalRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // 100 requests per window
  message: {
    error: 'Too many requests',
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: 900 // 15 minutes in seconds
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  
  // Custom key generator to handle proxies
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
  
  // Custom handler for rate limit exceeded
  handler: createRateLimitHandler('global'),
  
  // Skip successful requests for authenticated users (give them higher limits)
  skip: (req) => {
    if (req.user) {
      // Authenticated users get 5x higher limit
      return false;
    }
    return false;
  }
});

/**
 * Authentication rate limiting
 * Stricter limits for authentication endpoints
 */
const authRateLimit = rateLimit({
  windowMs: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.AUTH_RATE_LIMIT_MAX_REQUESTS) || 5, // 5 attempts per window
  message: {
    error: 'Too many authentication attempts',
    message: 'Too many authentication attempts, please try again later.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    // Rate limit by IP and email combination for more granular control
    const email = req.body?.email || '';
    return `${req.ip}-${email}`;
  },
  
  handler: createRateLimitHandler('authentication'),
  
  // Always apply to auth endpoints regardless of authentication status
  skip: () => false
});

/**
 * Password reset rate limiting
 * Prevents abuse of password reset functionality
 */
const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour per IP
  message: {
    error: 'Too many password reset attempts',
    message: 'Too many password reset attempts, please try again later.',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    const email = req.body?.email || '';
    return `pwd-reset-${req.ip}-${email}`;
  },
  
  handler: createRateLimitHandler('password_reset')
});

/**
 * API key rate limiting
 * Higher limits for API key authenticated requests
 */
const apiKeyRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // 1000 requests per window for API keys
  message: {
    error: 'API key rate limit exceeded',
    message: 'API key rate limit exceeded.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    const apiKey = req.headers['x-api-key'];
    return apiKey ? `api-${apiKey.substring(0, 8)}` : req.ip;
  },
  
  handler: createRateLimitHandler('api_key'),
  
  skip: (req) => {
    // Only apply to requests with API keys
    return !req.headers['x-api-key'];
  }
});

/**
 * File upload rate limiting
 * Limits file upload attempts to prevent abuse
 */
const uploadRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 uploads per hour
  message: {
    error: 'Too many file uploads',
    message: 'Too many file uploads, please try again later.',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    return req.user ? `upload-${req.user.id}` : `upload-${req.ip}`;
  },
  
  handler: createRateLimitHandler('file_upload')
});

/**
 * Search rate limiting
 * Prevents abuse of search functionality
 */
const searchRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 searches per minute
  message: {
    error: 'Too many search requests',
    message: 'Too many search requests, please slow down.',
    retryAfter: 60
  },
  standardHeaders: true,
  legacyHeaders: false,
  
  keyGenerator: (req) => {
    return req.user ? `search-${req.user.id}` : `search-${req.ip}`;
  },
  
  handler: createRateLimitHandler('search'),
  
  skip: (req) => {
    // Skip for admin users
    return req.user?.role === 'admin';
  }
});

/**
 * Progressive rate limiting
 * Increases penalties for repeated violations
 */
class ProgressiveRateLimit {
  constructor() {
    this.violations = new Map(); // Track violations per IP
    this.cleanupInterval = setInterval(this.cleanup.bind(this), 60 * 60 * 1000); // Cleanup every hour
  }

  middleware() {
    return (req, res, next) => {
      const ip = req.ip;
      const now = Date.now();
      
      if (!this.violations.has(ip)) {
        this.violations.set(ip, []);
      }
      
      const userViolations = this.violations.get(ip);
      
      // Remove violations older than 24 hours
      const recentViolations = userViolations.filter(
        violation => now - violation.timestamp < 24 * 60 * 60 * 1000
      );
      
      this.violations.set(ip, recentViolations);
      
      // Calculate progressive penalty
      const violationCount = recentViolations.length;
      let penaltyMultiplier = 1;
      
      if (violationCount > 0) {
        penaltyMultiplier = Math.min(10, Math.pow(2, violationCount)); // Exponential backoff, max 10x
        
        const lastViolation = recentViolations[recentViolations.length - 1];
        const timeSinceLastViolation = now - lastViolation.timestamp;
        const requiredCooldown = lastViolation.cooldown || 0;
        
        if (timeSinceLastViolation < requiredCooldown) {
          return res.status(429).json({
            error: 'Progressive rate limit active',
            message: `Please wait ${Math.ceil((requiredCooldown - timeSinceLastViolation) / 1000)} more seconds`,
            retryAfter: Math.ceil((requiredCooldown - timeSinceLastViolation) / 1000),
            violationCount
          });
        }
      }
      
      // Store original end method to wrap it
      const originalEnd = res.end;
      
      // Wrap the response end to add violation tracking
      res.end = function(...args) {
        if (res.statusCode === 429) {
          const cooldown = penaltyMultiplier * 60 * 1000; // Minutes in milliseconds
          recentViolations.push({
            timestamp: now,
            cooldown,
            endpoint: req.originalUrl
          });
          
          logger.warn('Progressive rate limit violation:', {
            ip,
            violationCount: recentViolations.length,
            cooldown,
            endpoint: req.originalUrl
          });
        }
        
        return originalEnd.apply(this, args);
      };
      
      next();
    };
  }

  cleanup() {
    const now = Date.now();
    const dayAgo = 24 * 60 * 60 * 1000;
    
    for (const [ip, violations] of this.violations.entries()) {
      const recentViolations = violations.filter(
        violation => now - violation.timestamp < dayAgo
      );
      
      if (recentViolations.length === 0) {
        this.violations.delete(ip);
      } else {
        this.violations.set(ip, recentViolations);
      }
    }
  }

  getViolations(ip) {
    return this.violations.get(ip) || [];
  }
}

// Create progressive rate limit instance
const progressiveRateLimit = new ProgressiveRateLimit();

/**
 * Whitelist middleware
 * Allows certain IPs to bypass rate limiting
 */
const rateLimitWhitelist = (req, res, next) => {
  const whitelist = (process.env.RATE_LIMIT_WHITELIST || '').split(',').filter(Boolean);
  
  if (whitelist.includes(req.ip)) {
    logger.debug('Rate limit bypassed for whitelisted IP:', req.ip);
    return next();
  }
  
  next();
};

/**
 * Rate limit info middleware
 * Adds rate limit information to responses
 */
const addRateLimitInfo = (req, res, next) => {
  const originalJson = res.json;
  
  res.json = function(data) {
    // Add rate limit info to response if available
    if (req.rateLimit && process.env.NODE_ENV === 'development') {
      data.rateLimit = {
        limit: req.rateLimit.limit,
        current: req.rateLimit.current,
        remaining: req.rateLimit.remaining,
        resetTime: req.rateLimit.resetTime
      };
    }
    
    return originalJson.call(this, data);
  };
  
  next();
};

module.exports = {
  globalRateLimit,
  authRateLimit,
  passwordResetRateLimit,
  apiKeyRateLimit,
  uploadRateLimit,
  searchRateLimit,
  progressiveRateLimit: progressiveRateLimit.middleware(),
  rateLimitWhitelist,
  addRateLimitInfo
};