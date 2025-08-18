/**
 * Authentication Middleware
 * 
 * Provides JWT authentication, role-based authorization, and session management
 * middleware for the Secure Patient Portal API endpoints.
 */

const authService = require('../services/authService');
const auditService = require('../services/auditService');
const User = require('../models/User');
const logger = require('../utils/logger');

/**
 * Verify JWT token and authenticate user
 * Middleware that checks for valid JWT token in Authorization header
 */
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authService.extractTokenFromHeader(authHeader);

    if (!token) {
      await auditService.logSecurityEvent({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          reason: 'No token provided',
          method: req.method
        }
      });

      return res.status(401).json({
        success: false,
        message: 'Access token required',
        code: 'TOKEN_REQUIRED'
      });
    }

    // Verify the token
    const decoded = authService.verifyAccessToken(token);

    // Get user from database to ensure they still exist and are active
    const user = await User.findByPk(decoded.id);
    
    if (!user) {
      await auditService.logSecurityEvent({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'high',
        userId: decoded.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          reason: 'User not found',
          tokenUserId: decoded.id
        }
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid token - user not found',
        code: 'USER_NOT_FOUND'
      });
    }

    if (!user.isActive) {
      await auditService.logSecurityEvent({
        eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
        severity: 'medium',
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          reason: 'Inactive user account',
          userEmail: user.email
        }
      });

      return res.status(403).json({
        success: false,
        message: 'Account is deactivated',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Check if account is locked
    if (user.isAccountLocked()) {
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_ATTEMPT_LOCKED_ACCOUNT',
        severity: 'medium',
        userId: user.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          lockedUntil: user.accountLockedUntil
        }
      });

      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked',
        code: 'ACCOUNT_LOCKED'
      });
    }

    // Attach user to request object
    req.user = {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName
    };

    // Log successful authentication
    await auditService.logUserAction({
      userId: user.id,
      action: 'API_ACCESS',
      details: {
        endpoint: req.originalUrl,
        method: req.method
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      httpMethod: req.method
    });

    next();

  } catch (error) {
    let errorMessage = 'Authentication failed';
    let errorCode = 'AUTH_FAILED';

    if (error.message === 'Access token expired') {
      errorMessage = 'Token expired';
      errorCode = 'TOKEN_EXPIRED';
    } else if (error.message === 'Invalid access token') {
      errorMessage = 'Invalid token';
      errorCode = 'TOKEN_INVALID';
    }

    await auditService.logSecurityEvent({
      eventType: 'AUTHENTICATION_FAILED',
      severity: 'medium',
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      details: {
        error: error.message,
        method: req.method
      }
    });

    logger.warn('Authentication failed:', {
      error: error.message,
      ip: req.ip,
      endpoint: req.originalUrl
    });

    return res.status(401).json({
      success: false,
      message: errorMessage,
      code: errorCode
    });
  }
};

/**
 * Authorize user based on required roles
 * @param {Array|string} allowedRoles - Roles that can access the endpoint
 */
const authorizeRoles = (allowedRoles) => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const userRole = req.user.role;
      const roles = Array.isArray(allowedRoles) ? allowedRoles : [allowedRoles];

      if (!roles.includes(userRole)) {
        await auditService.logSecurityEvent({
          eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
          severity: 'medium',
          userId: req.user.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          endpoint: req.originalUrl,
          details: {
            reason: 'Insufficient privileges',
            userRole,
            requiredRoles: roles,
            method: req.method
          }
        });

        logger.warn('Authorization failed:', {
          userId: req.user.id,
          userRole,
          requiredRoles: roles,
          endpoint: req.originalUrl
        });

        return res.status(403).json({
          success: false,
          message: 'Insufficient privileges',
          code: 'INSUFFICIENT_PRIVILEGES'
        });
      }

      // Log successful authorization
      await auditService.logUserAction({
        userId: req.user.id,
        action: 'AUTHORIZATION_SUCCESS',
        details: {
          endpoint: req.originalUrl,
          method: req.method,
          userRole,
          requiredRoles: roles
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        httpMethod: req.method
      });

      next();

    } catch (error) {
      logger.error('Authorization error:', error);
      
      return res.status(500).json({
        success: false,
        message: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Optional authentication middleware
 * Authenticates user if token is present, but doesn't require it
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authService.extractTokenFromHeader(authHeader);

    if (token) {
      try {
        const decoded = authService.verifyAccessToken(token);
        const user = await User.findByPk(decoded.id);
        
        if (user && user.isActive && !user.isAccountLocked()) {
          req.user = {
            id: user.id,
            email: user.email,
            role: user.role,
            firstName: user.firstName,
            lastName: user.lastName
          };
        }
      } catch (error) {
        // Token invalid, but we continue without user
        logger.debug('Optional auth failed:', error.message);
      }
    }

    next();

  } catch (error) {
    logger.error('Optional auth error:', error);
    next(); // Continue without authentication
  }
};

/**
 * Resource ownership middleware
 * Checks if user owns the resource or has admin privileges
 * @param {string} resourceIdParam - Request parameter containing resource ID
 * @param {string} userIdField - Field in resource that contains user ID
 */
const checkResourceOwnership = (resourceIdParam = 'id', userIdField = 'userId') => {
  return async (req, res, next) => {
    try {
      if (!req.user) {
        return res.status(401).json({
          success: false,
          message: 'Authentication required',
          code: 'AUTH_REQUIRED'
        });
      }

      const resourceId = req.params[resourceIdParam];
      const userId = req.user.id;
      const userRole = req.user.role;

      // Admins can access any resource
      if (userRole === 'admin') {
        return next();
      }

      // For patient role, check if they're accessing their own data
      if (userRole === 'patient') {
        // If accessing by user ID directly
        if (resourceIdParam === 'userId' && resourceId !== userId) {
          await auditService.logSecurityEvent({
            eventType: 'UNAUTHORIZED_ACCESS_ATTEMPT',
            severity: 'high',
            userId,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            endpoint: req.originalUrl,
            details: {
              reason: 'Attempted access to other user data',
              requestedUserId: resourceId,
              actualUserId: userId
            }
          });

          return res.status(403).json({
            success: false,
            message: 'Access denied - can only access own data',
            code: 'ACCESS_DENIED'
          });
        }
      }

      // For providers, implement additional checks based on patient assignments
      if (userRole === 'provider') {
        // This would typically check if the provider is assigned to the patient
        // For demo purposes, we'll allow provider access
      }

      next();

    } catch (error) {
      logger.error('Resource ownership check failed:', error);
      
      return res.status(500).json({
        success: false,
        message: 'Authorization check failed',
        code: 'AUTHORIZATION_ERROR'
      });
    }
  };
};

/**
 * Session validation middleware
 * Validates session data and checks for session hijacking
 */
const validateSession = async (req, res, next) => {
  try {
    if (!req.user) {
      return next(); // Skip if no user authenticated
    }

    const sessionData = req.session?.userData;
    
    if (sessionData) {
      // Validate session consistency
      if (!authService.validateSession(sessionData, req)) {
        await auditService.logSecurityEvent({
          eventType: 'SESSION_VALIDATION_FAILED',
          severity: 'high',
          userId: req.user.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          details: {
            reason: 'Session validation failed',
            sessionUserId: sessionData.userId,
            tokenUserId: req.user.id
          }
        });

        // Clear invalid session
        req.session.destroy();

        return res.status(401).json({
          success: false,
          message: 'Session invalid',
          code: 'SESSION_INVALID'
        });
      }
    }

    next();

  } catch (error) {
    logger.error('Session validation error:', error);
    next(); // Continue on error to avoid blocking legitimate requests
  }
};

/**
 * Rate limiting bypass for authenticated users
 * Provides higher rate limits for authenticated users
 */
const authenticatedRateLimit = (req, res, next) => {
  if (req.user) {
    // Authenticated users get higher limits
    req.rateLimit = {
      ...req.rateLimit,
      max: req.rateLimit.max * 5 // 5x higher limit
    };
  }
  next();
};

/**
 * Device fingerprint validation
 * Checks if request comes from a recognized device
 */
const validateDeviceFingerprint = async (req, res, next) => {
  try {
    if (!req.user) {
      return next();
    }

    const currentFingerprint = authService.generateDeviceFingerprint(req);
    const userId = req.user.id;

    // Check if this is a new device
    const user = await User.findByPk(userId);
    const knownDevices = user.preferences?.knownDevices || [];

    if (!knownDevices.includes(currentFingerprint)) {
      await auditService.logSecurityEvent({
        eventType: 'NEW_DEVICE_DETECTED',
        severity: 'medium',
        userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          deviceFingerprint: currentFingerprint,
          knownDevicesCount: knownDevices.length
        }
      });

      // Add device to known devices (in real app, might require user confirmation)
      knownDevices.push(currentFingerprint);
      await user.update({
        preferences: {
          ...user.preferences,
          knownDevices: knownDevices.slice(-10) // Keep last 10 devices
        }
      });
    }

    next();

  } catch (error) {
    logger.error('Device fingerprint validation error:', error);
    next(); // Continue on error
  }
};

/**
 * API key authentication (for external integrations)
 * Alternative authentication method using API keys
 */
const authenticateApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required',
        code: 'API_KEY_REQUIRED'
      });
    }

    // Validate API key format
    if (!apiKey.startsWith('spp_')) {
      return res.status(401).json({
        success: false,
        message: 'Invalid API key format',
        code: 'INVALID_API_KEY_FORMAT'
      });
    }

    // In a real implementation, you would validate against stored API keys
    // For demo purposes, we'll accept any properly formatted key
    const isValidKey = apiKey.length > 20; // Simple validation

    if (!isValidKey) {
      await auditService.logSecurityEvent({
        eventType: 'INVALID_API_KEY_ATTEMPT',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          apiKeyPrefix: apiKey.substring(0, 8)
        }
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid API key',
        code: 'INVALID_API_KEY'
      });
    }

    // Set API client info
    req.apiClient = {
      id: 'demo-client',
      type: 'api_key',
      keyPrefix: apiKey.substring(0, 8)
    };

    await auditService.logUserAction({
      userId: null, // API key doesn't have user context
      action: 'API_KEY_ACCESS',
      details: {
        endpoint: req.originalUrl,
        method: req.method,
        apiKeyPrefix: apiKey.substring(0, 8)
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      httpMethod: req.method
    });

    next();

  } catch (error) {
    logger.error('API key authentication error:', error);
    
    return res.status(500).json({
      success: false,
      message: 'API key validation failed',
      code: 'API_KEY_VALIDATION_ERROR'
    });
  }
};

/**
 * Require two-factor authentication for sensitive operations
 */
const requireTwoFactor = async (req, res, next) => {
  try {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }

    const user = await User.findByPk(req.user.id);
    
    if (!user.twoFactorEnabled) {
      await auditService.logSecurityEvent({
        eventType: 'TWO_FACTOR_REQUIRED',
        severity: 'medium',
        userId: req.user.id,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        details: {
          reason: '2FA not enabled for sensitive operation'
        }
      });

      return res.status(403).json({
        success: false,
        message: 'Two-factor authentication required for this operation',
        code: 'TWO_FACTOR_REQUIRED'
      });
    }

    // Check for 2FA verification in session or headers
    const twoFactorVerified = req.session?.twoFactorVerified || req.headers['x-2fa-verified'];
    
    if (!twoFactorVerified) {
      return res.status(403).json({
        success: false,
        message: 'Two-factor authentication verification required',
        code: 'TWO_FACTOR_VERIFICATION_REQUIRED'
      });
    }

    next();

  } catch (error) {
    logger.error('Two-factor authentication check error:', error);
    
    return res.status(500).json({
      success: false,
      message: 'Two-factor authentication check failed',
      code: 'TWO_FACTOR_CHECK_ERROR'
    });
  }
};

/**
 * Middleware to log API access for audit trails
 */
const logApiAccess = async (req, res, next) => {
  const startTime = Date.now();

  // Override res.json to capture response
  const originalJson = res.json;
  res.json = function(data) {
    const responseTime = Date.now() - startTime;
    
    // Log the API access
    auditService.logUserAction({
      userId: req.user?.id || null,
      action: 'API_REQUEST',
      details: {
        endpoint: req.originalUrl,
        method: req.method,
        statusCode: res.statusCode,
        responseTime,
        success: res.statusCode < 400
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      endpoint: req.originalUrl,
      httpMethod: req.method,
      statusCode: res.statusCode,
      responseTime
    }).catch(error => {
      logger.error('Failed to log API access:', error);
    });

    return originalJson.call(this, data);
  };

  next();
};

module.exports = {
  authenticateToken,
  authorizeRoles,
  optionalAuth,
  checkResourceOwnership,
  validateSession,
  authenticatedRateLimit,
  validateDeviceFingerprint,
  authenticateApiKey,
  requireTwoFactor,
  logApiAccess
};