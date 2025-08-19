/**
 * Authentication Service
 * 
 * Provides comprehensive authentication services including JWT token management,
 * session handling, and security validation for the healthcare portal.
 */

const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const logger = require('../utils/logger');

class AuthService {
  constructor() {
    this.jwtSecret = process.env.JWT_SECRET || 'demo-jwt-secret-key';
    this.jwtRefreshSecret = process.env.JWT_REFRESH_SECRET || 'demo-refresh-secret-key';
    this.accessTokenExpiry = process.env.JWT_ACCESS_EXPIRE || '15m';
    this.refreshTokenExpiry = process.env.JWT_REFRESH_EXPIRE || '7d';
    this.saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;
  }

  /**
   * Generate JWT access token
   * @param {Object} payload - User payload
   * @returns {string} JWT access token
   */
  generateAccessToken(payload) {
    try {
      const tokenPayload = {
        id: payload.id,
        email: payload.email,
        role: payload.role,
        type: 'access'
      };

      return jwt.sign(tokenPayload, this.jwtSecret, {
        expiresIn: this.accessTokenExpiry,
        issuer: 'secure-patient-portal',
        audience: 'patient-portal-users'
      });
    } catch (error) {
      logger.error('Failed to generate access token:', error);
      throw new Error('Token generation failed');
    }
  }

  /**
   * Generate JWT refresh token
   * @param {Object} payload - User payload
   * @returns {string} JWT refresh token
   */
  generateRefreshToken(payload) {
    try {
      const tokenPayload = {
        id: payload.id,
        email: payload.email,
        type: 'refresh',
        tokenId: crypto.randomUUID() // Unique token ID for revocation
      };

      return jwt.sign(tokenPayload, this.jwtRefreshSecret, {
        expiresIn: this.refreshTokenExpiry,
        issuer: 'secure-patient-portal',
        audience: 'patient-portal-users'
      });
    } catch (error) {
      logger.error('Failed to generate refresh token:', error);
      throw new Error('Refresh token generation failed');
    }
  }

  /**
   * Generate both access and refresh tokens
   * @param {Object} payload - User payload
   * @returns {Object} Object containing both tokens
   */
  generateTokens(payload) {
    return {
      accessToken: this.generateAccessToken(payload),
      refreshToken: this.generateRefreshToken(payload)
    };
  }

  /**
   * Verify JWT access token
   * @param {string} token - JWT token to verify
   * @returns {Object} Decoded token payload
   */
  verifyAccessToken(token) {
    try {
      return jwt.verify(token, this.jwtSecret, {
        issuer: 'secure-patient-portal',
        audience: 'patient-portal-users'
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Access token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid access token');
      } else {
        logger.error('Access token verification failed:', error);
        throw new Error('Token verification failed');
      }
    }
  }

  /**
   * Verify JWT refresh token
   * @param {string} token - Refresh token to verify
   * @returns {Object} Decoded token payload
   */
  verifyRefreshToken(token) {
    try {
      return jwt.verify(token, this.jwtRefreshSecret, {
        issuer: 'secure-patient-portal',
        audience: 'patient-portal-users'
      });
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        throw new Error('Refresh token expired');
      } else if (error.name === 'JsonWebTokenError') {
        throw new Error('Invalid refresh token');
      } else {
        logger.error('Refresh token verification failed:', error);
        throw new Error('Refresh token verification failed');
      }
    }
  }

  /**
   * Extract token from Authorization header
   * @param {string} authHeader - Authorization header value
   * @returns {string|null} Extracted token or null
   */
  extractTokenFromHeader(authHeader) {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  /**
   * Hash password using bcrypt
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password) {
    try {
      return await bcrypt.hash(password, this.saltRounds);
    } catch (error) {
      logger.error('Password hashing failed:', error);
      throw new Error('Password hashing failed');
    }
  }

  /**
   * Compare password with hash
   * @param {string} password - Plain text password
   * @param {string} hash - Hashed password
   * @returns {Promise<boolean>} True if password matches
   */
  async comparePassword(password, hash) {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      logger.error('Password comparison failed:', error);
      throw new Error('Password comparison failed');
    }
  }

  /**
   * Generate secure random token for password reset, email verification, etc.
   * @param {number} length - Token length in bytes (default: 32)
   * @returns {string} Random hex token
   */
  generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate API key for external integrations
   * @param {string} prefix - Optional prefix for the API key
   * @returns {string} API key
   */
  generateApiKey(prefix = 'spp') {
    const randomPart = crypto.randomBytes(24).toString('hex');
    return `${prefix}_${randomPart}`;
  }

  /**
   * Create password reset token with expiration
   * @param {string} userId - User ID
   * @returns {Object} Reset token and expiration
   */
  createPasswordResetToken(userId) {
    const token = this.generateSecureToken();
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    return {
      token,
      expiresAt,
      userId
    };
  }

  /**
   * Create email verification token
   * @param {string} userId - User ID
   * @param {string} email - Email address
   * @returns {Object} Verification token and expiration
   */
  createEmailVerificationToken(userId, email) {
    const token = this.generateSecureToken();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    return {
      token,
      expiresAt,
      userId,
      email
    };
  }

  /**
   * Validate password complexity
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  validatePasswordComplexity(password) {
    const result = {
      isValid: true,
      errors: []
    };

    // Minimum length
    if (password.length < 8) {
      result.isValid = false;
      result.errors.push('Password must be at least 8 characters long');
    }

    // Maximum length
    if (password.length > 128) {
      result.isValid = false;
      result.errors.push('Password must be less than 128 characters long');
    }

    // Must contain lowercase letter
    if (!/[a-z]/.test(password)) {
      result.isValid = false;
      result.errors.push('Password must contain at least one lowercase letter');
    }

    // Must contain uppercase letter
    if (!/[A-Z]/.test(password)) {
      result.isValid = false;
      result.errors.push('Password must contain at least one uppercase letter');
    }

    // Must contain number
    if (!/\d/.test(password)) {
      result.isValid = false;
      result.errors.push('Password must contain at least one number');
    }

    // Must contain special character
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      result.isValid = false;
      result.errors.push('Password must contain at least one special character');
    }

    // Check for common patterns
    const commonPatterns = [
      /(.)\1{2,}/, // Repeated characters (aaa, 111)
      /123456/, // Sequential numbers
      /abcdef/, // Sequential letters
      /password/i, // Common words
      /qwerty/i
    ];

    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        result.isValid = false;
        result.errors.push('Password contains common patterns and is not secure');
        break;
      }
    }

    return result;
  }

  /**
   * Generate two-factor authentication secret
   * @param {string} userEmail - User's email for QR code
   * @returns {string} Base32 secret
   */
  generateTwoFactorSecret(userEmail) {
    // In a real implementation, you would use a library like 'speakeasy'
    // For demo purposes, we'll generate a random secret
    return crypto.randomBytes(20).toString('base64');
  }

  /**
   * Verify two-factor authentication token
   * @param {string} token - 6-digit TOTP token
   * @param {string} secret - User's 2FA secret
   * @returns {boolean} True if token is valid
   */
  verifyTwoFactorToken(token, secret) {
    // In a real implementation, you would use TOTP verification
    // For demo purposes, we'll accept any 6-digit number
    return /^\d{6}$/.test(token);
  }

  /**
   * Generate backup codes for two-factor authentication
   * @param {number} count - Number of backup codes to generate
   * @returns {Array<string>} Array of backup codes
   */
  generateBackupCodes(count = 10) {
    const codes = [];
    for (let i = 0; i < count; i++) {
      // Generate 8-character alphanumeric codes
      const code = crypto.randomBytes(4).toString('hex').toUpperCase();
      codes.push(code);
    }
    return codes;
  }

  /**
   * Create session data
   * @param {Object} user - User object
   * @param {Object} request - Request object
   * @returns {Object} Session data
   */
  createSessionData(user, request) {
    return {
      userId: user.id,
      email: user.email,
      role: user.role,
      createdAt: new Date(),
      ipAddress: request.ip,
      userAgent: request.get('User-Agent'),
      sessionId: crypto.randomUUID()
    };
  }

  /**
   * Validate session data
   * @param {Object} sessionData - Session data to validate
   * @param {Object} request - Current request
   * @returns {boolean} True if session is valid
   */
  validateSession(sessionData, request) {
    if (!sessionData || !sessionData.userId) {
      return false;
    }

    // Check session age (24 hours max)
    const sessionAge = Date.now() - new Date(sessionData.createdAt).getTime();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours
    
    if (sessionAge > maxAge) {
      return false;
    }

    // Optional: Check IP consistency (commented out for demo flexibility)
    // if (sessionData.ipAddress !== request.ip) {
    //   return false;
    // }

    return true;
  }

  /**
   * Get token expiration time
   * @param {string} token - JWT token
   * @returns {Date|null} Expiration date or null if invalid
   */
  getTokenExpiration(token) {
    try {
      const decoded = jwt.decode(token);
      if (decoded && decoded.exp) {
        return new Date(decoded.exp * 1000);
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Check if token is expired
   * @param {string} token - JWT token
   * @returns {boolean} True if token is expired
   */
  isTokenExpired(token) {
    const expiration = this.getTokenExpiration(token);
    if (!expiration) {
      return true;
    }
    return expiration < new Date();
  }

  /**
   * Create secure cookie options
   * @param {boolean} httpOnly - Whether cookie should be HTTP only
   * @returns {Object} Cookie options
   */
  createCookieOptions(httpOnly = true) {
    return {
      httpOnly,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/'
    };
  }

  /**
   * Sanitize user data for token payload
   * @param {Object} user - User object
   * @returns {Object} Sanitized user data
   */
  sanitizeUserForToken(user) {
    return {
      id: user.id,
      email: user.email,
      role: user.role,
      firstName: user.firstName,
      lastName: user.lastName
    };
  }

  /**
   * Generate device fingerprint for security tracking
   * @param {Object} request - Express request object
   * @returns {string} Device fingerprint
   */
  generateDeviceFingerprint(request) {
    const userAgent = request.get('User-Agent') || '';
    const acceptLanguage = request.get('Accept-Language') || '';
    const acceptEncoding = request.get('Accept-Encoding') || '';
    
    const fingerprint = `${userAgent}|${acceptLanguage}|${acceptEncoding}`;
    return crypto.createHash('sha256').update(fingerprint).digest('hex');
  }

  /**
   * Log authentication event
   * @param {string} eventType - Type of auth event
   * @param {Object} details - Event details
   */
  logAuthEvent(eventType, details) {
    logger.audit(`AUTH_${eventType}`, {
      ...details,
      timestamp: new Date().toISOString()
    });
  }
}

// Create singleton instance
const authService = new AuthService();

module.exports = authService;