/**
 * Authentication Controller
 * 
 * Handles user authentication, registration, and session management.
 * Implements comprehensive security measures including risk assessment,
 * audit logging, and secure token management for healthcare applications.
 * 
 * @author Your Name
 * @version 1.0.0
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const User = require('../models/User');
const SecurityLog = require('../models/SecurityLog');
const authService = require('../services/authService');
const riskAssessmentService = require('../services/riskAssessmentService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');

/**
 * User Registration
 * Creates new user account with proper validation and security measures
 * 
 * @route POST /api/auth/register
 * @access Public (with rate limiting)
 */
const register = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      logger.warn('Registration validation failed', { 
        errors: errors.array(),
        ip: req.ip 
      });
      
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password, firstName, lastName, role, dateOfBirth, phone } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      logger.warn('Registration attempt with existing email', { 
        email,
        ip: req.ip 
      });
      
      return res.status(409).json({
        success: false,
        message: 'User already exists with this email'
      });
    }

    // Hash password with high salt rounds for security
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new user
    const newUser = await User.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      role: role || 'patient', // Default to patient role
      dateOfBirth,
      phone,
      isActive: true,
      emailVerified: false, // Would integrate with email verification service
      lastLogin: null,
      failedLoginAttempts: 0,
      accountLockedUntil: null
    });

    // Log successful registration
    await auditService.logUserAction({
      userId: newUser.id,
      action: 'USER_REGISTERED',
      details: {
        email: newUser.email,
        role: newUser.role,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    logger.info('User registered successfully', {
      userId: newUser.id,
      email: newUser.email,
      role: newUser.role
    });

    // Return success without sensitive data
    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: newUser.id,
        email: newUser.email,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        role: newUser.role,
        emailVerified: newUser.emailVerified
      }
    });

  } catch (error) {
    logger.error('Registration error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Registration failed. Please try again.'
    });
  }
};

/**
 * User Login
 * Authenticates user with comprehensive security checks and risk assessment
 * 
 * @route POST /api/auth/login
 * @access Public (with strict rate limiting)
 */
const login = async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const { email, password } = req.body;
    const clientInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    };

    // Find user by email
    const user = await User.findOne({ where: { email } });
    
    if (!user) {
      // Log failed login attempt
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_FAILED_USER_NOT_FOUND',
        details: { email, ...clientInfo },
        severity: 'medium',
        ipAddress: req.ip
      });

      logger.warn('Login attempt with non-existent email', { email, ip: req.ip });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if account is locked
    if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_ATTEMPT_LOCKED_ACCOUNT',
        userId: user.id,
        details: { email, ...clientInfo },
        severity: 'high',
        ipAddress: req.ip
      });

      logger.warn('Login attempt on locked account', { 
        userId: user.id,
        email,
        lockedUntil: user.accountLockedUntil 
      });

      return res.status(423).json({
        success: false,
        message: 'Account is temporarily locked due to failed login attempts'
      });
    }

    // Check if account is active
    if (!user.isActive) {
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_ATTEMPT_INACTIVE_ACCOUNT',
        userId: user.id,
        details: { email, ...clientInfo },
        severity: 'medium',
        ipAddress: req.ip
      });

      return res.status(403).json({
        success: false,
        message: 'Account is deactivated. Please contact support.'
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
      // Increment failed login attempts
      const failedAttempts = (user.failedLoginAttempts || 0) + 1;
      const maxAttempts = 5;
      
      let updateData = { failedLoginAttempts: failedAttempts };
      
      // Lock account after max attempts
      if (failedAttempts >= maxAttempts) {
        const lockDuration = 30 * 60 * 1000; // 30 minutes
        updateData.accountLockedUntil = new Date(Date.now() + lockDuration);
        
        logger.warn('Account locked due to failed login attempts', {
          userId: user.id,
          email,
          failedAttempts
        });
      }
      
      await user.update(updateData);

      // Log failed login attempt
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_FAILED_INVALID_PASSWORD',
        userId: user.id,
        details: { 
          email, 
          failedAttempts,
          accountLocked: failedAttempts >= maxAttempts,
          ...clientInfo 
        },
        severity: failedAttempts >= maxAttempts ? 'high' : 'medium',
        ipAddress: req.ip
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        attemptsRemaining: Math.max(0, maxAttempts - failedAttempts)
      });
    }

    // Perform risk assessment
    const riskAssessment = await riskAssessmentService.assessLoginRisk({
      userId: user.id,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      timestamp: new Date()
    });

    // Handle high-risk logins
    if (riskAssessment.riskLevel === 'HIGH') {
      await auditService.logSecurityEvent({
        eventType: 'HIGH_RISK_LOGIN_DETECTED',
        userId: user.id,
        details: {
          email,
          riskScore: riskAssessment.riskScore,
          riskFactors: riskAssessment.factors,
          ...clientInfo
        },
        severity: 'high',
        ipAddress: req.ip
      });

      logger.warn('High-risk login detected', {
        userId: user.id,
        email,
        riskScore: riskAssessment.riskScore,
        factors: riskAssessment.factors
      });

      // In production, you might require additional verification
      // For demo purposes, we'll allow but log the risk
    }

    // Generate tokens
    const tokens = authService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role
    });

    // Update user login information
    await user.update({
      lastLogin: new Date(),
      failedLoginAttempts: 0,
      accountLockedUntil: null,
      lastLoginIp: req.ip,
      lastLoginUserAgent: req.get('User-Agent')
    });

    // Log successful login
    await auditService.logUserAction({
      userId: user.id,
      action: 'USER_LOGIN',
      details: {
        email: user.email,
        riskScore: riskAssessment.riskScore,
        riskLevel: riskAssessment.riskLevel,
        ...clientInfo
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    logger.info('User logged in successfully', {
      userId: user.id,
      email: user.email,
      riskLevel: riskAssessment.riskLevel
    });

    // Set secure HTTP-only cookie for refresh token
    res.cookie('refreshToken', tokens.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return success response with access token
    res.json({
      success: true,
      message: 'Login successful',
      accessToken: tokens.accessToken,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        lastLogin: user.lastLogin
      },
      riskAssessment: {
        riskLevel: riskAssessment.riskLevel,
        riskScore: riskAssessment.riskScore,
        requiresAdditionalVerification: riskAssessment.riskLevel === 'HIGH'
      }
    });

  } catch (error) {
    logger.error('Login error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.'
    });
  }
};

/**
 * Refresh Access Token
 * Generates new access token using refresh token
 * 
 * @route POST /api/auth/refresh
 * @access Private (requires refresh token)
 */
const refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.cookies;
    
    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token not provided'
      });
    }

    // Verify refresh token
    const decoded = authService.verifyRefreshToken(refreshToken);
    
    // Find user
    const user = await User.findByPk(decoded.id);
    if (!user || !user.isActive) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token'
      });
    }

    // Generate new access token
    const newAccessToken = authService.generateAccessToken({
      id: user.id,
      email: user.email,
      role: user.role
    });

    // Log token refresh
    await auditService.logUserAction({
      userId: user.id,
      action: 'TOKEN_REFRESHED',
      details: {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    logger.debug('Token refreshed successfully', { userId: user.id });

    res.json({
      success: true,
      accessToken: newAccessToken
    });

  } catch (error) {
    logger.error('Token refresh error:', error);
    
    res.status(401).json({
      success: false,
      message: 'Invalid refresh token'
    });
  }
};

/**
 * User Logout
 * Invalidates tokens and clears session
 * 
 * @route POST /api/auth/logout
 * @access Private
 */
const logout = async (req, res) => {
  try {
    const userId = req.user.id;

    // Log logout action
    await auditService.logUserAction({
      userId,
      action: 'USER_LOGOUT',
      details: {
        ip: req.ip,
        userAgent: req.get('User-Agent')
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    // Destroy session if using sessions
    if (req.session) {
      req.session.destroy();
    }

    logger.info('User logged out successfully', { userId });

    res.json({
      success: true,
      message: 'Logout successful'
    });

  } catch (error) {
    logger.error('Logout error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Logout failed'
    });
  }
};

/**
 * Get User Profile
 * Returns current user information
 * 
 * @route GET /api/auth/profile
 * @access Private
 */
const getProfile = async (req, res) => {
  try {
    const user = await User.findByPk(req.user.id, {
      attributes: { exclude: ['password'] } // Never return password
    });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        dateOfBirth: user.dateOfBirth,
        phone: user.phone,
        emailVerified: user.emailVerified,
        lastLogin: user.lastLogin,
        createdAt: user.createdAt
      }
    });

  } catch (error) {
    logger.error('Get profile error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Failed to fetch profile'
    });
  }
};

/**
 * Update User Profile
 * Updates user information with validation
 * 
 * @route PUT /api/auth/profile
 * @access Private
 */
const updateProfile = async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        errors: errors.array()
      });
    }

    const userId = req.user.id;
    const { firstName, lastName, phone, dateOfBirth } = req.body;

    const user = await User.findByPk(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update allowed fields only
    await user.update({
      firstName,
      lastName,
      phone,
      dateOfBirth
    });

    // Log profile update
    await auditService.logUserAction({
      userId,
      action: 'PROFILE_UPDATED',
      details: {
        updatedFields: Object.keys(req.body),
        ip: req.ip,
        userAgent: req.get('User-Agent')
      },
      ipAddress: req.ip,
      userAgent: req.get('User-Agent')
    });

    logger.info('Profile updated successfully', { userId });

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        dateOfBirth: user.dateOfBirth,
        phone: user.phone
      }
    });

  } catch (error) {
    logger.error('Update profile error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Failed to update profile'
    });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  updateProfile
};