//server/controllers/authController.js
// * Authentication Controller
//  * 
//  * Handles user authentication, registration, and session management.
//  * Implements comprehensive security measures including risk assessment,
//  * audit logging, and secure token management for healthcare applications.
//  */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { validationResult } = require('express-validator');
const authService = require('../services/authService');
const auditService = require('../services/auditService');
const logger = require('../utils/logger');

// Simple user storage for demo mode (replace with actual User model in production)
const demoUsers = [
  {
    id: '1',
    email: 'patient@demo.com',
    password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeqvLnP.n5.5H5qNa', // SecurePass123!
    firstName: 'John',
    lastName: 'Patient',
    role: 'patient',
    isActive: true,
    emailVerified: true,
    failedLoginAttempts: 0,
    accountLockedUntil: null
  },
  {
    id: '2',
    email: 'doctor@demo.com',
    password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeqvLnP.n5.5H5qNa', // SecurePass123!
    firstName: 'Dr. Sarah',
    lastName: 'Smith',
    role: 'provider',
    isActive: true,
    emailVerified: true,
    failedLoginAttempts: 0,
    accountLockedUntil: null
  },
  {
    id: '3',
    email: 'admin@demo.com',
    password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeqvLnP.n5.5H5qNa', // SecurePass123!
    firstName: 'Admin',
    lastName: 'User',
    role: 'admin',
    isActive: true,
    emailVerified: true,
    failedLoginAttempts: 0,
    accountLockedUntil: null
  },
  {
    id: '4',
    email: 'suspicious@demo.com',
    password: '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeqvLnP.n5.5H5qNa', // SecurePass123!
    firstName: 'Suspicious',
    lastName: 'User',
    role: 'patient',
    isActive: true,
    emailVerified: true,
    failedLoginAttempts: 0,
    accountLockedUntil: null
  }
];

/**
 * Find user by email (demo mode)
 */
function findUserByEmail(email) {
  return demoUsers.find(user => user.email === email.toLowerCase());
}

/**
 * Find user by ID (demo mode)
 */
function findUserById(id) {
  return demoUsers.find(user => user.id === id);
}

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
    const existingUser = findUserByEmail(email);
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

    // Create new user (in demo mode, just return success)
    const newUser = {
      id: String(demoUsers.length + 1),
      email: email.toLowerCase(),
      password: hashedPassword,
      firstName,
      lastName,
      role: role || 'patient',
      dateOfBirth,
      phone,
      isActive: true,
      emailVerified: false,
      failedLoginAttempts: 0,
      accountLockedUntil: null
    };

    // Add to demo users array
    demoUsers.push(newUser);

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
    const user = findUserByEmail(email);
    
    if (!user) {
      logger.warn('Login attempt with non-existent email', { email, ip: req.ip });
      
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if account is locked
    if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
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
      
      user.failedLoginAttempts = failedAttempts;
      
      // Lock account after max attempts
      if (failedAttempts >= maxAttempts) {
        const lockDuration = 30 * 60 * 1000; // 30 minutes
        user.accountLockedUntil = new Date(Date.now() + lockDuration);
        
        logger.warn('Account locked due to failed login attempts', {
          userId: user.id,
          email,
          failedAttempts
        });
      }

      return res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        attemptsRemaining: Math.max(0, maxAttempts - failedAttempts)
      });
    }

    // Perform risk assessment (simplified for demo)
    const riskAssessment = {
      riskScore: user.email === 'suspicious@demo.com' ? 85 : 
                 user.role === 'admin' ? 35 :
                 user.role === 'provider' ? 15 : 25,
      riskLevel: user.email === 'suspicious@demo.com' ? 'HIGH' :
                 user.role === 'admin' ? 'MEDIUM' : 'LOW',
      factors: []
    };

    // Generate tokens
    const tokens = authService.generateTokens({
      id: user.id,
      email: user.email,
      role: user.role
    });

    // Update user login information
    user.lastLogin = new Date();
    user.failedLoginAttempts = 0;
    user.accountLockedUntil = null;
    user.lastLoginIp = req.ip;
    user.lastLoginUserAgent = req.get('User-Agent');

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
 * Refresh Access Token - THIS WAS MISSING!
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
    const user = findUserById(decoded.id);
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
    const user = findUserById(req.user.id);

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
        lastLogin: user.lastLogin
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

    const user = findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Update allowed fields only
    if (firstName) user.firstName = firstName;
    if (lastName) user.lastName = lastName;
    if (phone) user.phone = phone;
    if (dateOfBirth) user.dateOfBirth = dateOfBirth;

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

/**
 * Change Password - ADDED MISSING METHOD
 * Changes user password with validation
 * 
 * @route POST /api/auth/change-password
 * @access Private
 */
const changePassword = async (req, res) => {
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
    const { currentPassword, newPassword } = req.body;

    const user = findUserById(userId);
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isCurrentPasswordValid) {
      return res.status(400).json({
        success: false,
        message: 'Current password is incorrect'
      });
    }

    // Hash new password
    const saltRounds = 12;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Update password
    user.password = hashedNewPassword;
    user.passwordChangedAt = new Date();

    logger.info('Password changed successfully', { userId });

    res.json({
      success: true,
      message: 'Password changed successfully'
    });

  } catch (error) {
    logger.error('Change password error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Failed to change password'
    });
  }
};

module.exports = {
  register,
  login,
  refreshToken,
  logout,
  getProfile,
  updateProfile,
  changePassword
};