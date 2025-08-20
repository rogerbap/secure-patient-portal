//server/routes/auth.js
const express = require('express');
const { body, validationResult } = require('express-validator');
const router = express.Router();

// Import services and middleware
const authController = require('../controllers/authController');
const { authenticateToken, validateSession } = require('../middleware/auth');
const { authRateLimit } = require('../middleware/rateLimit');

/**
 * Authentication validation rules
 */
const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters long')
];

const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Please provide a valid email address'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, lowercase letter, number, and special character'),
  body('firstName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s\-'\.]+$/)
    .withMessage('First name must contain only letters, spaces, hyphens, apostrophes, and periods'),
  body('lastName')
    .trim()
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s\-'\.]+$/)
    .withMessage('Last name must contain only letters, spaces, hyphens, apostrophes, and periods'),
  body('role')
    .optional()
    .isIn(['patient', 'provider', 'admin'])
    .withMessage('Role must be patient, provider, or admin'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Date of birth must be a valid date'),
  body('phone')
    .optional()
    .matches(/^[\+]?[1-9][\d]{0,15}$/)
    .withMessage('Phone number must be in valid format')
];

const profileUpdateValidation = [
  body('firstName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s\-'\.]+$/)
    .withMessage('First name must contain only letters, spaces, hyphens, apostrophes, and periods'),
  body('lastName')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .matches(/^[a-zA-Z\s\-'\.]+$/)
    .withMessage('Last name must contain only letters, spaces, hyphens, apostrophes, and periods'),
  body('phone')
    .optional()
    .matches(/^[\+]?[1-9][\d]{0,15}$/)
    .withMessage('Phone number must be in valid format'),
  body('dateOfBirth')
    .optional()
    .isISO8601()
    .withMessage('Date of birth must be a valid date')
];

/**
 * @route   POST /api/auth/register
 * @desc    Register new user account
 * @access  Public (with rate limiting)
 */
router.post('/register', 
  authRateLimit,
  registerValidation,
  authController.register
);

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user with risk assessment
 * @access  Public (with strict rate limiting)
 */
router.post('/login', 
  authRateLimit,
  loginValidation,
  authController.login
);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Private (requires refresh token in cookies)
 */
router.post('/refresh', authController.refreshToken);

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user and invalidate tokens
 * @access  Private
 */
router.post('/logout', 
  authenticateToken,
  validateSession,
  authController.logout
);

/**
 * @route   GET /api/auth/profile
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/profile', 
  authenticateToken,
  validateSession,
  authController.getProfile
);

/**
 * @route   PUT /api/auth/profile
 * @desc    Update user profile
 * @access  Private
 */
router.put('/profile', 
  authenticateToken,
  validateSession,
  profileUpdateValidation,
  authController.updateProfile
);

/**
 * @route   GET /api/auth/verify-token
 * @desc    Verify if current token is valid
 * @access  Private
 */
router.get('/verify-token', authenticateToken, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      role: req.user.role,
      firstName: req.user.firstName,
      lastName: req.user.lastName
    },
    message: 'Token is valid'
  });
});

/**
 * @route   POST /api/auth/change-password
 * @desc    Change user password
 * @access  Private
 */
router.post('/change-password',
  authenticateToken,
  validateSession,
  [
    body('currentPassword')
      .notEmpty()
      .withMessage('Current password is required'),
    body('newPassword')
      .isLength({ min: 8 })
      .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
      .withMessage('New password must contain at least one uppercase letter, lowercase letter, number, and special character'),
    body('confirmPassword')
      .custom((value, { req }) => {
        if (value !== req.body.newPassword) {
          throw new Error('Password confirmation does not match');
        }
        return true;
      })
  ],
  authController.changePassword
);

/**
 * Error handling middleware for auth routes
 */
router.use((error, req, res, next) => {
  console.error('Auth route error:', error);
  
  res.status(500).json({
    success: false,
    message: 'Authentication service temporarily unavailable',
    timestamp: new Date().toISOString()
  });
});

module.exports = router;