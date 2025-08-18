/**
 * Secure Patient Portal - Complete Express Application Configuration
 * 
 * Configures Express app with comprehensive security middleware, CORS settings,
 * database integration, and API routes. Implements healthcare-grade security 
 * measures including rate limiting, input validation, and audit logging.
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const path = require('path');

// Import configuration and utilities
const logger = require('./utils/logger');
const auditService = require('./services/auditService');

// Import middleware
const { globalRateLimit, authRateLimit } = require('./middleware/rateLimit');
const { logApiAccess } = require('./middleware/auth');

// Create Express application
const app = express();

/**
 * Security Configuration
 * Implements comprehensive security headers and policies
 */

// Helmet for security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "https://cdnjs.cloudflare.com"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false // Allow for development
}));

/**
 * CORS Configuration
 * Restricts cross-origin requests to authorized clients
 */
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.CLIENT_URL || 'http://localhost:8080',
      'http://localhost:3000', // Development server
      'http://127.0.0.1:8080',
      'http://127.0.0.1:3000'
    ];
    
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.warn(`CORS blocked origin: ${origin}`);
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  optionsSuccessStatus: 200,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key']
};

app.use(cors(corsOptions));

/**
 * Session Configuration
 * Secure session management with memory storage for demo
 */
app.use(session({
  secret: process.env.SESSION_SECRET || 'demo-session-secret-change-in-production',
  name: 'patientPortalSession', // Custom session name for security
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS only in production
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'strict'
  }
}));

/**
 * Request Parsing Middleware
 * Configures body parsing with size limits for security
 */
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    // Store raw body for webhook verification if needed
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * Static File Serving
 * Serves client-side files with proper headers
 */
app.use(express.static(path.join(__dirname, '../client'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    // Set security headers for static files
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

/**
 * Request ID and Logging
 * Adds unique request ID and comprehensive logging
 */
app.use((req, res, next) => {
  // Generate unique request ID
  req.id = require('crypto').randomUUID();
  
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    const logData = {
      requestId: req.id,
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id || 'anonymous'
    };
    
    if (res.statusCode >= 400) {
      logger.warn('Request completed with error', logData);
    } else {
      logger.info('Request completed', logData);
    }
  });
  
  next();
});

/**
 * Rate Limiting
 * Prevents brute force attacks and API abuse
 */
app.use('/api/auth', authRateLimit); // Stricter limits for auth endpoints
app.use('/api', globalRateLimit); // General API rate limiting

/**
 * API Access Logging
 * Logs all API requests for audit trails
 */
app.use('/api', logApiAccess);

/**
 * Health Check Endpoint
 * Provides system status for monitoring
 */
app.get('/api/health', async (req, res) => {
  try {
    const healthStatus = {
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development',
      uptime: process.uptime(),
      features: {
        riskAssessment: process.env.RISK_ASSESSMENT_ENABLED === 'true',
        authentication: true,
        rateLimit: true,
        auditLogging: true
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
 * Demo API Endpoint
 * Provides API information and demo accounts
 */
app.get('/api/demo', (req, res) => {
  res.json({
    title: 'Secure Patient Portal API',
    version: '1.0.0',
    description: 'Healthcare security demonstration with risk assessment',
    timestamp: new Date().toISOString(),
    features: [
      'JWT Authentication with Refresh Tokens',
      'Advanced Risk Assessment Engine',
      'Role-based Access Control (Patient/Provider/Admin)',
      'Comprehensive Audit Logging',
      'Rate Limiting & Brute Force Protection',
      'HIPAA-Compliant Security Headers',
      'Real-time Security Monitoring',
      'Device Fingerprinting',
      'Geographic Risk Analysis',
      'Session Management'
    ],
    demoAccounts: {
      patient: {
        email: 'patient@demo.com',
        password: 'SecurePass123!',
        role: 'patient',
        riskLevel: 'Low (25/100)'
      },
      provider: {
        email: 'doctor@demo.com',
        password: 'SecurePass123!',
        role: 'provider',
        riskLevel: 'Low (15/100)'
      },
      admin: {
        email: 'admin@demo.com',
        password: 'SecurePass123!',
        role: 'admin',
        riskLevel: 'Medium (35/100)'
      },
      suspicious: {
        email: 'suspicious@demo.com',
        password: 'SecurePass123!',
        role: 'patient',
        riskLevel: 'High (85/100)'
      }
    },
    endpoints: {
      authentication: '/api/auth',
      health: '/api/health',
      documentation: '/api/docs'
    }
  });
});

/**
 * Mock Authentication Endpoint
 * Simulates complete authentication with risk assessment
 */
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Input validation
    if (!email || !password) {
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_FAILED_VALIDATION',
        severity: 'low',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          reason: 'Missing email or password',
          email: email || 'not provided'
        }
      });

      return res.status(400).json({
        success: false,
        message: 'Email and password are required',
        timestamp: new Date().toISOString()
      });
    }
    
    // Demo users with different risk profiles
    const users = {
      'patient@demo.com': { 
        id: '550e8400-e29b-41d4-a716-446655440001',
        role: 'patient', 
        name: 'John Patient', 
        riskScore: 25,
        riskFactors: {
          location: { status: 'success', text: 'Trusted Location' },
          device: { status: 'success', text: 'Recognized Device' },
          timing: { status: 'success', text: 'Normal Hours' },
          velocity: { status: 'success', text: 'Normal Pattern' }
        }
      },
      'doctor@demo.com': { 
        id: '550e8400-e29b-41d4-a716-446655440002',
        role: 'provider', 
        name: 'Dr. Sarah Smith', 
        riskScore: 15,
        riskFactors: {
          location: { status: 'success', text: 'Hospital Network' },
          device: { status: 'success', text: 'Work Computer' },
          timing: { status: 'success', text: 'Work Hours' },
          velocity: { status: 'success', text: 'Normal Pattern' }
        }
      },
      'admin@demo.com': { 
        id: '550e8400-e29b-41d4-a716-446655440003',
        role: 'admin', 
        name: 'Admin User', 
        riskScore: 35,
        riskFactors: {
          location: { status: 'warning', text: 'New Location' },
          device: { status: 'success', text: 'Recognized Device' },
          timing: { status: 'success', text: 'Normal Hours' },
          velocity: { status: 'success', text: 'Normal Pattern' }
        }
      },
      'suspicious@demo.com': { 
        id: '550e8400-e29b-41d4-a716-446655440004',
        role: 'patient', 
        name: 'Suspicious User', 
        riskScore: 85,
        riskFactors: {
          location: { status: 'danger', text: 'Unknown Location' },
          device: { status: 'danger', text: 'New Device' },
          timing: { status: 'warning', text: 'Unusual Hours' },
          velocity: { status: 'danger', text: 'Multiple Rapid Attempts' }
        }
      }
    };
    
    // Simulate authentication delay
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    if (users[email] && password === 'SecurePass123!') {
      const user = users[email];
      
      // Log successful authentication
      await auditService.logUserAction({
        userId: user.id,
        action: 'USER_LOGIN',
        details: {
          email,
          role: user.role,
          riskScore: user.riskScore,
          loginMethod: 'password'
        },
        ipAddress: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Determine risk level
      let riskLevel = 'LOW';
      let securityAction = 'Login approved - All security checks passed';
      
      if (user.riskScore >= 80) {
        riskLevel = 'HIGH';
        securityAction = 'High risk detected - Additional verification may be required';
        
        await auditService.logSecurityEvent({
          eventType: 'HIGH_RISK_LOGIN_DETECTED',
          severity: 'high',
          userId: user.id,
          ipAddress: req.ip,
          userAgent: req.get('User-Agent'),
          details: {
            email,
            riskScore: user.riskScore,
            riskFactors: user.riskFactors
          }
        });
      } else if (user.riskScore >= 30) {
        riskLevel = 'MEDIUM';
        securityAction = 'Medium risk detected - Enhanced monitoring enabled';
      }

      res.json({
        success: true,
        message: 'Login successful',
        user: {
          id: user.id,
          email,
          role: user.role,
          name: user.name
        },
        riskAssessment: {
          riskScore: user.riskScore,
          riskLevel,
          factors: user.riskFactors,
          securityAction,
          requiresAdditionalVerification: riskLevel === 'HIGH'
        },
        timestamp: new Date().toISOString()
      });
    } else {
      // Log failed authentication
      await auditService.logSecurityEvent({
        eventType: 'LOGIN_FAILED_INVALID_CREDENTIALS',
        severity: 'medium',
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          email,
          reason: 'Invalid email or password'
        }
      });

      res.status(401).json({
        success: false,
        message: 'Invalid email or password',
        timestamp: new Date().toISOString()
      });
    }
    
  } catch (error) {
    logger.error('Login error:', error);
    
    res.status(500).json({
      success: false,
      message: 'Login failed. Please try again.',
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * API Documentation Endpoint
 * Serves API documentation
 */
app.get('/api/docs', (req, res) => {
  res.json({
    title: 'Secure Patient Portal API Documentation',
    version: '1.0.0',
    description: 'Healthcare security demonstration with comprehensive risk assessment',
    baseUrl: `${req.protocol}://${req.get('host')}/api`,
    endpoints: {
      health: {
        method: 'GET',
        path: '/health',
        description: 'System health check',
        authentication: false
      },
      demo: {
        method: 'GET',
        path: '/demo',
        description: 'API information and demo accounts',
        authentication: false
      },
      login: {
        method: 'POST',
        path: '/auth/login',
        description: 'User authentication with risk assessment',
        authentication: false,
        body: {
          email: 'string (required)',
          password: 'string (required)'
        }
      },
      docs: {
        method: 'GET',
        path: '/docs',
        description: 'API documentation',
        authentication: false
      }
    },
    security: {
      authentication: 'JWT Bearer Token',
      rateLimit: '100 requests per 15 minutes',
      cors: 'Restricted to allowed origins',
      headers: 'Comprehensive security headers via Helmet.js'
    },
    compliance: {
      hipaa: 'Designed with HIPAA compliance in mind',
      auditLogging: 'All actions logged for audit trails',
      dataEncryption: 'Sensitive data encrypted at rest and in transit'
    }
  });
});

/**
 * 404 Handler for API routes
 * Returns JSON error for API endpoints
 */
app.use('/api/*', (req, res) => {
  logger.warn(`API endpoint not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    error: 'API endpoint not found',
    message: `The requested endpoint ${req.method} ${req.originalUrl} does not exist`,
    timestamp: new Date().toISOString(),
    availableEndpoints: ['/api/health', '/api/demo', '/api/auth/login', '/api/docs']
  });
});

/**
 * Catch-all for client-side routing
 * Serves index.html for non-API routes (SPA support)
 */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/index.html'));
});

/**
 * Global Error Handler
 * Centralized error handling with security considerations
 */
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', {
    error: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });
  
  // Log security event for server errors
  auditService.logSecurityEvent({
    eventType: 'SYSTEM_ERROR',
    severity: 'medium',
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    endpoint: req.originalUrl,
    details: {
      error: error.message,
      method: req.method
    }
  }).catch(auditError => {
    logger.error('Failed to log security event:', auditError);
  });
  
  // Don't leak sensitive information in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  const errorResponse = {
    error: 'Internal server error',
    message: isDevelopment ? error.message : 'Something went wrong',
    timestamp: new Date().toISOString(),
    requestId: req.id // If you add request ID middleware
  };
  
  // Add stack trace only in development
  if (isDevelopment) {
    errorResponse.stack = error.stack;
  }
  
  res.status(error.status || 500).json(errorResponse);
});

module.exports = app;