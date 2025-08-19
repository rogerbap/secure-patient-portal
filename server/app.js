/**
 * Secure Patient Portal - Express Application Configuration
 * 
 * Updated to include all routes and enhanced middleware configuration.
 * Implements healthcare-grade security measures with comprehensive
 * route handling and error management.
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

// Import routes
const apiRoutes = require('./routes/index');

// Create Express application
const app = express();

/**
 * Security Configuration
 * Implements comprehensive security headers and policies
 */
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
 * Mount API Routes
 * All API routes are handled through the centralized router
 */
app.use('/api', apiRoutes);

/**
 * Root endpoint - redirect to login or serve app info
 */
app.get('/', (req, res) => {
  // Check if this is an API request
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    res.json({
      name: 'HealthSecure Portal',
      version: '1.0.0',
      description: 'Secure Patient Portal with Advanced Risk Assessment',
      api: {
        baseUrl: `/api`,
        documentation: `/api/docs`,
        health: `/api/health`
      },
      frontend: {
        login: `/login.html`,
        dashboard: `/dashboard/`
      },
      timestamp: new Date().toISOString()
    });
  } else {
    // Serve the login page for browser requests
    res.sendFile(path.join(__dirname, '../client/login.html'));
  }
});

/**
 * Demo endpoint for showcasing API capabilities
 */
app.get('/demo', (req, res) => {
  res.json({
    title: 'HealthSecure Portal Demo',
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
        riskLevel: 'Low (25/100)',
        description: 'Standard patient account with normal access patterns'
      },
      provider: {
        email: 'doctor@demo.com',
        password: 'SecurePass123!',
        role: 'provider',
        riskLevel: 'Low (15/100)',
        description: 'Healthcare provider with trusted network access'
      },
      admin: {
        email: 'admin@demo.com',
        password: 'SecurePass123!',
        role: 'admin',
        riskLevel: 'Medium (35/100)',
        description: 'System administrator with elevated privileges'
      },
      suspicious: {
        email: 'suspicious@demo.com',
        password: 'SecurePass123!',
        role: 'patient',
        riskLevel: 'High (85/100)',
        description: 'High-risk scenario demonstrating security response'
      }
    },
    endpoints: {
      authentication: '/api/auth',
      dashboard: '/api/dashboard',
      security: '/api/security',
      health: '/api/health',
      documentation: '/api/docs'
    },
    quickStart: {
      login: 'POST /api/auth/login',
      dashboard: 'GET /api/dashboard/{role}',
      profile: 'GET /api/auth/profile'
    }
  });
});

/**
 * Handle client-side routing for SPA
 * Serves index.html for non-API routes to support client-side routing
 */
app.get('/dashboard/*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/dashboard/patient.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/login.html'));
});

/**
 * 404 Handler for non-API routes
 * Returns appropriate response based on request type
 */
app.use((req, res, next) => {
  // Check if this is an API request
  if (req.originalUrl.startsWith('/api/')) {
    // API 404 is handled by the API routes
    return next();
  }

  // For non-API requests, check accept header
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    res.status(404).json({
      error: 'Page not found',
      message: `The requested page ${req.originalUrl} does not exist`,
      timestamp: new Date().toISOString(),
      availablePages: [
        '/',
        '/login',
        '/dashboard/',
        '/demo'
      ]
    });
  } else {
    // Serve 404 page or redirect to login
    res.status(404).sendFile(path.join(__dirname, '../client/login.html'));
  }
});

/**
 * Global Error Handler
 * Centralized error handling with security considerations
 */
app.use((error, req, res, next) => {
  logger.error('Unhandled application error:', {
    error: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    requestId: req.id
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
      method: req.method,
      requestId: req.id
    }
  }).catch(auditError => {
    logger.error('Failed to log security event:', auditError);
  });
  
  // Don't leak sensitive information in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  // Check if this is an API request
  if (req.originalUrl.startsWith('/api/') || 
      (req.headers.accept && req.headers.accept.includes('application/json'))) {
    
    const errorResponse = {
      success: false,
      error: 'Internal server error',
      message: isDevelopment ? error.message : 'Something went wrong',
      timestamp: new Date().toISOString(),
      requestId: req.id
    };
    
    // Add stack trace only in development
    if (isDevelopment) {
      errorResponse.stack = error.stack;
    }
    
    res.status(error.status || 500).json(errorResponse);
  } else {
    // For non-API requests, serve error page
    res.status(500).sendFile(path.join(__dirname, '../client/login.html'));
  }
});

/**
 * Graceful shutdown handling
 */
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Starting graceful shutdown...');
  // Perform cleanup operations here
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Starting graceful shutdown...');
  // Perform cleanup operations here
});

module.exports = app;