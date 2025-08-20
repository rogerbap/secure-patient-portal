//server/app.js
/**
 * Secure Patient Portal - Express Application Configuration
 * 
 * Updated to include all routes and enhanced middleware configuration.
 * Implements healthcare-grade security measures with comprehensive
 * route handling and error management.
 */
//server/app.js - Complete Updated Version
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
  crossOriginEmbedderPolicy: false
}));

/**
 * CORS Configuration
 */
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.CLIENT_URL || 'http://localhost:8080',
      'http://localhost:3000',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:3000'
    ];
    
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
 */
app.use(session({
  secret: process.env.SESSION_SECRET || 'demo-session-secret-change-in-production',
  name: 'patientPortalSession',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: 'strict'
  }
}));

/**
 * Request Parsing Middleware
 */
app.use(express.json({ 
  limit: '10mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

/**
 * Static File Serving
 */
app.use(express.static(path.join(__dirname, '../client'), {
  maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

/**
 * Request ID and Logging
 */
app.use((req, res, next) => {
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
 */
app.use('/api/auth', authRateLimit);
app.use('/api', globalRateLimit);

/**
 * API Access Logging
 */
app.use('/api', logApiAccess);

/**
 * Mount API Routes - FIRST
 */
app.use('/api', apiRoutes);

/**
 * Demo endpoint
 */
app.get('/demo', (req, res) => {
  res.json({
    title: 'HealthSecure Portal Demo',
    version: '1.0.0',
    description: 'Healthcare security demonstration with risk assessment',
    timestamp: new Date().toISOString(),
    mode: 'minimal',
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
      login: '/',
      dashboard: '/dashboard/',
      api: '/api',
      health: '/api/health'
    }
  });
});

/**
 * Handle client-side routing for dashboard
 */
app.get('/dashboard/*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/dashboard/patient.html'));
});

/**
 * Legacy login route - redirect to index
 */
app.get('/login', (req, res) => {
  res.redirect('/');
});

/**
 * Root endpoint - serve index.html (login page)
 */
app.get('/', (req, res) => {
  // Check if this is an API request
  if (req.headers.accept && req.headers.accept.includes('application/json')) {
    res.json({
      name: 'HealthSecure Portal',
      version: '1.0.0',
      description: 'Secure Patient Portal with Advanced Risk Assessment',
      api: {
        baseUrl: '/api',
        documentation: '/api/docs',
        health: '/api/health'
      },
      frontend: {
        login: '/',
        dashboard: '/dashboard/'
      },
      timestamp: new Date().toISOString()
    });
  } else {
    // Serve the index page (login page)
    res.sendFile(path.join(__dirname, '../client/index.html'));
  }
});

/**
 * 404 Handler - MUST BE LAST
 */
app.use('*', (req, res) => {
  if (req.originalUrl.startsWith('/api/')) {
    res.status(404).json({ 
      error: 'API endpoint not found',
      path: req.originalUrl,
      timestamp: new Date().toISOString()
    });
  } else {
    // For any unknown route, serve the login page
    res.status(404).sendFile(path.join(__dirname, '../client/index.html'));
  }
});

/**
 * Global Error Handler
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
  
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  if (req.originalUrl.startsWith('/api/') || 
      (req.headers.accept && req.headers.accept.includes('application/json'))) {
    
    const errorResponse = {
      success: false,
      error: 'Internal server error',
      message: isDevelopment ? error.message : 'Something went wrong',
      timestamp: new Date().toISOString(),
      requestId: req.id
    };
    
    if (isDevelopment) {
      errorResponse.stack = error.stack;
    }
    
    res.status(error.status || 500).json(errorResponse);
  } else {
    res.status(500).sendFile(path.join(__dirname, '../client/index.html'));
  }
});

/**
 * Graceful shutdown handling
 */
process.on('SIGTERM', () => {
  logger.info('SIGTERM received. Starting graceful shutdown...');
});

process.on('SIGINT', () => {
  logger.info('SIGINT received. Starting graceful shutdown...');
});

module.exports = app;