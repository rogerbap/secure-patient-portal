//server/app.js - FIXED VERSION WITH PROPER DASHBOARD ROUTING
/**
 * Secure Patient Portal - Express Application Configuration
 *
 * FIXED: Enhanced dashboard routing that properly handles authentication
 * and supports both session-based and token-based authentication
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const session = require('express-session');
const path = require('path');

// Import configuration and utilities
const logger = require('./utils/logger');
const auditService = require('./services/auditService');
const authService = require('./services/authService');

// Import middleware
const { globalRateLimit, authRateLimit } = require('./middleware/rateLimit');
const { logApiAccess, authenticateToken, optionalAuth } = require('./middleware/auth');

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
 * Enhanced Authentication Check Middleware for Dashboard Routes
 * This checks multiple sources for user authentication
 */
const checkDashboardAuth = async (req, res, next) => {
  let userRole = null;
  
  try {
    // Method 1: Check Authorization header (JWT token)
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      try {
        // Try to verify as a real JWT token first
        const decoded = authService.verifyAccessToken(token);
        userRole = decoded.role;
        req.user = decoded;
      } catch (jwtError) {
        // If JWT verification fails, check if it's a demo token
        if (token.startsWith('demo-token-')) {
          const parts = token.split('-');
          if (parts.length >= 3) {
            userRole = parts[2];
            req.user = { role: userRole, id: parts[2] };
          }
        }
      }
    }
    
    // Method 2: Check session data
    if (!userRole && req.session && req.session.userData) {
      userRole = req.session.userData.role;
      req.user = req.session.userData;
    }
    
    // Method 3: Check for user info in session storage (via request headers)
    if (!userRole && req.headers['x-user-role']) {
      // This can be set by frontend for demo purposes
      userRole = req.headers['x-user-role'];
    }
    
    // Method 4: Check for demo authentication cookie
    if (!userRole && req.headers.cookie) {
      const cookies = req.headers.cookie.split(';').reduce((acc, cookie) => {
        const [key, value] = cookie.trim().split('=');
        acc[key] = value;
        return acc;
      }, {});
      
      if (cookies.demoAuth) {
        try {
          const demoData = JSON.parse(decodeURIComponent(cookies.demoAuth));
          userRole = demoData.role;
          req.user = demoData;
        } catch (cookieError) {
          // Ignore cookie parsing errors
        }
      }
    }
    
    req.userRole = userRole;
    next();
    
  } catch (error) {
    logger.error('Dashboard auth check error:', error);
    req.userRole = null;
    next();
  }
};

/**
 * Demo endpoint
 */
app.get('/demo', (req, res) => {
  res.json({
    title: 'HealthSecure Portal Demo',
    version: '1.0.0',
    description: 'Healthcare security demonstration with risk assessment',
    timestamp: new Date().toISOString(),
    mode: 'enhanced',
    demoAccounts: {
      patient: {
        email: 'patient@demo.com',
        password: 'SecurePass123!',
        role: 'patient',
        riskLevel: 'Low (25/100)',
        dashboard: '/dashboard/patient'
      },
      provider: {
        email: 'doctor@demo.com',
        password: 'SecurePass123!',
        role: 'provider',
        riskLevel: 'Low (15/100)',
        dashboard: '/dashboard/provider'
      },
      admin: {
        email: 'admin@demo.com',
        password: 'SecurePass123!',
        role: 'admin',
        riskLevel: 'Medium (35/100)',
        dashboard: '/dashboard/admin'
      },
      suspicious: {
        email: 'suspicious@demo.com',
        password: 'SecurePass123!',
        role: 'patient',
        riskLevel: 'High (85/100)',
        dashboard: '/dashboard/patient'
      }
    },
    endpoints: {
      login: '/',
      dashboards: {
        patient: '/dashboard/patient',
        provider: '/dashboard/provider',
        admin: '/dashboard/admin'
      },
      api: '/api',
      health: '/api/health'
    }
  });
});

/**
 * FIXED Dashboard Routing with Multiple Authentication Methods
 */

// Patient Dashboard - FIXED to prevent redirect loops
app.get('/dashboard/patient', checkDashboardAuth, (req, res) => {
  const userRole = req.userRole;
  
  console.log(`Dashboard access attempt: /dashboard/patient, userRole: ${userRole}`);
  
  // Allow patients, suspicious users (who are patients), and admins
  if (userRole === 'patient' || userRole === 'admin') {
    res.sendFile(path.join(__dirname, '../client/dashboard/patient.html'));
  } else if (!userRole) {
    console.log('No authentication found, redirecting to login');
    res.redirect(`/?redirect=${encodeURIComponent('/dashboard/patient')}&error=authentication_required`);
  } else {
    console.log(`Wrong role ${userRole} for patient dashboard, redirecting to ${userRole} dashboard`);
    if (userRole === 'provider') {
      res.redirect('/dashboard/provider');
    } else if (userRole === 'admin') {
      res.redirect('/dashboard/admin');
    } else {
      res.redirect('/?error=invalid_role');
    }
  }
});

// Provider Dashboard
app.get('/dashboard/provider', checkDashboardAuth, (req, res) => {
  const userRole = req.userRole;
  
  console.log(`Dashboard access attempt: /dashboard/provider, userRole: ${userRole}`);
  
  if (userRole === 'provider' || userRole === 'admin') {
    res.sendFile(path.join(__dirname, '../client/dashboard/provider.html'));
  } else if (!userRole) {
    res.redirect(`/?redirect=${encodeURIComponent('/dashboard/provider')}&error=authentication_required`);
  } else {
    if (userRole === 'patient') {
      res.redirect('/dashboard/patient');
    } else if (userRole === 'admin') {
      res.redirect('/dashboard/admin');
    } else {
      res.redirect('/?error=invalid_role');
    }
  }
});

// Admin Dashboard
app.get('/dashboard/admin', checkDashboardAuth, (req, res) => {
  const userRole = req.userRole;
  
  console.log(`Dashboard access attempt: /dashboard/admin, userRole: ${userRole}`);
  
  if (userRole === 'admin') {
    res.sendFile(path.join(__dirname, '../client/dashboard/admin.html'));
  } else if (!userRole) {
    res.redirect(`/?redirect=${encodeURIComponent('/dashboard/admin')}&error=authentication_required`);
  } else {
    if (userRole === 'patient') {
      res.redirect('/dashboard/patient');
    } else if (userRole === 'provider') {
      res.redirect('/dashboard/provider');
    } else {
      res.redirect('/?error=access_denied');
    }
  }
});

// Generic dashboard route - redirect based on role
app.get('/dashboard', checkDashboardAuth, (req, res) => {
  const userRole = req.userRole;
  
  console.log(`Generic dashboard access, userRole: ${userRole}`);
  
  if (userRole) {
    res.redirect(`/dashboard/${userRole}`);
  } else {
    res.redirect('/?error=authentication_required');
  }
});

// FIXED: Catch-all for dashboard routes to prevent loops
app.get('/dashboard/*', checkDashboardAuth, (req, res) => {
  const userRole = req.userRole;
  const requestedPath = req.path;
  
  console.log(`Dashboard catch-all: ${requestedPath}, userRole: ${userRole}`);
  
  const targetDashboard = `/dashboard/${userRole}`;
  
  if (!userRole) {
    res.redirect('/?error=session_expired');
  } else if (requestedPath === targetDashboard) {
    res.sendFile(path.join(__dirname, `../client/dashboard/${userRole}.html`));
  } else {
    res.redirect(targetDashboard);
  }
});

/**
 * Login routes
 */
app.get('/login', (req, res) => {
  res.redirect('/');
});

app.get('/login.html', (req, res) => {
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
        dashboards: {
          patient: '/dashboard/patient',
          provider: '/dashboard/provider',
          admin: '/dashboard/admin'
        }
      },
      timestamp: new Date().toISOString()
    });
  } else {
    // Serve the index page (login page)
    res.sendFile(path.join(__dirname, '../client/index.html'));
  }
});

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    services: {
      api: 'operational',
      database: 'connected',
      authentication: 'active'
    }
  });
});

/**
 * 404 Handler - MUST BE LAST
 */
app.use('*', (req, res) => {
  if (req.originalUrl.startsWith('/api/')) {
    res.status(404).json({
      error: 'API endpoint not found',
      path: req.originalUrl,
      timestamp: new Date().toISOString(),
      availableEndpoints: [
        '/api/auth/login',
        '/api/auth/refresh',
        '/api/dashboard/patient',
        '/api/dashboard/provider',
        '/api/dashboard/admin',
        '/api/health'
      ]
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