//server/routes/index.js
const express = require('express');
const router = express.Router();

// Import route modules
const authRoutes = require('./auth');
const dashboardRoutes = require('./dashboard');
const securityRoutes = require('./security');
const healthRoutes = require('./health');

// Import middleware
const { authenticateToken } = require('../middleware/auth');
const { globalRateLimit } = require('../middleware/rateLimit');
const auditService = require('../services/auditService');

/**
 * API Documentation endpoint
 */
router.get('/', (req, res) => {
  res.json({
    name: 'HealthSecure Portal API',
    version: '1.0.0',
    description: 'Secure Patient Portal with Advanced Risk Assessment',
    timestamp: new Date().toISOString(),
    endpoints: {
      authentication: '/api/auth',
      dashboard: '/api/dashboard',
      security: '/api/security',
      health: '/api/health'
    },
    features: [
      'JWT Authentication with Refresh Tokens',
      'Advanced Risk Assessment Engine',
      'Role-based Access Control',
      'Real-time Security Monitoring',
      'HIPAA-Compliant Audit Logging',
      'Rate Limiting & DDoS Protection'
    ],
    documentation: {
      swagger: '/api/docs',
      postman: '/api/postman'
    }
  });
});

/**
 * Mount route modules with appropriate middleware
 */

// Health and system status routes (no authentication required)
router.use('/health', healthRoutes);

// Authentication routes (public with rate limiting)
router.use('/auth', authRoutes);

// Security monitoring routes (mixed authentication)
router.use('/security', securityRoutes);

// Dashboard routes (require authentication)
router.use('/dashboard', authenticateToken, dashboardRoutes);

/**
 * API Statistics endpoint
 */
router.get('/stats', globalRateLimit, async (req, res) => {
  try {
    // Get basic API statistics
    const stats = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV || 'development',
      nodeVersion: process.version,
      apiVersion: '1.0.0'
    };

    // Add security statistics if user is authenticated
    if (req.user && req.user.role === 'admin') {
      const securityStats = await auditService.getAuditStatistics();
      stats.security = securityStats;
    }

    res.json({
      success: true,
      data: stats
    });

  } catch (error) {
    console.error('Stats endpoint error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to retrieve statistics'
    });
  }
});

/**
 * API Documentation endpoint (Swagger-style)
 */
router.get('/docs', (req, res) => {
  res.json({
    openapi: '3.0.0',
    info: {
      title: 'HealthSecure Portal API',
      version: '1.0.0',
      description: 'Secure Patient Portal with Advanced Risk Assessment',
      contact: {
        name: 'API Support',
        email: 'support@healthsecure.com'
      }
    },
    servers: [
      {
        url: `${req.protocol}://${req.get('host')}/api`,
        description: 'Development server'
      }
    ],
    paths: {
      '/auth/login': {
        post: {
          summary: 'User authentication',
          description: 'Authenticate user with email and password, includes risk assessment',
          tags: ['Authentication'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', minLength: 8 }
                  },
                  required: ['email', 'password']
                }
              }
            }
          },
          responses: {
            200: {
              description: 'Successful authentication',
              content: {
                'application/json': {
                  schema: {
                    type: 'object',
                    properties: {
                      success: { type: 'boolean' },
                      accessToken: { type: 'string' },
                      user: { type: 'object' },
                      riskAssessment: { type: 'object' }
                    }
                  }
                }
              }
            },
            401: { description: 'Invalid credentials' },
            429: { description: 'Too many requests' }
          }
        }
      },
      '/auth/register': {
        post: {
          summary: 'User registration',
          description: 'Register new user account',
          tags: ['Authentication'],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    email: { type: 'string', format: 'email' },
                    password: { type: 'string', minLength: 8 },
                    firstName: { type: 'string' },
                    lastName: { type: 'string' },
                    role: { type: 'string', enum: ['patient', 'provider', 'admin'] }
                  },
                  required: ['email', 'password', 'firstName', 'lastName']
                }
              }
            }
          }
        }
      },
      '/dashboard/patient': {
        get: {
          summary: 'Get patient dashboard data',
          description: 'Retrieve dashboard information for patient users',
          tags: ['Dashboard'],
          security: [{ bearerAuth: [] }],
          responses: {
            200: {
              description: 'Dashboard data retrieved successfully'
            },
            401: { description: 'Authentication required' },
            403: { description: 'Insufficient permissions' }
          }
        }
      },
      '/health': {
        get: {
          summary: 'Health check',
          description: 'Check API health and system status',
          tags: ['System'],
          responses: {
            200: {
              description: 'System is healthy'
            }
          }
        }
      }
    },
    components: {
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT'
        }
      }
    },
    tags: [
      { name: 'Authentication', description: 'User authentication and authorization' },
      { name: 'Dashboard', description: 'Dashboard data and functionality' },
      { name: 'Security', description: 'Security monitoring and logs' },
      { name: 'System', description: 'System health and monitoring' }
    ]
  });
});

/**
 * Postman Collection endpoint
 */
router.get('/postman', (req, res) => {
  const baseUrl = `${req.protocol}://${req.get('host')}/api`;
  
  res.json({
    info: {
      name: 'HealthSecure Portal API',
      description: 'Complete API collection for testing',
      schema: 'https://schema.getpostman.com/json/collection/v2.1.0/collection.json'
    },
    item: [
      {
        name: 'Authentication',
        item: [
          {
            name: 'Login',
            request: {
              method: 'POST',
              header: [
                {
                  key: 'Content-Type',
                  value: 'application/json'
                }
              ],
              body: {
                mode: 'raw',
                raw: JSON.stringify({
                  email: 'patient@demo.com',
                  password: 'SecurePass123!'
                })
              },
              url: {
                raw: `${baseUrl}/auth/login`,
                host: [baseUrl],
                path: ['auth', 'login']
              }
            }
          },
          {
            name: 'Register',
            request: {
              method: 'POST',
              header: [
                {
                  key: 'Content-Type',
                  value: 'application/json'
                }
              ],
              body: {
                mode: 'raw',
                raw: JSON.stringify({
                  email: 'newuser@example.com',
                  password: 'SecurePass123!',
                  firstName: 'John',
                  lastName: 'Doe',
                  role: 'patient'
                })
              },
              url: {
                raw: `${baseUrl}/auth/register`,
                host: [baseUrl],
                path: ['auth', 'register']
              }
            }
          }
        ]
      },
      {
        name: 'Dashboard',
        item: [
          {
            name: 'Patient Dashboard',
            request: {
              method: 'GET',
              header: [
                {
                  key: 'Authorization',
                  value: 'Bearer {{accessToken}}'
                }
              ],
              url: {
                raw: `${baseUrl}/dashboard/patient`,
                host: [baseUrl],
                path: ['dashboard', 'patient']
              }
            }
          }
        ]
      }
    ],
    variable: [
      {
        key: 'baseUrl',
        value: baseUrl
      },
      {
        key: 'accessToken',
        value: ''
      }
    ]
  });
});

/**
 * API Testing endpoint for development
 */
if (process.env.NODE_ENV === 'development') {
  router.get('/test', (req, res) => {
    res.json({
      message: 'API test endpoint',
      timestamp: new Date().toISOString(),
      headers: req.headers,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      environment: process.env.NODE_ENV
    });
  });
}

/**
 * Catch-all for unmatched API routes
 */
router.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'API endpoint not found',
    path: req.originalUrl,
    method: req.method,
    timestamp: new Date().toISOString(),
    availableEndpoints: [
      '/api/auth',
      '/api/dashboard',
      '/api/security',
      '/api/health',
      '/api/docs'
    ]
  });
});

/**
 * Global error handler for API routes
 */
router.use((error, req, res, next) => {
  console.error('API Route Error:', {
    error: error.message,
    stack: error.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip
  });

  // Log security event for server errors
  auditService.logSecurityEvent({
    eventType: 'API_ERROR',
    severity: 'medium',
    ipAddress: req.ip,
    userAgent: req.get('User-Agent'),
    endpoint: req.originalUrl,
    details: {
      error: error.message,
      method: req.method
    }
  }).catch(auditError => {
    console.error('Failed to log API error:', auditError);
  });

  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(error.status || 500).json({
    success: false,
    message: isDevelopment ? error.message : 'Internal server error',
    timestamp: new Date().toISOString(),
    requestId: req.id,
    ...(isDevelopment && { stack: error.stack })
  });
});

module.exports = router;