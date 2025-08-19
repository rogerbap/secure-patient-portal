require('dotenv').config();

// Import core modules
const app = require('./app');
const { setupDatabase, closeDatabase } = require('./config/database');

// Initialize logger first
let logger;
try {
  logger = require('./utils/logger');
} catch (error) {
  // Fallback logger if Winston setup fails
  logger = {
    info: console.log,
    error: console.error,
    warn: console.warn,
    debug: console.log
  };
}

// Configuration
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * Initialize database and start server
 * Ensures database is properly connected before accepting requests
 */
async function startServer() {
  try {
    // Setup database connection and models
    logger.info('Setting up database connection...');
    await setupDatabase();
    
    // Initialize models after database setup
    await initializeModels();

    // Start HTTP server
    const server = app.listen(PORT, () => {
      displayStartupBanner();
    });

    // Configure server settings
    server.timeout = 30000; // 30 second timeout
    server.keepAliveTimeout = 5000; // 5 second keep-alive
    server.headersTimeout = 6000; // Headers timeout slightly higher than keep-alive

    // Graceful shutdown handling
    setupGracefulShutdown(server);

    return server;

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Initialize database models
 * Sets up all Sequelize models and associations
 */
async function initializeModels() {
  try {
    // Import models to ensure they're registered with Sequelize
    require('./models/User');
    require('./models/securityLog');
    
    // Future models can be added here:
    // require('./models/Appointment');
    // require('./models/MedicalRecord');
    // require('./models/Patient');
    
    logger.info('Database models initialized');

    // Create demo users in development
    if (NODE_ENV === 'development') {
      await createDemoUsers();
    }

  } catch (error) {
    logger.error('Model initialization failed:', error);
    throw error;
  }
}

/**
 * Create demo users for development and testing
 */
async function createDemoUsers() {
  try {
    const User = require('./models/User');
    const authService = require('./services/authService');

    // Check if demo users already exist
    const existingUser = await User.findOne({ where: { email: 'patient@demo.com' } });
    if (existingUser) {
      logger.debug('Demo users already exist');
      return;
    }

    // Create demo users
    const demoUsers = [
      {
        email: 'patient@demo.com',
        password: 'SecurePass123!',
        firstName: 'John',
        lastName: 'Patient',
        role: 'patient',
        dateOfBirth: '1985-06-15',
        phone: '+1-555-0101',
        isActive: true,
        emailVerified: true
      },
      {
        email: 'doctor@demo.com',
        password: 'SecurePass123!',
        firstName: 'Dr. Sarah',
        lastName: 'Smith',
        role: 'provider',
        dateOfBirth: '1978-03-22',
        phone: '+1-555-0102',
        isActive: true,
        emailVerified: true
      },
      {
        email: 'admin@demo.com',
        password: 'SecurePass123!',
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
        dateOfBirth: '1980-11-08',
        phone: '+1-555-0103',
        isActive: true,
        emailVerified: true
      },
      {
        email: 'suspicious@demo.com',
        password: 'SecurePass123!',
        firstName: 'Suspicious',
        lastName: 'User',
        role: 'patient',
        dateOfBirth: '1990-01-01',
        phone: '+1-555-0104',
        isActive: true,
        emailVerified: false
      }
    ];

    for (const userData of demoUsers) {
      // Hash password
      userData.password = await authService.hashPassword(userData.password);
      
      // Create user
      const user = await User.create(userData);
      logger.debug(`Created demo user: ${user.email} (${user.role})`);
    }

    logger.info('Demo users created successfully');

  } catch (error) {
    logger.error('Failed to create demo users:', error);
    // Don't throw error - demo users are not critical for server startup
  }
}

/**
 * Display startup banner with server information
 */
function displayStartupBanner() {
  const banner = `
🏥 ============================================
   SECURE PATIENT PORTAL
============================================
🚀 Server running on port ${PORT}
📊 Environment: ${NODE_ENV}
🔒 Security features enabled
🛡️  Risk assessment active
📝 Audit logging enabled
🌐 Frontend: http://localhost:8080
🔌 API Base: http://localhost:${PORT}/api
📋 Health Check: http://localhost:${PORT}/api/health
🧪 Demo API: http://localhost:${PORT}/api/demo
📚 Documentation: http://localhost:${PORT}/api/docs
============================================

Demo Accounts Available:
👤 Patient: patient@demo.com
👨‍⚕️ Provider: doctor@demo.com  
👨‍💼 Admin: admin@demo.com
🔍 High Risk: suspicious@demo.com
🔑 Password: SecurePass123!

Security Features:
✅ JWT Authentication
✅ Role-based Access Control
✅ Advanced Risk Assessment  
✅ Rate Limiting & DDoS Protection
✅ Comprehensive Audit Logging
✅ HIPAA-Compliant Security Headers
✅ Input Validation & Sanitization
✅ Session Management
✅ Device Fingerprinting

============================================`;

  console.log(banner);
  
  logger.info('🏥 Secure Patient Portal started successfully', {
    port: PORT,
    environment: NODE_ENV,
    features: {
      authentication: true,
      riskAssessment: process.env.RISK_ASSESSMENT_ENABLED === 'true',
      auditLogging: true,
      rateLimit: true
    }
  });
}

/**
 * Setup graceful shutdown handlers
 * Ensures clean shutdown of server and database connections
 */
function setupGracefulShutdown(server) {
  // Handle different shutdown signals
  const shutdownSignals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
  
  shutdownSignals.forEach(signal => {
    process.on(signal, async () => {
      logger.info(`${signal} received. Starting graceful shutdown...`);
      
      try {
        // Stop accepting new connections
        server.close(async () => {
          logger.info('HTTP server closed');
          
          try {
            // Close database connections
            await closeDatabase();
            
            logger.info('Graceful shutdown completed');
            process.exit(0);
          } catch (error) {
            logger.error('Error during database shutdown:', error);
            process.exit(1);
          }
        });
        
        // Force shutdown after timeout
        setTimeout(() => {
          logger.error('Graceful shutdown timeout. Forcing exit.');
          process.exit(1);
        }, 10000); // 10 second timeout
        
      } catch (error) {
        logger.error('Error during graceful shutdown:', error);
        process.exit(1);
      }
    });
  });
}

/**
 * Handle uncaught exceptions and unhandled rejections
 * Ensures application doesn't crash silently
 */
function setupErrorHandlers() {
  process.on('uncaughtException', (error) => {
    logger.error('Uncaught Exception:', {
      message: error.message,
      stack: error.stack,
      name: error.name
    });
    
    // Exit gracefully
    process.exit(1);
  });

  process.on('unhandledRejection', (reason, promise) => {
    logger.error('Unhandled Rejection:', {
      reason: reason instanceof Error ? reason.message : reason,
      stack: reason instanceof Error ? reason.stack : undefined,
      promise: promise
    });
    
    // Exit gracefully
    process.exit(1);
  });

  // Handle warning events
  process.on('warning', (warning) => {
    logger.warn('Process warning:', {
      name: warning.name,
      message: warning.message,
      stack: warning.stack
    });
  });
}

/**
 * Setup monitoring and health checks
 */
function setupMonitoring() {
  // Log memory usage periodically in development
  if (NODE_ENV === 'development') {
    setInterval(() => {
      const memUsage = process.memoryUsage();
      logger.debug('Memory usage:', {
        rss: `${Math.round(memUsage.rss / 1024 / 1024)} MB`,
        heapTotal: `${Math.round(memUsage.heapTotal / 1024 / 1024)} MB`,
        heapUsed: `${Math.round(memUsage.heapUsed / 1024 / 1024)} MB`,
        external: `${Math.round(memUsage.external / 1024 / 1024)} MB`
      });
    }, 60000); // Every minute
  }

  // Log uptime periodically
  setInterval(() => {
    const uptimeHours = Math.floor(process.uptime() / 3600);
    const uptimeMinutes = Math.floor((process.uptime() % 3600) / 60);
    
    logger.info(`Server uptime: ${uptimeHours}h ${uptimeMinutes}m`);
  }, 3600000); // Every hour
}

/**
 * Initialize environment validation
 */
function validateEnvironment() {
  const requiredEnvVars = [
    'JWT_SECRET',
    'JWT_REFRESH_SECRET',
    'SESSION_SECRET'
  ];

  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    logger.warn('Missing environment variables:', missingVars);
    
    if (NODE_ENV === 'production') {
      logger.error('Critical environment variables missing in production');
      process.exit(1);
    } else {
      logger.info('Using default values for development');
    }
  }

  // Validate JWT secrets length
  const jwtSecret = process.env.JWT_SECRET;
  if (jwtSecret && jwtSecret.length < 32) {
    logger.warn('JWT_SECRET should be at least 32 characters long');
  }

  // Log configuration status
  logger.info('Environment validation completed', {
    nodeEnv: NODE_ENV,
    port: PORT,
    riskAssessment: process.env.RISK_ASSESSMENT_ENABLED === 'true',
    auditLogging: process.env.AUDIT_LOG_ENABLED !== 'false',
    debugEnabled: process.env.DEBUG_ENABLED === 'true'
  });
}

/**
 * Main startup sequence
 */
async function main() {
  try {
    // Setup error handlers first
    setupErrorHandlers();
    
    // Validate environment
    validateEnvironment();
    
    // Setup monitoring
    setupMonitoring();
    
    // Start the server
    const server = await startServer();
    
    // Log successful startup
    logger.info('All systems initialized successfully');
    
    return server;

  } catch (error) {
    logger.error('Startup failed:', error);
    process.exit(1);
  }
}

// Start the server if this file is executed directly
if (require.main === module) {
  main().catch(error => {
    console.error('Fatal startup error:', error);
    process.exit(1);
  });
}

// Export for testing
module.exports = { 
  startServer,
  main,
  setupDatabase,
  initializeModels,
  createDemoUsers
};