//server/server.js
/**
 * Secure Patient Portal Server - Fixed Version
 * Enhanced error handling and graceful fallbacks
 */

require('dotenv').config();

// Initialize logger first with error handling
let logger;
try {
  logger = require('./utils/logger');
} catch (error) {
  console.warn('Logger initialization failed, using console fallback:', error.message);
  logger = {
    info: console.log,
    error: console.error,
    warn: console.warn,
    debug: console.log
  };
}

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

/**
 * Initialize database and start server with error handling
 */
async function startServer() {
  try {
    logger.info('🏥 Starting Secure Patient Portal...');
    
    // Try to setup database
    let database;
    try {
      const { setupDatabase } = require('./config/database');
      await setupDatabase();
      logger.info('✅ Database connected successfully');
      database = true;
    } catch (dbError) {
      logger.warn('⚠️ Database setup failed, using in-memory mode:', dbError.message);
      database = false;
    }

    // Initialize models if database is available
    if (database) {
      try {
        await initializeModels();
        logger.info('✅ Models initialized');
      } catch (modelError) {
        logger.warn('⚠️ Model initialization failed:', modelError.message);
      }
    }

    // Initialize Express app
    let app;
    try {
      app = require('./app');
      logger.info('✅ Express app initialized');
    } catch (appError) {
      logger.error('❌ Express app initialization failed:', appError.message);
      
      // Fallback to minimal app
      logger.info('🔄 Starting with minimal configuration...');
      app = createMinimalApp();
    }

    // Start HTTP server
    const server = app.listen(PORT, () => {
      displayStartupBanner(database);
    });

    // Configure server settings
    server.timeout = 30000;
    server.keepAliveTimeout = 5000;
    server.headersTimeout = 6000;

    // Graceful shutdown handling
    setupGracefulShutdown(server);

    return server;

  } catch (error) {
    logger.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

/**
 * Create minimal Express app as fallback
 */
function createMinimalApp() {
  const express = require('express');
  const cors = require('cors');
  const path = require('path');
  
  const app = express();

  // Basic middleware
  app.use(cors({
    origin: ['http://localhost:8080', 'http://127.0.0.1:8080'],
    credentials: true
  }));
  
  app.use(express.json());
  app.use(express.static(path.join(__dirname, '../client')));

  // Basic routes
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      mode: 'minimal',
      environment: NODE_ENV
    });
  });

  // Demo login
  app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;
    
    const users = {
      'patient@demo.com': { id: '1', role: 'patient', name: 'John Patient', riskScore: 25 },
      'doctor@demo.com': { id: '2', role: 'provider', name: 'Dr. Sarah Smith', riskScore: 15 },
      'admin@demo.com': { id: '3', role: 'admin', name: 'Admin User', riskScore: 35 },
      'suspicious@demo.com': { id: '4', role: 'patient', name: 'Suspicious User', riskScore: 85 }
    };
    
    if (users[email] && password === 'SecurePass123!') {
      const user = users[email];
      res.json({
        success: true,
        message: 'Login successful',
        user: { id: user.id, email, role: user.role, name: user.name },
        riskAssessment: {
          riskScore: user.riskScore,
          riskLevel: user.riskScore < 30 ? 'LOW' : user.riskScore < 60 ? 'MEDIUM' : 'HIGH'
        }
      });
    } else {
      res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
  });

  // Demo endpoint
  app.get('/demo', (req, res) => {
    res.json({
      title: 'HealthSecure Portal Demo',
      version: '1.0.0',
      mode: 'minimal',
      demoAccounts: {
        patient: { email: 'patient@demo.com', password: 'SecurePass123!' },
        provider: { email: 'doctor@demo.com', password: 'SecurePass123!' },
        admin: { email: 'admin@demo.com', password: 'SecurePass123!' },
        suspicious: { email: 'suspicious@demo.com', password: 'SecurePass123!' }
      }
    });
  });

  // Serve login page
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/index.html'));
  });

  // 404 handler
  app.use('*', (req, res) => {
    if (req.originalUrl.startsWith('/api/')) {
      res.status(404).json({ error: 'API endpoint not found' });
    } else {
      res.sendFile(path.join(__dirname, '../client/index.html'));
    }
  });

  return app;
}

/**
 * Initialize database models with error handling
 */
async function initializeModels() {
  try {
    // Try to import models
    try {
      require('./models/User');
      logger.debug('✅ User model loaded');
    } catch (error) {
      logger.warn('⚠️ User model not available:', error.message);
    }

    try {
      require('./models/securityLog');
      logger.debug('✅ SecurityLog model loaded');
    } catch (error) {
      logger.warn('⚠️ SecurityLog model not available:', error.message);
    }

    // Create demo users in development
    if (NODE_ENV === 'development') {
      try {
        await createDemoUsers();
      } catch (error) {
        logger.warn('⚠️ Demo user creation failed:', error.message);
      }
    }

  } catch (error) {
    logger.error('❌ Model initialization failed:', error);
    throw error;
  }
}

/**
 * Create demo users for development
 */
async function createDemoUsers() {
  try {
    const User = require('./models/User');
    
    // Check if demo users already exist
    const existingUser = await User.findOne({ where: { email: 'patient@demo.com' } });
    if (existingUser) {
      logger.debug('Demo users already exist');
      return;
    }

    // Create demo users (simplified)
    const demoUsers = [
      { email: 'patient@demo.com', password: 'SecurePass123!', firstName: 'John', lastName: 'Patient', role: 'patient' },
      { email: 'doctor@demo.com', password: 'SecurePass123!', firstName: 'Dr. Sarah', lastName: 'Smith', role: 'provider' },
      { email: 'admin@demo.com', password: 'SecurePass123!', firstName: 'Admin', lastName: 'User', role: 'admin' },
      { email: 'suspicious@demo.com', password: 'SecurePass123!', firstName: 'Suspicious', lastName: 'User', role: 'patient' }
    ];

    for (const userData of demoUsers) {
      try {
        await User.create(userData);
        logger.debug(`✅ Created demo user: ${userData.email}`);
      } catch (userError) {
        logger.warn(`⚠️ Failed to create user ${userData.email}:`, userError.message);
      }
    }

    logger.info('✅ Demo users setup completed');

  } catch (error) {
    logger.warn('⚠️ Demo user creation failed:', error.message);
  }
}

/**
 * Display startup banner
 */
function displayStartupBanner(databaseConnected) {
  const banner = `
🏥 ============================================
   SECURE PATIENT PORTAL
============================================
🚀 Server running on port ${PORT}
📊 Environment: ${NODE_ENV}
💾 Database: ${databaseConnected ? 'Connected' : 'Fallback Mode'}
🌐 Frontend: http://localhost:8080
🔌 API Base: http://localhost:${PORT}/api
📋 Health Check: http://localhost:${PORT}/api/health
🧪 Demo API: http://localhost:${PORT}/demo

Demo Accounts Available:
👤 Patient: patient@demo.com
👨‍⚕️ Provider: doctor@demo.com  
👨‍💼 Admin: admin@demo.com
🔍 High Risk: suspicious@demo.com
🔑 Password: SecurePass123!

${databaseConnected ? 'Full' : 'Minimal'} Mode Features:
✅ Authentication System
✅ Demo User Accounts
✅ Risk Assessment
${databaseConnected ? '✅ Database Storage' : '⚠️ In-Memory Only'}
${databaseConnected ? '✅ Audit Logging' : '⚠️ Console Logging'}
============================================`;

  console.log(banner);
  
  logger.info('🏥 Secure Patient Portal started successfully', {
    port: PORT,
    environment: NODE_ENV,
    database: databaseConnected,
    mode: databaseConnected ? 'full' : 'minimal'
  });
}

/**
 * Setup graceful shutdown handlers
 */
function setupGracefulShutdown(server) {
  const shutdownSignals = ['SIGTERM', 'SIGINT', 'SIGUSR2'];
  
  shutdownSignals.forEach(signal => {
    process.on(signal, async () => {
      logger.info(`${signal} received. Starting graceful shutdown...`);
      
      try {
        server.close(async () => {
          logger.info('HTTP server closed');
          
          try {
            // Try to close database connections
            const { closeDatabase } = require('./config/database');
            await closeDatabase();
          } catch (error) {
            logger.warn('Database close failed:', error.message);
          }
          
          logger.info('Graceful shutdown completed');
          process.exit(0);
        });
        
        // Force shutdown after timeout
        setTimeout(() => {
          logger.error('Graceful shutdown timeout. Forcing exit.');
          process.exit(1);
        }, 10000);
        
      } catch (error) {
        logger.error('Error during graceful shutdown:', error);
        process.exit(1);
      }
    });
  });
}

/**
 * Global error handlers
 */
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled Rejection:', reason);
  process.exit(1);
});

// Start the server
if (require.main === module) {
  startServer().catch(error => {
    console.error('Fatal startup error:', error);
    process.exit(1);
  });
}

module.exports = { startServer };