
const { Sequelize } = require('sequelize');
const path = require('path');
const fs = require('fs');

// Create a simple logger if the main logger isn't available yet
const createSimpleLogger = () => ({
  info: (msg, data) => console.log(`[DB INFO] ${msg}`, data || ''),
  error: (msg, data) => console.error(`[DB ERROR] ${msg}`, data || ''),
  debug: (msg, data) => process.env.NODE_ENV === 'development' && console.log(`[DB DEBUG] ${msg}`, data || ''),
  warn: (msg, data) => console.warn(`[DB WARN] ${msg}`, data || '')
});

const logger = createSimpleLogger();

// Environment configuration
const NODE_ENV = process.env.NODE_ENV || 'development';
const DATABASE_URL = process.env.DATABASE_URL;

/**
 * Database configuration for different environments
 */
const config = {
  development: {
    dialect: 'sqlite',
    storage: path.join(__dirname, '../../database/development.db'),
    logging: (msg) => logger.debug('Database Query:', msg),
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  },
  
  test: {
    dialect: 'sqlite',
    storage: ':memory:',
    logging: false,
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000
    }
  },
  
  production: {
    use_env_variable: 'DATABASE_URL',
    dialect: 'postgres',
    logging: false,
    dialectOptions: {
      ssl: process.env.DATABASE_SSL === 'true' ? {
        require: true,
        rejectUnauthorized: false
      } : false
    },
    pool: {
      max: 20,
      min: 0,
      acquire: 60000,
      idle: 10000
    }
  }
};

/**
 * Initialize Sequelize instance based on environment
 */
let sequelize;

// Ensure database directory exists for SQLite
const ensureDatabaseDirectory = () => {
  if (NODE_ENV === 'development' || NODE_ENV === 'test') {
    const dbDir = path.join(__dirname, '../../database');
    if (!fs.existsSync(dbDir)) {
      fs.mkdirSync(dbDir, { recursive: true });
      logger.info('Created database directory');
    }
  }
};

// Initialize database
const initializeDatabase = () => {
  try {
    ensureDatabaseDirectory();

    if (NODE_ENV === 'production' && DATABASE_URL) {
      // Production configuration with connection string
      sequelize = new Sequelize(DATABASE_URL, {
        ...config.production,
        define: getGlobalModelOptions()
      });
    } else {
      // Development/test configuration
      const envConfig = config[NODE_ENV];
      sequelize = new Sequelize({
        ...envConfig,
        define: getGlobalModelOptions()
      });
    }

    logger.info(`Database initialized for ${NODE_ENV} environment`);
    return sequelize;

  } catch (error) {
    logger.error('Database initialization failed:', error);
    throw error;
  }
};

/**
 * Get global model options for security and consistency
 */
function getGlobalModelOptions() {
  return {
    timestamps: true, // Adds createdAt and updatedAt
    paranoid: true, // Enables soft deletes (deletedAt)
    underscored: true, // Use snake_case for database columns
    freezeTableName: true, // Prevent pluralization of table names
    
    // Security: Add hooks for data validation
    hooks: {
      beforeCreate: (instance, options) => {
        // Add creation audit trail
        if (options.user?.id) {
          instance.created_by = options.user.id;
        }
      },
      beforeUpdate: (instance, options) => {
        // Add update audit trail
        if (options.user?.id) {
          instance.updated_by = options.user.id;
        }
      }
    }
  };
}

/**
 * Test database connection and handle errors
 */
const testConnection = async () => {
  try {
    await sequelize.authenticate();
    logger.info(`Database connected successfully (${NODE_ENV})`);
    return true;
  } catch (error) {
    logger.error('Database connection failed:', error);
    return false;
  }
};

/**
 * Setup database with proper error handling
 */
const setupDatabase = async () => {
  try {
    // Test connection first
    const isConnected = await testConnection();
    if (!isConnected) {
      throw new Error('Database connection failed');
    }

    // Sync models in development (be careful in production)
    if (NODE_ENV === 'development') {
      await sequelize.sync({ force: false, alter: true });
      logger.info('Database models synchronized');
      
      // Create demo data
      await createDemoData();
    }

    logger.info('Database setup completed successfully');
    return sequelize;

  } catch (error) {
    logger.error('Database setup failed:', error);
    throw error;
  }
};

/**
 * Create demo data for development
 */
const createDemoData = async () => {
  try {
    // This will be called after models are defined
    // For now, just log that demo data creation is ready
    logger.info('Demo data creation ready');
  } catch (error) {
    logger.error('Demo data creation failed:', error);
  }
};

/**
 * Graceful database shutdown
 */
const closeDatabase = async () => {
  try {
    if (sequelize) {
      await sequelize.close();
      logger.info('Database connection closed');
    }
  } catch (error) {
    logger.error('Error closing database connection:', error);
  }
};

/**
 * Database health check
 */
const healthCheck = async () => {
  try {
    await sequelize.authenticate();
    return {
      status: 'healthy',
      dialect: sequelize.getDialect(),
      database: sequelize.getDatabaseName()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      error: error.message
    };
  }
};

/**
 * Execute raw SQL with proper error handling (use sparingly)
 */
const executeRawQuery = async (query, replacements = {}) => {
  try {
    const [results, metadata] = await sequelize.query(query, {
      replacements,
      type: Sequelize.QueryTypes.SELECT
    });
    
    logger.debug('Raw query executed:', { query, replacements });
    return results;
    
  } catch (error) {
    logger.error('Raw query failed:', { query, error: error.message });
    throw error;
  }
};

/**
 * Transaction wrapper for complex operations
 */
const withTransaction = async (callback) => {
  const transaction = await sequelize.transaction();
  
  try {
    const result = await callback(transaction);
    await transaction.commit();
    logger.debug('Transaction committed successfully');
    return result;
    
  } catch (error) {
    await transaction.rollback();
    logger.error('Transaction rolled back:', error.message);
    throw error;
  }
};

// Initialize the database
sequelize = initializeDatabase();

/**
 * Export configured sequelize instance and utilities
 */
module.exports = {
  sequelize,
  Sequelize,
  setupDatabase,
  closeDatabase,
  healthCheck,
  executeRawQuery,
  withTransaction,
  
  // Export for direct access in models
  DataTypes: Sequelize.DataTypes,
  Op: Sequelize.Op
};