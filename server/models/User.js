
const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/database');
const bcrypt = require('bcryptjs');

/**
 * User Model Definition
 */
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    allowNull: false
  },
  
  // Authentication fields
  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: {
      isEmail: {
        msg: 'Must be a valid email address'
      },
      len: {
        args: [5, 255],
        msg: 'Email must be between 5 and 255 characters'
      }
    },
    set(value) {
      // Normalize email to lowercase
      this.setDataValue('email', value ? value.toLowerCase().trim() : value);
    }
  },
  
  password: {
    type: DataTypes.STRING(255),
    allowNull: false,
    validate: {
      len: {
        args: [8, 255],
        msg: 'Password must be at least 8 characters long'
      },
      isComplex(value) {
        // Password complexity validation
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/.test(value)) {
          throw new Error('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
        }
      }
    }
  },
  
  // Personal information
  firstName: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      len: {
        args: [1, 100],
        msg: 'First name must be between 1 and 100 characters'
      },
      is: {
        args: /^[a-zA-Z\s\-'\.]+$/,
        msg: 'First name can only contain letters, spaces, hyphens, apostrophes, and periods'
      }
    },
    set(value) {
      // Capitalize first letter of each word
      this.setDataValue('firstName', value ? value.trim().replace(/\b\w/g, l => l.toUpperCase()) : value);
    }
  },
  
  lastName: {
    type: DataTypes.STRING(100),
    allowNull: false,
    validate: {
      len: {
        args: [1, 100],
        msg: 'Last name must be between 1 and 100 characters'
      },
      is: {
        args: /^[a-zA-Z\s\-'\.]+$/,
        msg: 'Last name can only contain letters, spaces, hyphens, apostrophes, and periods'
      }
    },
    set(value) {
      // Capitalize first letter of each word
      this.setDataValue('lastName', value ? value.trim().replace(/\b\w/g, l => l.toUpperCase()) : value);
    }
  },
  
  dateOfBirth: {
    type: DataTypes.DATEONLY,
    allowNull: true,
    validate: {
      isDate: {
        msg: 'Must be a valid date'
      },
      isBefore: {
        args: new Date().toISOString().split('T')[0],
        msg: 'Date of birth must be in the past'
      },
      isReasonable(value) {
        if (value) {
          const birthYear = new Date(value).getFullYear();
          const currentYear = new Date().getFullYear();
          if (currentYear - birthYear > 150 || currentYear - birthYear < 0) {
            throw new Error('Date of birth must be within a reasonable range');
          }
        }
      }
    }
  },
  
  phone: {
    type: DataTypes.STRING(20),
    allowNull: true,
    validate: {
      is: {
        args: /^[\+]?[1-9][\d]{0,15}$/,
        msg: 'Phone number must be a valid format'
      }
    },
    set(value) {
      // Remove non-numeric characters except +
      this.setDataValue('phone', value ? value.replace(/[^\d\+]/g, '') : value);
    }
  },
  
  // Role-based access control
  role: {
    type: DataTypes.ENUM('patient', 'provider', 'admin', 'staff'),
    allowNull: false,
    defaultValue: 'patient',
    validate: {
      isIn: {
        args: [['patient', 'provider', 'admin', 'staff']],
        msg: 'Role must be patient, provider, admin, or staff'
      }
    }
  },
  
  // Account status and security
  isActive: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: true,
    comment: 'Whether the account is active and can log in'
  },
  
  emailVerified: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether the email address has been verified'
  },
  
  emailVerificationToken: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Token for email verification'
  },
  
  emailVerificationExpires: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the email verification token expires'
  },
  
  // Password reset functionality
  passwordResetToken: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Token for password reset'
  },
  
  passwordResetExpires: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the password reset token expires'
  },
  
  passwordChangedAt: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the password was last changed'
  },
  
  // Security tracking
  lastLogin: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Last successful login timestamp'
  },
  
  lastLoginIp: {
    type: DataTypes.STRING(45), // Supports IPv6
    allowNull: true,
    comment: 'IP address of last login'
  },
  
  lastLoginUserAgent: {
    type: DataTypes.TEXT,
    allowNull: true,
    comment: 'User agent string of last login'
  },
  
  failedLoginAttempts: {
    type: DataTypes.INTEGER,
    allowNull: false,
    defaultValue: 0,
    comment: 'Number of consecutive failed login attempts'
  },
  
  accountLockedUntil: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'When the account lock expires'
  },
  
  // Two-factor authentication
  twoFactorEnabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false,
    comment: 'Whether 2FA is enabled'
  },
  
  twoFactorSecret: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: 'Encrypted 2FA secret key'
  },
  
  twoFactorBackupCodes: {
    type: DataTypes.JSON,
    allowNull: true,
    comment: 'Encrypted backup codes for 2FA'
  },
  
  // Healthcare-specific fields
  medicalRecordNumber: {
    type: DataTypes.STRING(50),
    allowNull: true,
    unique: true,
    comment: 'Unique medical record identifier'
  },
  
  insuranceProvider: {
    type: DataTypes.STRING(100),
    allowNull: true,
    comment: 'Insurance provider name'
  },
  
  insurancePolicyNumber: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Insurance policy number'
  },
  
  emergencyContactName: {
    type: DataTypes.STRING(200),
    allowNull: true,
    comment: 'Emergency contact full name'
  },
  
  emergencyContactPhone: {
    type: DataTypes.STRING(20),
    allowNull: true,
    comment: 'Emergency contact phone number'
  },
  
  emergencyContactRelationship: {
    type: DataTypes.STRING(50),
    allowNull: true,
    comment: 'Relationship to emergency contact'
  },
  
  // Preferences and settings
  preferences: {
    type: DataTypes.JSON,
    allowNull: true,
    defaultValue: {},
    comment: 'User preferences and settings'
  },
  
  // Audit fields
  createdBy: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'ID of user who created this record'
  },
  
  updatedBy: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: 'ID of user who last updated this record'
  }
}, {
  // Model options
  tableName: 'users',
  timestamps: true, // Adds createdAt and updatedAt
  paranoid: true,   // Adds deletedAt for soft deletes
  underscored: true, // Use snake_case for column names
  
  // Indexes for performance
  indexes: [
    {
      unique: true,
      fields: ['email']
    },
    {
      fields: ['role']
    },
    {
      fields: ['is_active']
    },
    {
      fields: ['last_login']
    },
    {
      unique: true,
      fields: ['medical_record_number'],
      where: {
        medical_record_number: {
          [sequelize.Sequelize.Op.ne]: null
        }
      }
    }
  ],
  
  // Model hooks for security and validation
  hooks: {
    beforeCreate: async (user, options) => {
      // Generate medical record number for patients
      if (user.role === 'patient' && !user.medicalRecordNumber) {
        user.medicalRecordNumber = await generateMedicalRecordNumber();
      }
      
      // Set creation audit
      if (options.user) {
        user.createdBy = options.user.id;
      }
    },
    
    beforeUpdate: async (user, options) => {
      // Set update audit
      if (options.user) {
        user.updatedBy = options.user.id;
      }
      
      // Track password changes
      if (user.changed('password')) {
        user.passwordChangedAt = new Date();
        user.failedLoginAttempts = 0;
        user.accountLockedUntil = null;
      }
    },
    
    afterCreate: async (user, options) => {
      // Log user creation
      const logger = require('../utils/logger');
      logger.info('User created', {
        userId: user.id,
        email: user.email,
        role: user.role,
        createdBy: user.createdBy
      });
    }
  },
  
  // Default scope excludes sensitive fields
  defaultScope: {
    attributes: {
      exclude: [
        'password',
        'passwordResetToken',
        'emailVerificationToken',
        'twoFactorSecret',
        'twoFactorBackupCodes'
      ]
    }
  },
  
  // Additional scopes for different use cases
  scopes: {
    // Include all fields (for authentication)
    withPassword: {
      attributes: {}
    },
    
    // Active users only
    active: {
      where: {
        isActive: true,
        deletedAt: null
      }
    },
    
    // Patients only
    patients: {
      where: {
        role: 'patient'
      }
    },
    
    // Providers only
    providers: {
      where: {
        role: ['provider', 'admin']
      }
    },
    
    // Recently active users
    recentlyActive: {
      where: {
        lastLogin: {
          [sequelize.Sequelize.Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
        }
      }
    }
  }
});

/**
 * Instance Methods
 */

// Check if password matches
User.prototype.validatePassword = async function(password) {
  return bcrypt.compare(password, this.password);
};

// Check if account is locked
User.prototype.isAccountLocked = function() {
  return !!(this.accountLockedUntil && this.accountLockedUntil > new Date());
};

// Get full name
User.prototype.getFullName = function() {
  return `${this.firstName} ${this.lastName}`.trim();
};

// Check if user has specific role
User.prototype.hasRole = function(role) {
  if (Array.isArray(role)) {
    return role.includes(this.role);
  }
  return this.role === role;
};

// Check if user is healthcare provider
User.prototype.isProvider = function() {
  return ['provider', 'admin'].includes(this.role);
};

// Get user age
User.prototype.getAge = function() {
  if (!this.dateOfBirth) return null;
  
  const today = new Date();
  const birthDate = new Date(this.dateOfBirth);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  
  return age;
};

// Generate display name for UI
User.prototype.getDisplayName = function() {
  return this.getFullName() || this.email;
};

// Check if email needs verification
User.prototype.needsEmailVerification = function() {
  return !this.emailVerified;
};

// Check if password needs to be changed (e.g., temporary password)
User.prototype.needsPasswordChange = function() {
  // Example: password older than 90 days for admins
  if (this.role === 'admin' && this.passwordChangedAt) {
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);
    return this.passwordChangedAt < ninetyDaysAgo;
  }
  return false;
};

// Get sanitized user data for API responses
User.prototype.toSafeObject = function() {
  const safeFields = [
    'id', 'email', 'firstName', 'lastName', 'role', 
    'dateOfBirth', 'phone', 'isActive', 'emailVerified',
    'lastLogin', 'twoFactorEnabled', 'createdAt', 'updatedAt'
  ];
  
  const safeUser = {};
  safeFields.forEach(field => {
    if (this[field] !== undefined) {
      safeUser[field] = this[field];
    }
  });
  
  // Add computed fields
  safeUser.fullName = this.getFullName();
  safeUser.age = this.getAge();
  safeUser.displayName = this.getDisplayName();
  
  return safeUser;
};

/**
 * Class Methods (Static)
 */

// Find user by email with password
User.findByEmailWithPassword = function(email) {
  return this.scope('withPassword').findOne({
    where: { email: email.toLowerCase().trim() }
  });
};

// Find active users by role
User.findActiveByRole = function(role) {
  return this.scope('active').findAll({
    where: { role }
  });
};

// Search users by name or email
User.searchUsers = function(query, limit = 10) {
  const searchTerm = `%${query.toLowerCase()}%`;
  
  return this.findAll({
    where: {
      [sequelize.Sequelize.Op.or]: [
        sequelize.where(
          sequelize.fn('LOWER', sequelize.col('email')),
          { [sequelize.Sequelize.Op.like]: searchTerm }
        ),
        sequelize.where(
          sequelize.fn('LOWER', sequelize.col('first_name')),
          { [sequelize.Sequelize.Op.like]: searchTerm }
        ),
        sequelize.where(
          sequelize.fn('LOWER', sequelize.col('last_name')),
          { [sequelize.Sequelize.Op.like]: searchTerm }
        )
      ]
    },
    limit,
    order: [['lastName', 'ASC'], ['firstName', 'ASC']]
  });
};

// Get user statistics
User.getStatistics = async function() {
  const totalUsers = await this.count();
  const activeUsers = await this.count({ where: { isActive: true } });
  const patientCount = await this.count({ where: { role: 'patient' } });
  const providerCount = await this.count({ where: { role: 'provider' } });
  const adminCount = await this.count({ where: { role: 'admin' } });
  
  const recentlyActive = await this.count({
    where: {
      lastLogin: {
        [sequelize.Sequelize.Op.gte]: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
      }
    }
  });
  
  return {
    total: totalUsers,
    active: activeUsers,
    inactive: totalUsers - activeUsers,
    byRole: {
      patients: patientCount,
      providers: providerCount,
      admins: adminCount,
      staff: totalUsers - patientCount - providerCount - adminCount
    },
    recentlyActive
  };
};

/**
 * Associations
 * Define relationships with other models
 */
User.associate = function(models) {
  // User has many security logs
  User.hasMany(models.SecurityLog, {
    foreignKey: 'userId',
    as: 'securityLogs'
  });
  
  // Patient-specific associations
  User.hasMany(models.Appointment, {
    foreignKey: 'patientId',
    as: 'appointments',
    scope: { role: 'patient' }
  });
  
  User.hasMany(models.MedicalRecord, {
    foreignKey: 'patientId',
    as: 'medicalRecords',
    scope: { role: 'patient' }
  });
  
  // Provider-specific associations
  User.hasMany(models.Appointment, {
    foreignKey: 'providerId',
    as: 'providerAppointments',
    scope: { role: ['provider', 'admin'] }
  });
  
  // Self-referential for created/updated by
  User.belongsTo(models.User, {
    foreignKey: 'createdBy',
    as: 'creator'
  });
  
  User.belongsTo(models.User, {
    foreignKey: 'updatedBy',
    as: 'updater'
  });
};

/**
 * Utility Functions
 */

// Generate unique medical record number
async function generateMedicalRecordNumber() {
  const prefix = 'MRN';
  const timestamp = Date.now().toString().slice(-6); // Last 6 digits of timestamp
  const random = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
  
  let mrn = `${prefix}${timestamp}${random}`;
  
  // Ensure uniqueness
  let attempts = 0;
  while (attempts < 10) {
    const existing = await User.findOne({
      where: { medicalRecordNumber: mrn }
    });
    
    if (!existing) {
      return mrn;
    }
    
    // Generate new random part if collision
    const newRandom = Math.floor(Math.random() * 1000).toString().padStart(3, '0');
    mrn = `${prefix}${timestamp}${newRandom}`;
    attempts++;
  }
  
  // Fallback with UUID if still collision
  const { v4: uuidv4 } = require('uuid');
  return `${prefix}${uuidv4().replace(/-/g, '').slice(0, 9).toUpperCase()}`;
}

/**
 * Validation helpers
 */
User.validateEmail = function(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

User.validatePassword = function(password) {
  // At least 8 characters, 1 uppercase, 1 lowercase, 1 number, 1 special char
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

User.validatePhone = function(phone) {
  if (!phone) return true; // Optional field
  const phoneRegex = /^[\+]?[1-9][\d]{0,15}$/;
  return phoneRegex.test(phone.replace(/[^\d\+]/g, ''));
};

/**
 * Password hashing middleware
 * Note: This is handled in the controller for better error handling,
 * but kept here as an alternative approach
 */
User.addHook('beforeSave', async (user) => {
  if (user.changed('password')) {
    const saltRounds = 12;
    user.password = await bcrypt.hash(user.password, saltRounds);
  }
});

module.exports = User;