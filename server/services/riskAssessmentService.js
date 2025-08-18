/**
 * Risk Assessment Service
 * 
 * Implements comprehensive security risk assessment algorithms for healthcare applications.
 * Analyzes login patterns, geolocation, device fingerprinting, and behavioral analytics
 * to provide real-time risk scoring and threat detection.
 * 
 * Based on banking security practices adapted for healthcare environments.
 * 
 * @author Your Name
 * @version 1.0.0
 */

const geoip = require('geoip-lite');
const useragent = require('useragent');
const SecurityLog = require('../models/SecurityLog');
const User = require('../models/User');
const logger = require('../utils/logger');
const { Op } = require('sequelize');

/**
 * Risk scoring thresholds and weights
 */
const RISK_CONFIG = {
  // Base risk score for any login attempt
  BASE_SCORE: 10,
  
  // Risk thresholds
  THRESHOLDS: {
    LOW: 30,
    MEDIUM: 60,
    HIGH: 80
  },
  
  // Risk factor weights
  WEIGHTS: {
    NEW_LOCATION: 40,        // New geographic location
    NEW_DEVICE: 30,          // New device/browser
    UNUSUAL_TIME: 10,        // Login outside normal hours
    FAILED_ATTEMPTS: 25,     // Recent failed login attempts
    VELOCITY: 20,            // Multiple rapid login attempts
    TOR_PROXY: 50,          // Using anonymization tools
    SUSPICIOUS_PATTERN: 35   // Behavioral anomalies
  },
  
  // Time windows for analysis (in minutes)
  TIME_WINDOWS: {
    RECENT_ACTIVITY: 60,     // Last hour
    FAILED_ATTEMPTS: 180,    // Last 3 hours
    VELOCITY_CHECK: 5,       // Last 5 minutes
    HISTORICAL_PATTERN: 10080 // Last week
  }
};

/**
 * Main risk assessment function
 * Evaluates multiple risk factors and returns comprehensive risk analysis
 * 
 * @param {Object} loginData - Login attempt data
 * @param {string} loginData.userId - User ID
 * @param {string} loginData.ipAddress - Client IP address
 * @param {string} loginData.userAgent - User agent string
 * @param {Date} loginData.timestamp - Login timestamp
 * @returns {Object} Risk assessment result
 */
const assessLoginRisk = async (loginData) => {
  try {
    const { userId, ipAddress, userAgent, timestamp } = loginData;
    
    logger.debug('Starting risk assessment', { userId, ipAddress });
    
    // Initialize risk factors
    const riskFactors = {
      location: await assessLocationRisk(userId, ipAddress),
      device: await assessDeviceRisk(userId, userAgent),
      timing: await assessTimingRisk(userId, timestamp),
      velocity: await assessVelocityRisk(userId, ipAddress, timestamp),
      behavioral: await assessBehavioralRisk(userId, timestamp),
      reputation: await assessReputationRisk(ipAddress)
    };
    
    // Calculate total risk score
    const riskScore = calculateRiskScore(riskFactors);
    
    // Determine risk level
    const riskLevel = determineRiskLevel(riskScore);
    
    // Generate recommendations
    const recommendations = generateRecommendations(riskFactors, riskLevel);
    
    // Log risk assessment
    await logRiskAssessment({
      userId,
      ipAddress,
      userAgent,
      riskScore,
      riskLevel,
      riskFactors,
      timestamp
    });
    
    const result = {
      riskScore,
      riskLevel,
      factors: riskFactors,
      recommendations,
      timestamp: new Date(),
      requiresAdditionalVerification: riskLevel === 'HIGH'
    };
    
    logger.info('Risk assessment completed', {
      userId,
      riskScore,
      riskLevel,
      requiresAdditionalVerification: result.requiresAdditionalVerification
    });
    
    return result;
    
  } catch (error) {
    logger.error('Risk assessment failed:', error);
    
    // Return high risk on assessment failure for security
    return {
      riskScore: 100,
      riskLevel: 'HIGH',
      factors: { error: 'Assessment failed' },
      recommendations: ['Contact security team'],
      timestamp: new Date(),
      requiresAdditionalVerification: true
    };
  }
};

/**
 * Assess location-based risk factors
 * Analyzes IP geolocation against user's historical login patterns
 */
const assessLocationRisk = async (userId, ipAddress) => {
  try {
    // Get geolocation data
    const geoData = geoip.lookup(ipAddress);
    
    if (!geoData) {
      return {
        score: RISK_CONFIG.WEIGHTS.NEW_LOCATION * 0.5,
        details: 'Unable to determine location',
        isNewLocation: true
      };
    }
    
    // Check historical locations
    const recentLogins = await SecurityLog.findAll({
      where: {
        userId,
        eventType: 'USER_LOGIN',
        createdAt: {
          [Op.gte]: new Date(Date.now() - RISK_CONFIG.TIME_WINDOWS.HISTORICAL_PATTERN * 60000)
        }
      },
      attributes: ['details'],
      limit: 50
    });
    
    // Extract previous locations
    const previousLocations = recentLogins
      .map(log => log.details?.location)
      .filter(Boolean);
    
    // Check if this is a new location
    const currentLocation = `${geoData.country}-${geoData.region}-${geoData.city}`;
    const isNewLocation = !previousLocations.some(loc => 
      loc.country === geoData.country && 
      loc.region === geoData.region
    );
    
    // Calculate distance from usual locations
    let minDistance = Infinity;
    if (previousLocations.length > 0) {
      previousLocations.forEach(prevLoc => {
        if (prevLoc.ll && geoData.ll) {
          const distance = calculateDistance(
            prevLoc.ll[0], prevLoc.ll[1],
            geoData.ll[0], geoData.ll[1]
          );
          minDistance = Math.min(minDistance, distance);
        }
      });
    }
    
    // Score based on location novelty and distance
    let score = 0;
    if (isNewLocation) {
      score += RISK_CONFIG.WEIGHTS.NEW_LOCATION;
    }
    
    // Additional risk for very distant locations
    if (minDistance > 1000) { // More than 1000km away
      score += 10;
    }
    
    return {
      score,
      details: {
        country: geoData.country,
        region: geoData.region,
        city: geoData.city,
        isNewLocation,
        distanceFromUsual: minDistance === Infinity ? null : Math.round(minDistance),
        coordinates: geoData.ll
      }
    };
    
  } catch (error) {
    logger.error('Location risk assessment failed:', error);
    return {
      score: RISK_CONFIG.WEIGHTS.NEW_LOCATION,
      details: 'Location assessment failed',
      isNewLocation: true
    };
  }
};

/**
 * Assess device-based risk factors
 * Analyzes user agent and device fingerprinting
 */
const assessDeviceRisk = async (userId, userAgent) => {
  try {
    const agent = useragent.parse(userAgent);
    const deviceFingerprint = generateDeviceFingerprint(userAgent);
    
    // Check historical devices
    const recentLogins = await SecurityLog.findAll({
      where: {
        userId,
        eventType: 'USER_LOGIN',
        createdAt: {
          [Op.gte]: new Date(Date.now() - RISK_CONFIG.TIME_WINDOWS.HISTORICAL_PATTERN * 60000)
        }
      },
      attributes: ['userAgent'],
      limit: 20
    });
    
    const previousDevices = recentLogins
      .map(log => generateDeviceFingerprint(log.userAgent))
      .filter(Boolean);
    
    const isNewDevice = !previousDevices.includes(deviceFingerprint);
    
    let score = 0;
    if (isNewDevice) {
      score += RISK_CONFIG.WEIGHTS.NEW_DEVICE;
    }
    
    // Additional risk factors
    if (agent.os.toString().includes('Unknown')) {
      score += 5; // Unknown OS
    }
    
    if (userAgent.toLowerCase().includes('bot') || 
        userAgent.toLowerCase().includes('crawler')) {
      score += 15; // Automated tools
    }
    
    return {
      score,
      details: {
        browser: agent.toAgent(),
        os: agent.os.toString(),
        device: agent.device.toString(),
        isNewDevice,
        fingerprint: deviceFingerprint
      }
    };
    
  } catch (error) {
    logger.error('Device risk assessment failed:', error);
    return {
      score: RISK_CONFIG.WEIGHTS.NEW_DEVICE,
      details: 'Device assessment failed',
      isNewDevice: true
    };
  }
};

/**
 * Assess timing-based risk factors
 * Analyzes login timing patterns
 */
const assessTimingRisk = async (userId, timestamp) => {
  try {
    const hour = timestamp.getHours();
    const dayOfWeek = timestamp.getDay();
    
    // Get user's historical login patterns
    const historicalLogins = await SecurityLog.findAll({
      where: {
        userId,
        eventType: 'USER_LOGIN',
        createdAt: {
          [Op.gte]: new Date(Date.now() - RISK_CONFIG.TIME_WINDOWS.HISTORICAL_PATTERN * 60000)
        }
      },
      attributes: ['createdAt'],
      limit: 100
    });
    
    // Analyze typical login hours
    const loginHours = historicalLogins.map(log => log.createdAt.getHours());
    const hourCounts = loginHours.reduce((acc, h) => {
      acc[h] = (acc[h] || 0) + 1;
      return acc;
    }, {});
    
    // Calculate if current hour is unusual
    const totalLogins = loginHours.length;
    const currentHourFrequency = (hourCounts[hour] || 0) / Math.max(totalLogins, 1);
    
    let score = 0;
    
    // Risk for unusual hours (very early morning)
    if (hour >= 2 && hour <= 5) {
      score += RISK_CONFIG.WEIGHTS.UNUSUAL_TIME;
    }
    
    // Risk for hours user rarely logs in
    if (totalLogins > 10 && currentHourFrequency < 0.05) {
      score += RISK_CONFIG.WEIGHTS.UNUSUAL_TIME * 0.5;
    }
    
    return {
      score,
      details: {
        loginHour: hour,
        dayOfWeek,
        isUnusualHour: hour >= 2 && hour <= 5,
        historicalFrequency: currentHourFrequency,
        totalHistoricalLogins: totalLogins
      }
    };
    
  } catch (error) {
    logger.error('Timing risk assessment failed:', error);
    return {
      score: 0,
      details: 'Timing assessment failed'
    };
  }
};

/**
 * Assess velocity-based risk factors
 * Analyzes rapid login attempts and patterns
 */
const assessVelocityRisk = async (userId, ipAddress, timestamp) => {
  try {
    const recentWindow = new Date(timestamp.getTime() - RISK_CONFIG.TIME_WINDOWS.VELOCITY_CHECK * 60000);
    
    // Check recent login attempts from same IP
    const recentAttempts = await SecurityLog.count({
      where: {
        [Op.or]: [
          { userId },
          { ipAddress }
        ],
        eventType: {
          [Op.in]: ['USER_LOGIN', 'LOGIN_FAILED_INVALID_PASSWORD', 'LOGIN_FAILED_USER_NOT_FOUND']
        },
        createdAt: {
          [Op.gte]: recentWindow
        }
      }
    });
    
    // Check failed attempts specifically
    const failedAttempts = await SecurityLog.count({
      where: {
        [Op.or]: [
          { userId },
          { ipAddress }
        ],
        eventType: {
          [Op.in]: ['LOGIN_FAILED_INVALID_PASSWORD', 'LOGIN_FAILED_USER_NOT_FOUND']
        },
        createdAt: {
          [Op.gte]: new Date(timestamp.getTime() - RISK_CONFIG.TIME_WINDOWS.FAILED_ATTEMPTS * 60000)
        }
      }
    });
    
    let score = 0;
    
    // Risk for multiple rapid attempts
    if (recentAttempts > 3) {
      score += RISK_CONFIG.WEIGHTS.VELOCITY;
    }
    
    // Risk for recent failed attempts
    if (failedAttempts > 0) {
      score += RISK_CONFIG.WEIGHTS.FAILED_ATTEMPTS * Math.min(failedAttempts / 5, 1);
    }
    
    return {
      score,
      details: {
        recentAttempts,
        failedAttempts,
        timeWindow: RISK_CONFIG.TIME_WINDOWS.VELOCITY_CHECK
      }
    };
    
  } catch (error) {
    logger.error('Velocity risk assessment failed:', error);
    return {
      score: 0,
      details: 'Velocity assessment failed'
    };
  }
};

/**
 * Assess behavioral risk factors
 * Analyzes user behavior patterns and anomalies
 */
const assessBehavioralRisk = async (userId, timestamp) => {
  try {
    // Get user's recent activity patterns
    const recentActivity = await SecurityLog.findAll({
      where: {
        userId,
        createdAt: {
          [Op.gte]: new Date(timestamp.getTime() - RISK_CONFIG.TIME_WINDOWS.HISTORICAL_PATTERN * 60000)
        }
      },
      attributes: ['eventType', 'createdAt', 'details'],
      order: [['createdAt', 'DESC']],
      limit: 50
    });
    
    let score = 0;
    const behaviorFactors = [];
    
    // Check for rapid successive logins from different locations
    const loginEvents = recentActivity.filter(log => log.eventType === 'USER_LOGIN');
    if (loginEvents.length >= 2) {
      const locations = loginEvents
        .map(log => log.details?.location)
        .filter(Boolean)
        .slice(0, 5);
      
      // Check for impossible travel (logins from distant locations in short time)
      for (let i = 0; i < locations.length - 1; i++) {
        const loc1 = locations[i];
        const loc2 = locations[i + 1];
        const time1 = new Date(loginEvents[i].createdAt);
        const time2 = new Date(loginEvents[i + 1].createdAt);
        
        if (loc1.ll && loc2.ll) {
          const distance = calculateDistance(loc1.ll[0], loc1.ll[1], loc2.ll[0], loc2.ll[1]);
          const timeDiff = Math.abs(time1 - time2) / (1000 * 60 * 60); // hours
          const maxSpeed = distance / Math.max(timeDiff, 0.1); // km/h
          
          // Impossible travel speed (>1000 km/h)
          if (maxSpeed > 1000) {
            score += RISK_CONFIG.WEIGHTS.SUSPICIOUS_PATTERN;
            behaviorFactors.push(`Impossible travel: ${Math.round(distance)}km in ${timeDiff.toFixed(1)}h`);
            break;
          }
        }
      }
    }
    
    // Check for unusual activity patterns
    const activityTypes = recentActivity.map(log => log.eventType);
    const uniqueActivities = [...new Set(activityTypes)];
    
    // Risk for very diverse activity in short time
    if (uniqueActivities.length > 10) {
      score += 5;
      behaviorFactors.push('High activity diversity');
    }
    
    return {
      score,
      details: {
        recentActivityCount: recentActivity.length,
        uniqueActivityTypes: uniqueActivities.length,
        behaviorFactors,
        suspiciousPatterns: behaviorFactors.length > 0
      }
    };
    
  } catch (error) {
    logger.error('Behavioral risk assessment failed:', error);
    return {
      score: 0,
      details: 'Behavioral assessment failed'
    };
  }
};

/**
 * Assess IP reputation risk factors
 * Checks IP against known threat databases and patterns
 */
const assessReputationRisk = async (ipAddress) => {
  try {
    let score = 0;
    const reputationFactors = [];
    
    // Check for private/local IPs (lower risk)
    if (isPrivateIP(ipAddress)) {
      score -= 5;
      reputationFactors.push('Private IP address');
    }
    
    // Check for Tor exit nodes (simplified check)
    if (await isTorExitNode(ipAddress)) {
      score += RISK_CONFIG.WEIGHTS.TOR_PROXY;
      reputationFactors.push('Tor exit node detected');
    }
    
    // Check for VPN/Proxy indicators (simplified)
    const geoData = geoip.lookup(ipAddress);
    if (geoData && geoData.org) {
      const org = geoData.org.toLowerCase();
      if (org.includes('vpn') || org.includes('proxy') || org.includes('hosting')) {
        score += 15;
        reputationFactors.push('VPN/Proxy/Hosting provider');
      }
    }
    
    // Check recent malicious activity from this IP
    const recentMaliciousActivity = await SecurityLog.count({
      where: {
        ipAddress,
        eventType: {
          [Op.in]: [
            'LOGIN_FAILED_INVALID_PASSWORD',
            'HIGH_RISK_LOGIN_DETECTED',
            'SUSPICIOUS_ACTIVITY'
          ]
        },
        createdAt: {
          [Op.gte]: new Date(Date.now() - 24 * 60 * 60 * 1000) // Last 24 hours
        }
      }
    });
    
    if (recentMaliciousActivity > 5) {
      score += 20;
      reputationFactors.push(`${recentMaliciousActivity} recent suspicious activities`);
    }
    
    return {
      score,
      details: {
        reputationFactors,
        organization: geoData?.org || 'Unknown',
        isp: geoData?.org || 'Unknown',
        recentMaliciousActivity
      }
    };
    
  } catch (error) {
    logger.error('Reputation risk assessment failed:', error);
    return {
      score: 10, // Moderate risk on assessment failure
      details: 'Reputation assessment failed'
    };
  }
};

/**
 * Calculate total risk score from individual factors
 */
const calculateRiskScore = (riskFactors) => {
  const totalScore = RISK_CONFIG.BASE_SCORE +
    (riskFactors.location?.score || 0) +
    (riskFactors.device?.score || 0) +
    (riskFactors.timing?.score || 0) +
    (riskFactors.velocity?.score || 0) +
    (riskFactors.behavioral?.score || 0) +
    (riskFactors.reputation?.score || 0);
  
  // Cap at 100
  return Math.min(totalScore, 100);
};

/**
 * Determine risk level based on score
 */
const determineRiskLevel = (riskScore) => {
  if (riskScore >= RISK_CONFIG.THRESHOLDS.HIGH) {
    return 'HIGH';
  } else if (riskScore >= RISK_CONFIG.THRESHOLDS.MEDIUM) {
    return 'MEDIUM';
  } else {
    return 'LOW';
  }
};

/**
 * Generate security recommendations based on risk factors
 */
const generateRecommendations = (riskFactors, riskLevel) => {
  const recommendations = [];
  
  if (riskLevel === 'HIGH') {
    recommendations.push('Require additional authentication');
    recommendations.push('Notify security team');
    recommendations.push('Monitor user activity closely');
  }
  
  if (riskFactors.location?.details?.isNewLocation) {
    recommendations.push('Verify new location with user');
    recommendations.push('Send location alert notification');
  }
  
  if (riskFactors.device?.details?.isNewDevice) {
    recommendations.push('Verify new device with user');
    recommendations.push('Send device registration email');
  }
  
  if (riskFactors.velocity?.details?.failedAttempts > 0) {
    recommendations.push('Monitor for brute force attacks');
    recommendations.push('Consider temporary account restrictions');
  }
  
  if (riskFactors.reputation?.details?.reputationFactors?.some(f => f.includes('Tor'))) {
    recommendations.push('Review anonymization tool usage policy');
    recommendations.push('Require enhanced verification');
  }
  
  return recommendations;
};

/**
 * Log risk assessment results
 */
const logRiskAssessment = async (assessmentData) => {
  try {
    await SecurityLog.create({
      userId: assessmentData.userId,
      eventType: 'RISK_ASSESSMENT',
      details: {
        riskScore: assessmentData.riskScore,
        riskLevel: assessmentData.riskLevel,
        factors: assessmentData.riskFactors,
        ip: assessmentData.ipAddress,
        userAgent: assessmentData.userAgent
      },
      ipAddress: assessmentData.ipAddress,
      userAgent: assessmentData.userAgent,
      severity: assessmentData.riskLevel.toLowerCase()
    });
  } catch (error) {
    logger.error('Failed to log risk assessment:', error);
  }
};

/**
 * Utility Functions
 */

/**
 * Generate device fingerprint from user agent
 */
const generateDeviceFingerprint = (userAgent) => {
  if (!userAgent) return null;
  
  const agent = useragent.parse(userAgent);
  return `${agent.family}-${agent.major}-${agent.os.family}-${agent.os.major}`;
};

/**
 * Calculate distance between two coordinates (Haversine formula)
 */
const calculateDistance = (lat1, lon1, lat2, lon2) => {
  const R = 6371; // Earth's radius in kilometers
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
};

const toRad = (deg) => deg * (Math.PI / 180);

/**
 * Check if IP is private/local
 */
const isPrivateIP = (ip) => {
  const privateRanges = [
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^127\./,
    /^::1$/,
    /^fe80:/
  ];
  
  return privateRanges.some(range => range.test(ip));
};

/**
 * Simple Tor exit node check (in production, use a real database)
 */
const isTorExitNode = async (ipAddress) => {
  // In production, you would check against Tor exit node lists
  // For demo purposes, we'll do a simple check
  try {
    // This is a simplified check - in production use proper Tor databases
    const suspiciousIPs = ['127.0.0.1']; // Demo list
    return suspiciousIPs.includes(ipAddress);
  } catch (error) {
    logger.error('Tor check failed:', error);
    return false;
  }
};

/**
 * Get risk assessment history for a user
 */
const getRiskHistory = async (userId, limit = 10) => {
  try {
    const history = await SecurityLog.findAll({
      where: {
        userId,
        eventType: 'RISK_ASSESSMENT'
      },
      order: [['createdAt', 'DESC']],
      limit,
      attributes: ['createdAt', 'details', 'ipAddress']
    });
    
    return history.map(entry => ({
      timestamp: entry.createdAt,
      riskScore: entry.details.riskScore,
      riskLevel: entry.details.riskLevel,
      ipAddress: entry.ipAddress,
      factors: entry.details.factors
    }));
    
  } catch (error) {
    logger.error('Failed to get risk history:', error);
    return [];
  }
};

/**
 * Get current risk statistics
 */
const getRiskStatistics = async () => {
  try {
    const last24Hours = new Date(Date.now() - 24 * 60 * 60 * 1000);
    
    const stats = await SecurityLog.findAll({
      where: {
        eventType: 'RISK_ASSESSMENT',
        createdAt: {
          [Op.gte]: last24Hours
        }
      },
      attributes: ['details']
    });
    
    const riskLevels = stats.map(s => s.details.riskLevel);
    const riskScores = stats.map(s => s.details.riskScore);
    
    return {
      totalAssessments: stats.length,
      averageRiskScore: riskScores.reduce((a, b) => a + b, 0) / riskScores.length || 0,
      riskDistribution: {
        LOW: riskLevels.filter(r => r === 'LOW').length,
        MEDIUM: riskLevels.filter(r => r === 'MEDIUM').length,
        HIGH: riskLevels.filter(r => r === 'HIGH').length
      },
      timeWindow: '24 hours'
    };
    
  } catch (error) {
    logger.error('Failed to get risk statistics:', error);
    return null;
  }
};

module.exports = {
  assessLoginRisk,
  getRiskHistory,
  getRiskStatistics,
  RISK_CONFIG
};