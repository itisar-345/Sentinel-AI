// mlService.js
const axios = require('axios');
const { createLogger, format, transports } = require('winston');

// Configure logger
const logger = createLogger({
  level: 'debug',
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.printf(({ level, message, timestamp, ...meta }) => {
          return `${timestamp} [${level}]: ${message} ${Object.keys(meta).length ? JSON.stringify(meta, null, 2) : ''}`;
        })
      )
    })
  ]
});

// Configure ML client with better timeouts and retry logic
const mlClient = axios.create({
  baseURL: process.env.ML_MODEL_URL || 'http://localhost:5001',
  timeout: 5000, // 5 second timeout for initial connection
  headers: {
    'Connection': 'keep-alive',
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  httpAgent: new (require('http').Agent)({
    keepAlive: true,
    maxSockets: 20,
    maxFreeSockets: 10,
    timeout: 10000, // 10 second timeout for keep-alive
    keepAliveMsecs: 60000 // 1 minute keep-alive
  })
});

// Cache for health status to avoid repeated checks
// Cache configuration
let healthCache = { 
  status: null, 
  timestamp: 0, 
  lastError: null 
};

const HEALTH_CACHE_TTL = 10000; // 10 seconds cache TTL
const MAX_RETRIES = 2;
const RETRY_DELAY = 1000; // 1 second between retries

/**
 * Check if the ML model service is healthy
 * Implements retry logic and proper error handling
 */
const checkMLModelHealth = async (retryCount = 0) => {
  const healthEndpoint = '/health';
  const url = `${mlClient.defaults.baseURL}${healthEndpoint}`;
  
  try {
    // Use cached result if recent and was successful
    if (healthCache.status && healthCache.timestamp > Date.now() - HEALTH_CACHE_TTL) {
      return healthCache.status;
    }

    logger.info(`Checking ML Model health at ${url}`);
    
    const response = await mlClient.get(healthEndpoint, {
      timeout: 3000, // 3 second timeout for health check
      validateStatus: status => status < 500 // Consider any status < 500 as success for retry purposes
    });
    
    const isHealthy = response.status === 200;
    
    if (isHealthy) {
      logger.info(`ML Model health check successful: ${response.status} ${response.statusText}`);
      healthCache = { 
        status: true, 
        timestamp: Date.now(),
        lastError: null
      };
      return true;
    } else {
      const error = new Error(`Health check failed with status ${response.status}`);
      error.statusCode = response.status;
      throw error;
    }
  } catch (error) {
    // Retry logic
    if (retryCount < MAX_RETRIES) {
      await new Promise(resolve => setTimeout(resolve, RETRY_DELAY * (retryCount + 1)));
      return checkMLModelHealth(retryCount + 1);
    }
    
    logger.error(`ML Model health check failed after ${MAX_RETRIES + 1} attempts: ${error.message}`, {
      url,
      code: error.code,
      status: error.statusCode,
      stack: error.stack
    });
    
    healthCache = { 
      status: false, 
      timestamp: Date.now(),
      lastError: error.message
    };
    
    return false;
  }
};

/**
 * Predict traffic using the ML model
 * @param {Object} traffic - The traffic data to predict on
 * @param {Object} options - Additional options
 * @param {number} [options.timeout=5000] - Request timeout in ms
 * @param {number} [options.retries=1] - Number of retry attempts
 * @returns {Promise<Object>} - Prediction results
 */
const predictTraffic = async (traffic, options = {}) => {
  const {
    timeout = 5000, // 5 second default timeout
    retries = 1
  } = options;
  
  const requestId = `pred-${Date.now()}-${Math.floor(Math.random() * 1000)}`;
  const url = `${mlClient.defaults.baseURL}/predict`;
  
  const makeRequest = async (attempt = 0) => {
    try {
      logger.debug('Sending prediction request', { 
        requestId,
        url,
        attempt: attempt + 1,
        timeout
      });
      
      const response = await mlClient.post('/predict', { 
        traffic,
        timestamp: new Date().toISOString(),
        requestId
      }, {
        timeout,
        headers: {
          'X-Request-ID': requestId,
          'X-Attempt': attempt + 1
        }
      });
      
      if (response.status !== 200) {
        const error = new Error(`Unexpected status code: ${response.status}`);
        error.statusCode = response.status;
        error.response = response;
        throw error;
      }
      
      logger.debug('Prediction successful', { 
        requestId,
        status: response.status,
        data: response.data ? 'data received' : 'no data'
      });
      
      return response.data;
      
    } catch (error) {
      error.requestId = requestId;
      error.attempt = attempt;
      
      // Log the error with context
      const logContext = {
        requestId,
        url,
        attempt: attempt + 1,
        error: error.message,
        code: error.code,
        status: error.response?.status,
        statusText: error.response?.statusText,
        responseData: error.response?.data
      };
      
      if (attempt < retries) {
        logger.warn(`Prediction attempt ${attempt + 1} failed, retrying...`, logContext);
        return makeRequest(attempt + 1);
      }
      
      logger.error('Prediction failed after all retries', logContext);
      
      // Enhance the error with more context
      error.message = `Prediction failed after ${retries + 1} attempts: ${error.message}`;
      error.isRetryError = attempt > 0;
      throw error;
    }
  };
  
  return makeRequest();
};

module.exports = { predictTraffic, checkMLModelHealth };