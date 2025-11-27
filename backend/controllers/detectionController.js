// detectionController.js
const axios = require('axios');
require('dotenv').config();

// Optimized axios instances with connection pooling
const mlClient = axios.create({
  baseURL: process.env.ML_MODEL_URL?.replace('/predict', '') || 'http://localhost:5001',
  timeout: 600,
  headers: { 'Content-Type': 'application/json', 'Connection': 'keep-alive' },
  httpAgent: new (require('http').Agent)({ keepAlive: true, maxSockets: 5 })
});

const abuseClient = axios.create({
  baseURL: process.env.ABUSEIPDB_URL?.replace('/check', '') || 'https://api.abuseipdb.com/api/v2',
  timeout: 400,
  headers: { 
    'Key': process.env.ABUSEIPDB_API_KEY,
    'Accept': 'application/json',
    'Connection': 'keep-alive'
  },
  httpsAgent: new (require('https').Agent)({ keepAlive: true, maxSockets: 3 })
});

// IP cache to avoid repeated AbuseIPDB calls
const ipCache = new Map();
const IP_CACHE_TTL = 300000;

const detectDDoS = async (req, res) => {
  const startTime = Date.now();
  try {
    const { traffic, ip, packet_data, network_slice } = req.body;

    // Fast input validation
    if (!Array.isArray(traffic) || !traffic.every(num => typeof num === 'number' && !isNaN(num))) {
      return res.status(400).json({ error: 'Invalid traffic data: must be an array of numbers' });
    }
    if (!ip || !ip.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
      return res.status(400).json({ error: 'Invalid IP address' });
    }

    // PARALLEL PROCESSING: Call both ML model and AbuseIPDB simultaneously
    const [mlResponse, abuseResult] = await Promise.allSettled([
      mlClient.post('/predict', {
        traffic,
        ip_address: ip,
        packet_data: packet_data || {},
        network_slice: network_slice || 'eMBB'
      }),
      (async () => {
        const cached = ipCache.get(ip);
        if (cached && Date.now() - cached.timestamp < IP_CACHE_TTL) {
          return cached.data;
        }
        
        const response = await abuseClient.get('/check', {
          params: { ipAddress: ip, maxAgeInDays: 90 }
        });
        
        const result = {
          score: response.data.data.abuseConfidenceScore || 0,
          status: (response.data.data.abuseConfidenceScore || 0) > 25 ? 'suspicious' : 'clean'
        };
        
        ipCache.set(ip, { data: result, timestamp: Date.now() });
        return result;
      })()
    ]);

    // Process ML response
    let mlData = {};
    if (mlResponse.status === 'fulfilled') {
      mlData = mlResponse.value.data;
    } else {
      mlData = { prediction: 'normal', confidence: 0.5, threat_level: 'LOW' };
    }

    // Process AbuseIPDB response
    let abuseData = {};
    if (abuseResult.status === 'fulfilled') {
      abuseData = abuseResult.value;
    } else {
      abuseData = { score: 0, status: 'clean' };
    }

    // Combine results
    const mlThreat = mlData.prediction === 'ddos';
    const abuseThreat = abuseData.status === 'suspicious';
    const combinedThreat = mlThreat || abuseThreat;
    const combinedConfidence = (mlData.confidence + (abuseData.score / 100)) / 2;

    res.json({
      prediction: combinedThreat ? 'ddos' : 'normal',
      confidence: combinedConfidence,
      ml_prediction: mlData.prediction,
      abuse_score: abuseData.score,
      threat_level: mlData.threat_level,
      network_slice: network_slice || 'eMBB'
    });
  } catch (error) {
    console.error('Detection error:', error);
    res.status(500).json({ error: 'Detection failed' });
  }
};

module.exports = { detectDDoS };