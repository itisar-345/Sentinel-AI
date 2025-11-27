// ipDetectionRoutes.js
const express = require('express');
const { detectAndMitigate, blockIP } = require('../controllers/ipDetectionController');

const router = express.Router();

// Middleware to extract client IP
const getClientIp = (req, res, next) => {
  // Get IP from X-Forwarded-For header if behind a proxy
  const forwarded = req.headers['x-forwarded-for'];
  req.ipAddress = forwarded ? forwarded.split(',')[0].trim() : req.connection.remoteAddress;
  next();
};

// IP-based detection endpoint
router.post('/detect-ip', getClientIp, detectAndMitigate);

// Manual IP blocking endpoint (for admin use)
router.post('/block-ip', async (req, res) => {
  try {
    const { ip, reason } = req.body;
    
    if (!ip) {
      return res.status(400).json({ success: false, error: 'IP address is required' });
    }

    await blockIP(ip, reason || 'Manually blocked by administrator');
    
    res.json({
      success: true,
      message: `IP ${ip} has been blocked`,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Error blocking IP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to block IP',
      message: error.message
    });
  }
});

// Get blocked IPs
router.get('/blocked-ips', (req, res) => {
  try {
    const { _ipBehavior } = require('../controllers/ipDetectionController');
    const blockedIPs = [];
    
    for (const [ip, data] of _ipBehavior.entries()) {
      if (data.isBlocked) {
        blockedIPs.push({
          ip,
          blockedAt: data.blockedAt,
          reason: data.blockReason,
          lastSeen: data.lastSeen
        });
      }
    }
    
    res.json({
      success: true,
      count: blockedIPs.length,
      blockedIPs
    });
  } catch (error) {
    console.error('Error getting blocked IPs:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to get blocked IPs',
      message: error.message
    });
  }
});

// Unblock IP
router.post('/unblock-ip', async (req, res) => {
  try {
    const { ip } = req.body;
    
    if (!ip) {
      return res.status(400).json({ success: false, error: 'IP address is required' });
    }

    const { _ipBehavior } = require('../controllers/ipDetectionController');
    const behavior = _ipBehavior.get(ip);
    
    if (behavior) {
      behavior.isBlocked = false;
      behavior.blockedAt = null;
      behavior.blockReason = null;
      behavior.suspiciousCount = 0; // Reset suspicious count
      
      // TODO: Implement actual unblocking in your network infrastructure
      
      res.json({
        success: true,
        message: `IP ${ip} has been unblocked`,
        timestamp: new Date().toISOString()
      });
    } else {
      res.status(404).json({
        success: false,
        error: 'IP not found in blocked list'
      });
    }
  } catch (error) {
    console.error('Error unblocking IP:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to unblock IP',
      message: error.message
    });
  }
});

module.exports = router;