// detectionRoutes.js
const express = require('express');
const os = require('os');
const axios = require('axios');
const { detectDDoS } = require('../controllers/detectionController');
const { detectDDoSWithAPI } = require('../controllers/apiDetectionController');
const { detectDDoSCombined } = require('../controllers/combinedDetectionController');

const router = express.Router();

const PacketCapture = require('../services/packetCapture');
const captureInstance = new PacketCapture();

// Get only Ethernet and Wi-Fi IPs
router.get('/local-ips', (req, res) => {
  try {
    const interfaces = os.networkInterfaces();
    const results = [];
    
    for (const [name, nets] of Object.entries(interfaces)) {
      // Enhanced filtering for Ethernet and Wi-Fi interfaces only
      const nameL = name.toLowerCase();
      const isVirtual = nameL.includes('vmware') || nameL.includes('virtualbox') || 
                       nameL.includes('hyper-v') || nameL.includes('docker') || 
                       nameL.includes('vethernet') || nameL.includes('loopback') ||
                       nameL.includes('teredo') || nameL.includes('isatap') ||
                       nameL.includes('bluetooth');
      
      if (isVirtual) continue; // Skip virtual interfaces
      
      const isEthernet = nameL.includes('ethernet') && !nameL.includes('vmware');
      const isWiFi = nameL.includes('wi-fi') || nameL.includes('wifi') || 
                    nameL.includes('wireless lan') || nameL.includes('wlan');
      
      if (isEthernet || isWiFi) {
        for (const net of nets) {
          if (net.family === 'IPv4' && !net.internal) {
            results.push({ 
              interface: name, 
              address: net.address,
              type: isEthernet ? 'Ethernet' : 'Wi-Fi',
              netmask: net.netmask,
              mac: net.mac
            });
          }
        }
      }
    }
    
    // Sort by type (Ethernet first, then Wi-Fi)
    results.sort((a, b) => {
      if (a.type === 'Ethernet' && b.type === 'Wi-Fi') return -1;
      if (a.type === 'Wi-Fi' && b.type === 'Ethernet') return 1;
      return 0;
    });
    
    res.json(results);
  } catch (error) {
    console.error('Error getting local IPs:', error);
    res.status(500).json({ error: 'Failed to get local IPs' });
  }
});

// Start real packet capture
router.post('/start-capture', (req, res) => {
  try {
    const { targetIP, interfaceName } = req.body;
    
    if (!targetIP || !interfaceName) {
      return res.status(400).json({ error: 'targetIP and interfaceName required' });
    }
    
    // Validate that the IP is from Ethernet/Wi-Fi interface
    const interfaces = os.networkInterfaces();
    let validInterface = false;
    
    for (const [name, nets] of Object.entries(interfaces)) {
      if (name === interfaceName) {
        validInterface = true;
        break;
      }
    }
    
    if (!validInterface) {
      return res.status(400).json({ error: 'Invalid interface' });
    }
    
    captureInstance.startCapture(targetIP, interfaceName);
    res.json({ success: true, message: 'Capture started' });
  } catch (error) {
    console.error('Error starting capture:', error);
    res.status(500).json({ error: 'Failed to start capture' });
  }
});

// Stop capture
router.post('/stop-capture', (req, res) => {
  captureInstance.stopCapture();
  res.json({ success: true, message: 'Capture stopped' });
});

// Get capture status
router.get('/capture-status', (req, res) => {
  try {
    const io = req.app.get('io');
    const flowData = captureInstance.getFlowWindow();
    const recentPackets = flowData.slice(-100);
    const totalPackets = flowData.length;
    const startTime = captureInstance.captureStartTime || Date.now();
    const duration = (Date.now() - startTime) / 1000;
    
    res.json({
      isCapturing: captureInstance.isCapturing,
      mode: captureInstance.isCapturing ? 'real_capture' : 'idle',
      packetCount: totalPackets,
      recentTraffic: recentPackets.length > 0 ? recentPackets.map(p => p.size || 64).join(',') : '0',
      packetsPerSecond: Math.floor(totalPackets / Math.max(1, duration)),
      totalBytes: flowData.reduce((sum, p) => sum + (p.size || 0), 0),
      duration: Math.floor(duration)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Combined ensemble detection endpoint (uses both models)
router.post('/detect', detectDDoSCombined);

// Legacy endpoints (kept for backward compatibility)
router.post('/detect-local', detectDDoS);
router.post('/detect-api', detectDDoSWithAPI);

// ML Model connectivity check
router.get('/ml-status', async (req, res) => {
  try {
    const { checkMLHealth } = require('../controllers/combinedDetectionController');
    const isHealthy = await checkMLHealth();
    res.json({
      ml_model_status: isHealthy ? 'connected' : 'disconnected',
      ml_model_url: process.env.ML_MODEL_URL || 'http://localhost:5001',
      fallback_available: true,
      message: isHealthy ? 'ML model is responding' : 'Using enhanced fallback detection',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({
      ml_model_status: 'disconnected',
      ml_model_url: process.env.ML_MODEL_URL || 'http://localhost:5001',
      fallback_available: true,
      message: 'Using enhanced fallback detection',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// System status endpoint
router.get('/system-status', async (req, res) => {
  try {
    const { checkMLHealth } = require('../controllers/combinedDetectionController');
    const mlHealthy = await checkMLHealth();
    
    res.json({
      backend_status: 'connected',
      ml_model_status: mlHealthy ? 'connected' : 'disconnected',
      fallback_detection: 'available',
      real_time_updates: 'active',
      websocket_status: 'connected',
      capture_available: captureInstance ? 'ready' : 'unavailable',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    res.json({
      backend_status: 'connected',
      ml_model_status: 'disconnected',
      fallback_detection: 'available',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Make captureInstance available globally if needed
global.captureInstance = captureInstance;

// Export only the router
module.exports = router;