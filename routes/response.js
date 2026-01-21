const express = require('express');
const router = express.Router();
const responseController = require('../controllers/responseController');

// POST /api/response/execute - Execute automated response for a log
router.post('/execute', responseController.executeResponse);

// POST /api/response/analyze-and-respond - Analyze log and execute response
router.post('/analyze-and-respond', responseController.analyzeAndRespond);

// POST /api/response/block-ip - Manually block an IP
router.post('/block-ip', responseController.blockIP);

// POST /api/response/unblock-ip - Unblock an IP
router.post('/unblock-ip', responseController.unblockIP);

// GET /api/response/blocked-ips - Get all blocked IPs
router.get('/blocked-ips', responseController.getBlockedIPs);

// GET /api/response/incidents - Get security incidents
router.get('/incidents', responseController.getIncidents);

// PUT /api/response/incidents/:incident_id/close - Close an incident
router.put('/incidents/:incident_id/close', responseController.closeIncident);

// GET /api/response/history/:log_id - Get response history for a log
router.get('/history/:log_id', responseController.getResponseHistory);

module.exports = router;
