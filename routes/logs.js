const express = require('express');
const router = express.Router();
const logController = require('../controllers/logController');

// POST /api/logs - Create a new security log
router.post('/', logController.createLog);

// GET /api/logs - Get all logs with filtering
router.get('/', logController.getLogs);

// GET /api/logs/stats - Get log statistics
router.get('/stats', logController.getStats);

// GET /api/logs/:id - Get a specific log by ID
router.get('/:id', logController.getLogById);

// DELETE /api/logs/:id - Delete a log
router.delete('/:id', logController.deleteLog);

module.exports = router;
