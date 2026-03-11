const express = require('express');
const router = express.Router();
const logController = require('../controllers/logController');
const { authMiddleware, requireRole } = require('../middleware/auth');

// ทุก endpoint ต้อง login
router.use(authMiddleware);

// POST /api/logs - Create a new security log  (analyst, admin)
router.post('/', requireRole(['admin', 'analyst']), logController.createLog);

// GET /api/logs - Get all logs with filtering  (all roles)
router.get('/', logController.getLogs);

// GET /api/logs/stats - Get log statistics  (all roles)
router.get('/stats', logController.getStats);

// GET /api/logs/:id - Get a specific log by ID  (all roles)
router.get('/:id', logController.getLogById);

// DELETE /api/logs/:id - Delete a log  (admin only)
router.delete('/:id', requireRole(['admin']), logController.deleteLog);

module.exports = router;
