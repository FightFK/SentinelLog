const express = require('express');
const router = express.Router();
const { agentController } = require('../controllers/agentController');
const agentCommandService = require('../services/agentCommandService');
const logger = require('../middleware/logger');

/**
 * ==================== AGENT AUTH MIDDLEWARE ====================
 * ตรวจสอบ X-Agent-ID + X-Agent-Key headers
 * หลัง verify แล้วจะ attach req.agent = agent record
 */
const agentAuthMiddleware = async (req, res, next) => {
  const agentId = req.headers['x-agent-id'];
  const apiKey = req.headers['x-agent-key'];

  if (!agentId || !apiKey) {
    return res.status(401).json({
      error: 'Missing agent credentials. Required headers: X-Agent-ID, X-Agent-Key'
    });
  }

  try {
    const agent = await agentCommandService.authenticateAgent(agentId, apiKey);
    if (!agent) {
      logger.warn(`🚫 Agent auth failed: ${agentId}`);
      return res.status(401).json({ error: 'Invalid agent credentials' });
    }
    req.agent = agent;
    next();
  } catch (err) {
    next(err);
  }
};

// ==================== PUBLIC (ไม่ต้อง auth) ====================

// POST /api/agent/register — Agent ลงทะเบียนครั้งแรก (ป้องกันด้วย register secret แทน)
router.post('/register', agentController.register.bind(agentController));

// ==================== PROTECTED (ต้อง agent auth) ====================

// POST /api/agent/heartbeat
router.post('/heartbeat', agentAuthMiddleware, agentController.heartbeat.bind(agentController));

// GET /api/agent/commands — poll pending commands
router.get('/commands', agentAuthMiddleware, agentController.pollCommands.bind(agentController));

// POST /api/agent/commands/:command_id/result — รายงานผล
router.post(
  '/commands/:command_id/result',
  agentAuthMiddleware,
  agentController.reportResult.bind(agentController)
);

module.exports = router;
