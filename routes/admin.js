const express = require('express');
const router = express.Router();
const { adminDecisionController } = require('../controllers/webhookController');
const autoProcessingService = require('../services/autoProcessingService');
const { adminAgentController } = require('../controllers/agentController');
const agentCommandService = require('../services/agentCommandService');
const { authMiddleware, requireRole } = require('../middleware/auth');

// ทุก endpoint ใน /api/admin ต้อง login + เป็น admin
router.use(authMiddleware);
router.use(requireRole(['admin']));

// GET /api/admin/pending - Get pending decisions
router.get('/pending', adminDecisionController.getPendingDecisions);

// GET /api/admin/pending/:alert_id - Get a single pending alert by ID
router.get('/pending/:alert_id', adminDecisionController.getPendingById.bind(adminDecisionController));

// POST /api/admin/decide/:alert_id - Make a decision on pending alert
router.post('/decide/:alert_id', adminDecisionController.makeDecision);

// DELETE /api/admin/pending/:alert_id - Delete/dismiss pending decision
router.delete('/pending/:alert_id', adminDecisionController.deletePendingDecision);

// GET /api/admin/decisions - Get decision history
router.get('/decisions', adminDecisionController.getDecisionHistory);

// GET /api/admin/learned-rules - Get learned rules statistics
router.get('/learned-rules', adminDecisionController.getLearnedRulesStats);

// POST /api/admin/regenerate-embeddings - Regenerate failed embeddings
router.post('/regenerate-embeddings', async (req, res, next) => {
  try {
    const { limit = 100 } = req.body;
    const result = await autoProcessingService.regenerateFailedEmbeddings(limit);
    res.json({
      success: true,
      data: result
    });
  } catch (error) {
    next(error);
  }
});

// ==================== Agent Management ====================

// GET /api/admin/agents - List all agents
router.get('/agents', adminAgentController.listAgents.bind(adminAgentController));

// POST /api/admin/agents/:agent_db_id/command - Send command to specific agent
// Use agent_db_id = 'broadcast' to send to ALL active agents
router.post(
  '/agents/:agent_db_id/command',
  adminAgentController.sendCommand.bind(adminAgentController)
);

// GET /api/admin/agents/:agent_db_id/commands - Command history for an agent
router.get(
  '/agents/:agent_db_id/commands',
  adminAgentController.getCommandHistory.bind(adminAgentController)
);

// POST /api/admin/agents/stale-check - Manually trigger stale agent check
router.post('/agents/stale-check', async (req, res, next) => {
  try {
    const { threshold_minutes = 10 } = req.body;
    const count = await agentCommandService.markStaleAgents(parseInt(threshold_minutes));
    res.json({ success: true, data: { marked_disconnected: count } });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
