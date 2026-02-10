const express = require('express');
const router = express.Router();
const { adminDecisionController } = require('../controllers/webhookController');
const autoProcessingService = require('../services/autoProcessingService');

// GET /api/admin/pending - Get pending decisions
router.get('/pending', adminDecisionController.getPendingDecisions);

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

module.exports = router;
