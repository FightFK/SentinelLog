const express = require('express');
const router = express.Router();
const { adminDecisionController } = require('../controllers/webhookController');

// GET /api/admin/pending - Get pending decisions
router.get('/pending', adminDecisionController.getPendingDecisions);

// POST /api/admin/decide/:alert_id - Make a decision on pending alert
router.post('/decide/:alert_id', adminDecisionController.makeDecision);

// GET /api/admin/decisions - Get decision history
router.get('/decisions', adminDecisionController.getDecisionHistory);

// GET /api/admin/learned-rules - Get learned rules statistics
router.get('/learned-rules', adminDecisionController.getLearnedRulesStats);

module.exports = router;
