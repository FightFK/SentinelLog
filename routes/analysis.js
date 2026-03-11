const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');
const { authMiddleware, requireRole } = require('../middleware/auth');

// ทุก endpoint ต้อง login
router.use(authMiddleware);

// POST /api/analysis/analyze - Analyze a single log  (analyst, admin)
router.post('/analyze', requireRole(['admin', 'analyst']), analysisController.analyzeLog);

// POST /api/analysis/batch - Batch analyze multiple logs  (analyst, admin)
router.post('/batch', requireRole(['admin', 'analyst']), analysisController.batchAnalyze);

// GET /api/analysis/similar/:log_id - Find similar logs  (all roles)
router.get('/similar/:log_id', analysisController.findSimilar);

// GET /api/analysis/results/:log_id - Get analysis results for a log  (all roles)
router.get('/results/:log_id', analysisController.getAnalysisResults);

// GET /api/analysis/threats - Get threat summary  (all roles)
router.get('/threats', analysisController.getThreatSummary);

// GET /api/analysis/overview - Full threat analysis page data  (all roles)
// Query params: start_date, end_date, severity (HIGH|MEDIUM|LOW|All)
router.get('/overview', analysisController.getOverview);

// POST /api/analysis/embedding - Update log embedding  (admin only)
router.post('/embedding', requireRole(['admin']), analysisController.updateEmbedding);

module.exports = router;
