const express = require('express');
const router = express.Router();
const analysisController = require('../controllers/analysisController');

// POST /api/analysis/analyze - Analyze a single log
router.post('/analyze', analysisController.analyzeLog);

// POST /api/analysis/batch - Batch analyze multiple logs
router.post('/batch', analysisController.batchAnalyze);

// GET /api/analysis/similar/:log_id - Find similar logs
router.get('/similar/:log_id', analysisController.findSimilar);

// GET /api/analysis/results/:log_id - Get analysis results for a log
router.get('/results/:log_id', analysisController.getAnalysisResults);

// GET /api/analysis/threats - Get threat summary
router.get('/threats', analysisController.getThreatSummary);

// POST /api/analysis/embedding - Update log embedding
router.post('/embedding', analysisController.updateEmbedding);

module.exports = router;
