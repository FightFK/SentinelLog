const express = require('express');
const router = express.Router();
const { webhookController } = require('../controllers/webhookController');

// Webhook routes ไม่ใช้ JWT เพราะถูกเรียกโดย Linux Agent
// (Agent ใช้ X-Agent-ID / X-Agent-Key แทน)

// POST /api/webhook/nginx - Receive single nginx log
router.post('/nginx', webhookController.receiveNginxLog);

// POST /api/webhook/nginx/batch - Receive batch of nginx logs
router.post('/nginx/batch', webhookController.receiveBatchLogs);

module.exports = router;
