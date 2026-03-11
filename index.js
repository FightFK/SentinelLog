require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const winston = require('winston');

// Import routes
const logsRoutes = require('./routes/logs');
const analysisRoutes = require('./routes/analysis');
const webhookRoutes = require('./routes/webhook');
const adminRoutes = require('./routes/admin');
const agentRoutes = require('./routes/agent');
const agentCommandService = require('./services/agentCommandService');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  ]
});

// Middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'SentinelLog API'
  });
});

// API routes
app.use('/api/logs', logsRoutes);
app.use('/api/analysis', analysisRoutes);
app.use('/api/webhook', webhookRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/agent', agentRoutes); // Agent endpoints (used by Linux agents)

// Error handling middleware
app.use((err, req, res, next) => {
  logger.error(err.stack);
  res.status(err.status || 500).json({
    error: {
      message: err.message || 'Internal Server Error',
      status: err.status || 500
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: {
      message: 'Route not found',
      status: 404
    }
  });
});

// Start server
app.listen(PORT, () => {
  logger.info(`SentinelLog server running on port ${PORT}`);
  logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);

  // Mark agents that haven't sent heartbeat in >10 minutes as disconnected
  // Run every 2 minutes
  setInterval(() => {
    agentCommandService.markStaleAgents(10).catch(err =>
      logger.error('Stale agent check error:', err.message)
    );
  }, 2 * 60 * 1000);
});

module.exports = app;
