const aiAnalysisService = require('../services/aiAnalysisService');
const { prisma } = require('../config/database');

class AnalysisController {
  // Analyze a single log
  async analyzeLog(req, res, next) {
    try {
      const { log_id } = req.body;

      if (!log_id) {
        return res.status(400).json({
          error: 'log_id is required'
        });
      }

      const result = await aiAnalysisService.analyzeLog(log_id);

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Batch analyze multiple logs
  async batchAnalyze(req, res, next) {
    try {
      const { log_ids } = req.body;

      if (!log_ids || !Array.isArray(log_ids) || log_ids.length === 0) {
        return res.status(400).json({
          error: 'log_ids array is required and must not be empty'
        });
      }

      const result = await aiAnalysisService.batchAnalyze(log_ids);

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Find similar logs
  async findSimilar(req, res, next) {
    try {
      const { log_id } = req.params;
      const { limit = 5 } = req.query;

      const result = await aiAnalysisService.findSimilarLogs(
        parseInt(log_id),
        parseInt(limit)
      );

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Get analysis results for a log
  async getAnalysisResults(req, res, next) {
    try {
      const { log_id } = req.params;

      const results = await prisma.analysisResult.findMany({
        where: { logId: parseInt(log_id) },
        orderBy: { analyzedAt: 'desc' },
        include: {
          securityLog: {
            select: {
              id: true,
              timestamp: true,
              source: true,
              severity: true,
              eventType: true
            }
          }
        }
      });

      res.json({
        success: true,
        data: results
      });
    } catch (error) {
      next(error);
    }
  }

  // Get threat summary
  async getThreatSummary(req, res, next) {
    try {
      const { start_date, end_date } = req.query;

      const where = {};

      if (start_date || end_date) {
        where.analyzedAt = {};
        if (start_date) {
          where.analyzedAt.gte = new Date(start_date);
        }
        if (end_date) {
          where.analyzedAt.lte = new Date(end_date);
        }
      }

      const threatStats = await prisma.analysisResult.groupBy({
        by: ['threatLevel'],
        where,
        _count: {
          id: true
        },
        _avg: {
          confidence: true
        }
      });

      // Sort by threat level priority
      const threatOrder = { 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'NONE': 4 };
      const sortedStats = threatStats
        .filter(s => s.threatLevel)
        .sort((a, b) => {
          return (threatOrder[a.threatLevel] || 999) - (threatOrder[b.threatLevel] || 999);
        });

      res.json({
        success: true,
        data: sortedStats.map(s => ({
          threat_level: s.threatLevel,
          count: s._count.id,
          avg_confidence: s._avg.confidence
        }))
      });
    } catch (error) {
      next(error);
    }
  }

  // Update log embedding
  async updateEmbedding(req, res, next) {
    try {
      const { log_id } = req.body;

      if (!log_id) {
        return res.status(400).json({
          error: 'log_id is required'
        });
      }

      const result = await aiAnalysisService.updateLogEmbedding(log_id);

      res.json({
        success: true,
        message: 'Embedding updated successfully',
        data: result
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new AnalysisController();
