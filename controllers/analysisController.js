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

  // GET /api/analysis/overview — all data for Threat Analysis page
  async getOverview(req, res, next) {
    try {
      const { start_date, end_date, severity } = req.query;

      // Build WHERE clause for analysis_results (joined with security_logs)
      const dateFilter = {};
      if (start_date || end_date) {
        dateFilter.analyzedAt = {};
        if (start_date) dateFilter.analyzedAt.gte = new Date(start_date);
        if (end_date)   dateFilter.analyzedAt.lte = new Date(end_date);
      }

      // Optional severity filter maps to threatLevel
      const severityFilter = severity && severity !== 'All'
        ? { threatLevel: severity.toUpperCase() }
        : {};

      const where = { ...dateFilter, ...severityFilter, threatLevel: { not: null } };

      // 1. Threat counts by level
      const threatsByLevel = await prisma.analysisResult.groupBy({
        by: ['threatLevel'],
        where,
        _count: { id: true }
      });

      const levelMap = { HIGH: 0, MEDIUM: 0, LOW: 0, NONE: 0 };
      for (const t of threatsByLevel) {
        if (t.threatLevel in levelMap) levelMap[t.threatLevel] = t._count.id;
      }
      const totalThreats = levelMap.HIGH + levelMap.MEDIUM + levelMap.LOW;

      // 2. Top threat types from metadata->detected_attacks JSONB array
      //    Use date filter on security_logs.timestamp
      const dateSQL = start_date || end_date
        ? `AND sl.timestamp BETWEEN ${ start_date ? `'${new Date(start_date).toISOString()}'` : "'1970-01-01'" } AND ${ end_date ? `'${new Date(end_date).toISOString()}'` : "NOW()" }`
        : '';
      const severitySQL = severity && severity !== 'All'
        ? `AND ar.threat_level = '${severity.toUpperCase().replace(/'/g, "''")}' `
        : '';

      const topThreatTypes = await prisma.$queryRawUnsafe(`
        SELECT attack_type, COUNT(*)::int AS count
        FROM security_logs sl
        JOIN analysis_results ar ON ar.log_id = sl.id
        CROSS JOIN LATERAL jsonb_array_elements_text(
          COALESCE(sl.metadata->'detected_attacks', '[]'::jsonb)
        ) AS attack_type
        WHERE attack_type != 'normal_traffic'
          AND ar.threat_level IS NOT NULL
          ${dateSQL}
          ${severitySQL}
        GROUP BY attack_type
        ORDER BY count DESC
        LIMIT 10
      `);

      // 3. Top attacker IPs
      const topAttackerIPs = await prisma.$queryRawUnsafe(`
        SELECT sl.ip_address AS ip,
               COUNT(DISTINCT ar.id)::int AS threat_count,
               MAX(ar.threat_level) AS top_threat_level
        FROM security_logs sl
        JOIN analysis_results ar ON ar.log_id = sl.id
        WHERE ar.threat_level IN ('HIGH', 'MEDIUM')
          AND sl.ip_address IS NOT NULL
          ${dateSQL}
        GROUP BY sl.ip_address
        ORDER BY threat_count DESC
        LIMIT 10
      `);

      // 4. Severity distribution with percentages
      const total = totalThreats || 1; // avoid div by zero
      const severityDistribution = ['HIGH', 'MEDIUM', 'LOW'].map(level => ({
        level,
        count: levelMap[level],
        percent: parseFloat(((levelMap[level] / total) * 100).toFixed(1))
      }));

      res.json({
        success: true,
        data: {
          summary: {
            total_threats: totalThreats,
            high: levelMap.HIGH,
            medium: levelMap.MEDIUM,
            low: levelMap.LOW
          },
          severity_distribution: severityDistribution,
          top_threat_types: topThreatTypes,
          top_attacker_ips: topAttackerIPs
        }
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
