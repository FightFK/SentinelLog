const { prisma } = require('../config/database');

class LogController {
  // Create a new security log entry
  async createLog(req, res, next) {
    try {
      const {
        source,
        severity,
        event_type,
        description,
        ip_address,
        user_agent,
        raw_log,
        metadata
      } = req.body;

      if (!source || !severity || !event_type) {
        return res.status(400).json({
          error: 'Missing required fields: source, severity, event_type'
        });
      }

      const log = await prisma.securityLog.create({
        data: {
          source,
          severity,
          eventType: event_type,
          description: description || null,
          ipAddress: ip_address || null,
          userAgent: user_agent || null,
          rawLog: raw_log || null,
          metadata: metadata || null
        }
      });

      res.status(201).json({
        success: true,
        data: log
      });
    } catch (error) {
      next(error);
    }
  }

  // Get all logs with filtering and pagination
  async getLogs(req, res, next) {
    try {
      const {
        severity,
        event_type,
        source,
        start_date,
        end_date,
        limit = 50,
        offset = 0
      } = req.query;

      const where = {};

      if (severity) {
        where.severity = severity;
      }

      if (event_type) {
        where.eventType = event_type;
      }

      if (source) {
        where.source = source;
      }

      if (start_date || end_date) {
        where.timestamp = {};
        if (start_date) {
          where.timestamp.gte = new Date(start_date);
        }
        if (end_date) {
          where.timestamp.lte = new Date(end_date);
        }
      }

      const [logs, total] = await Promise.all([
        prisma.securityLog.findMany({
          where,
          orderBy: { timestamp: 'desc' },
          take: parseInt(limit),
          skip: parseInt(offset)
        }),
        prisma.securityLog.count({ where })
      ]);

      res.json({
        success: true,
        data: logs,
        pagination: {
          total,
          limit: parseInt(limit),
          offset: parseInt(offset)
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // Get a specific log by ID
  async getLogById(req, res, next) {
    try {
      const { id } = req.params;

      const log = await prisma.securityLog.findUnique({
        where: { id: parseInt(id) },
        include: {
          analysisResults: {
            orderBy: { analyzedAt: 'desc' }
          }
        }
      });

      if (!log) {
        return res.status(404).json({
          error: 'Log not found'
        });
      }

      res.json({
        success: true,
        data: log
      });
    } catch (error) {
      next(error);
    }
  }

  // Get log statistics
  async getStats(req, res, next) {
    try {
      const { start_date, end_date } = req.query;

      const where = {};

      if (start_date || end_date) {
        where.timestamp = {};
        if (start_date) {
          where.timestamp.gte = new Date(start_date);
        }
        if (end_date) {
          where.timestamp.lte = new Date(end_date);
        }
      }

      // Count by severity
      const severityStats = await prisma.securityLog.groupBy({
        by: ['severity'],
        where,
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        }
      });

      // Count by event type
      const eventTypeStats = await prisma.securityLog.groupBy({
        by: ['eventType'],
        where,
        _count: {
          id: true
        },
        orderBy: {
          _count: {
            id: 'desc'
          }
        },
        take: 10
      });

      // Total logs
      const total = await prisma.securityLog.count({ where });

      res.json({
        success: true,
        data: {
          total,
          by_severity: severityStats.map(s => ({
            severity: s.severity,
            count: s._count.id
          })),
          by_event_type: eventTypeStats.map(e => ({
            event_type: e.eventType,
            count: e._count.id
          }))
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // GET /api/logs/dashboard — unified dashboard summary
  async getDashboard(req, res, next) {
    try {
      const [
        totalLogs,
        threatAnalysesCount,
        pendingAlertsCount,
        threatsByLevel,
        requestsByMethod,
        responseStatusCodes,
        topSourceIPs,
        topAttackerIPs
      ] = await Promise.all([
        // 1. Total logs
        prisma.securityLog.count(),

        // 2. Logs that have at least one analysis result
        prisma.securityLog.count({
          where: { analysisResults: { some: {} } }
        }),

        // 3. Pending admin decisions
        prisma.pendingAdminDecision.count({
          where: { status: 'pending' }
        }),

        // 4. Threats by level from analysis results
        prisma.analysisResult.groupBy({
          by: ['threatLevel'],
          where: { threatLevel: { not: null } },
          _count: { id: true },
          orderBy: { _count: { id: 'desc' } }
        }),

        // 5. Requests by HTTP method (stored in metadata JSONB)
        prisma.$queryRaw`
          SELECT metadata->>'request_method' AS method,
                 COUNT(*)::int AS count
          FROM security_logs
          WHERE metadata->>'request_method' IS NOT NULL
          GROUP BY method
          ORDER BY count DESC
        `,

        // 6. Response status codes (stored in metadata JSONB)
        prisma.$queryRaw`
          SELECT metadata->>'status_code' AS status_code,
                 COUNT(*)::int AS count
          FROM security_logs
          WHERE metadata->>'status_code' IS NOT NULL
          GROUP BY status_code
          ORDER BY count DESC
          LIMIT 10
        `,

        // 7. Top source IPs (all traffic)
        prisma.$queryRaw`
          SELECT ip_address AS ip,
                 COUNT(*)::int AS count
          FROM security_logs
          WHERE ip_address IS NOT NULL
          GROUP BY ip_address
          ORDER BY count DESC
          LIMIT 10
        `,

        // 8. Top attacker IPs (IPs linked to HIGH/MEDIUM threat analysis)
        prisma.$queryRaw`
          SELECT sl.ip_address AS ip,
                 COUNT(DISTINCT ar.id)::int AS threat_count,
                 MAX(ar.threat_level) AS top_threat_level
          FROM security_logs sl
          JOIN analysis_results ar ON ar.log_id = sl.id
          WHERE ar.threat_level IN ('HIGH', 'MEDIUM')
            AND sl.ip_address IS NOT NULL
          GROUP BY sl.ip_address
          ORDER BY threat_count DESC
          LIMIT 10
        `
      ]);

      // Calculate threats detected count (any HIGH or MEDIUM threat analysis)
      const threatsDetected = threatsByLevel
        .filter(t => ['HIGH', 'MEDIUM'].includes(t.threatLevel))
        .reduce((sum, t) => sum + t._count.id, 0);

      res.json({
        success: true,
        data: {
          summary: {
            total_logs: totalLogs,
            threats_detected: {
              count: threatsDetected,
              percent: totalLogs > 0
                ? parseFloat(((threatsDetected / totalLogs) * 100).toFixed(1))
                : 0
            },
            threat_analyses: threatAnalysesCount,
            pending_alerts: pendingAlertsCount
          },
          requests_by_method: requestsByMethod,
          threats_by_severity: threatsByLevel.map(t => ({
            threat_level: t.threatLevel,
            count: t._count.id
          })),
          response_status_codes: responseStatusCodes,
          top_source_ips: topSourceIPs,
          top_attacker_ips: topAttackerIPs
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // Delete a log
  async deleteLog(req, res, next) {
    try {
      const { id } = req.params;

      const log = await prisma.securityLog.delete({
        where: { id: parseInt(id) }
      });

      res.json({
        success: true,
        message: 'Log deleted successfully',
        data: log
      });
    } catch (error) {
      if (error.code === 'P2025') {
        return res.status(404).json({
          error: 'Log not found'
        });
      }
      next(error);
    }
  }
}

module.exports = new LogController();
