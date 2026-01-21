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
