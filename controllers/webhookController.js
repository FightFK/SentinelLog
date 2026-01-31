const autoProcessingService = require('../services/autoProcessingService');
const { prisma } = require('../config/database');

class WebhookController {
  // Receive nginx logs via webhook
  async receiveNginxLog(req, res, next) {
    try {
      const logData = req.body;

      // Validate required fields
      if (!logData) {
        return res.status(400).json({
          error: 'Log data is required'
        });
      }

      // Process the log automatically
      const result = await autoProcessingService.processIncomingLog(logData);

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Receive batch of nginx logs
  async receiveBatchLogs(req, res, next) {
    try {
      const { logs } = req.body;

      if (!logs || !Array.isArray(logs)) {
        return res.status(400).json({
          error: 'logs array is required'
        });
      }

      const results = [];
      const errors = [];

      for (const logData of logs) {
        try {
          const result = await autoProcessingService.processIncomingLog(logData);
          results.push(result);
        } catch (error) {
          errors.push({
            log: logData,
            error: error.message
          });
        }
      }

      res.json({
        success: true,
        data: {
          processed: results.length,
          failed: errors.length,
          results: results,
          errors: errors
        }
      });
    } catch (error) {
      next(error);
    }
  }
}

class AdminDecisionController {
  // Get pending decisions
  async getPendingDecisions(req, res, next) {
    try {
      const { limit = 50 } = req.query;

      const pending = await autoProcessingService.getPendingDecisions(parseInt(limit));

      res.json({
        success: true,
        data: pending
      });
    } catch (error) {
      next(error);
    }
  }

  // Admin makes a decision
  async makeDecision(req, res, next) {
    try {
      const { alert_id } = req.params;
      const { action, reason, duration } = req.body;

      if (!action) {
        return res.status(400).json({
          error: 'action is required (block, monitor, alert, ignore)'
        });
      }

      // Get the pending alert
      const alert = await prisma.pendingAdminDecision.findUnique({
        where: { id: parseInt(alert_id) },
        include: { log: true }
      });

      if (!alert) {
        return res.status(404).json({
          error: 'Alert not found'
        });
      }

      if (alert.status !== 'pending') {
        return res.status(400).json({
          error: 'Alert has already been processed'
        });
      }

      // Record admin decision
      const decision = await prisma.adminDecision.create({
        data: {
          logId: alert.logId,
          pendingId: alert.id,
          action: action,
          reason: reason || null,
          duration: duration || 3600,
          threatLevel: alert.threatLevel,
          analysisData: alert.analysis,
          applied: true,
          decidedAt: new Date()
        }
      });

      // Execute the action
      let executionResult = null;
      
      switch (action) {
        case 'block':
          if (alert.log.ipAddress) {
            const blockDuration = duration || 3600;
            const expiresAt = new Date(Date.now() + blockDuration * 1000);
            await prisma.blockedIP.upsert({
              where: { ipAddress: alert.log.ipAddress },
              update: {
                expiresAt,
                reason: reason || `Blocked by admin: ${alert.threatLevel}`,
                active: true,
                blockedAt: new Date()
              },
              create: {
                ipAddress: alert.log.ipAddress,
                expiresAt,
                reason: reason || `Blocked by admin: ${alert.threatLevel}`,
                active: true
              }
            });
            executionResult = {
              action: 'block',
              status: 'success',
              ip: alert.log.ipAddress,
              duration: blockDuration,
              expiresAt
            };
          }
          break;

        case 'monitor':
          executionResult = {
            action: 'monitor',
            status: 'success',
            message: 'Monitoring flag set for this log pattern'
          };
          break;

        case 'alert':
          executionResult = {
            action: 'alert',
            status: 'success',
            message: 'Alert notification sent to admin'
          };
          break;

        case 'ignore':
          executionResult = {
            action: 'ignore',
            status: 'success',
            message: 'Marked as safe/false positive'
          };
          break;
      }

      // Update alert status
      await prisma.pendingAdminDecision.update({
        where: { id: parseInt(alert_id) },
        data: {
          status: 'resolved',
          resolvedAt: new Date()
        }
      });

      res.json({
        success: true,
        data: {
          decision: decision,
          execution: executionResult,
          message: `Action '${action}' executed successfully. System will learn from this decision.`
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // Get decision history
  async getDecisionHistory(req, res, next) {
    try {
      const { limit = 100 } = req.query;

      const history = await prisma.adminDecision.findMany({
        orderBy: { decidedAt: 'desc' },
        take: parseInt(limit)
      });

      res.json({
        success: true,
        data: history
      });
    } catch (error) {
      next(error);
    }
  }

  // Get learned rules statistics
  async getLearnedRulesStats(req, res, next) {
    try {
      // Count auto-applied rules
      const autoApplied = await prisma.autoAppliedRule.groupBy({
        by: ['actionTaken'],
        _count: {
          id: true
        }
      });

      // Get recent auto-applied rules
      const recentRules = await prisma.autoAppliedRule.findMany({
        include: {
          log: true
        },
        orderBy: { executedAt: 'desc' },
        take: 20
      });

      res.json({
        success: true,
        data: {
          statistics: autoApplied.map(stat => ({
            action: stat.actionTaken,
            count: stat._count.id
          })),
          recent_applications: recentRules
        }
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = {
  webhookController: new WebhookController(),
  adminDecisionController: new AdminDecisionController()
};
