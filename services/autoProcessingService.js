const { prisma } = require('../config/database');
const aiAnalysisService = require('./aiAnalysisService');
const securityResponseService = require('./securityResponseService');
const logger = require('../middleware/logger');

class AutoProcessingService {
  constructor() {
    this.similarityThreshold = 0.85; // Threshold for considering logs as similar
    this.processingQueue = [];
  }

  // Main auto-processing flow
  async processIncomingLog(logData) {
    try {
      logger.info('Starting auto-processing for incoming log');

      // Step 1: Create log entry
      const log = await prisma.securityLog.create({
        data: {
          source: logData.source || 'nginx',
          severity: this.estimateInitialSeverity(logData),
          eventType: logData.event_type || this.detectEventType(logData),
          description: logData.description || logData.message,
          ipAddress: logData.ip_address || logData.remote_addr,
          userAgent: logData.user_agent,
          rawLog: logData.raw_log || JSON.stringify(logData),
          metadata: logData.metadata || {}
        }
      });

      logger.info(`Log created with ID: ${log.id}`);

      // Step 2: Generate embedding for the log
      const text = `${log.eventType} ${log.description || ''} ${log.rawLog || ''}`;
      const embedding = await aiAnalysisService.generateEmbedding(text);
      
      await prisma.securityLog.update({
        where: { id: log.id },
        data: { embedding: JSON.stringify(embedding) }
      });

      logger.info(`Embedding generated for log ${log.id}`);

      // Step 3: Find similar logs
      const similarLogs = await aiAnalysisService.findSimilarLogs(log.id, 5);

      // Step 4: Check if similar logs exist
      const hasSimilar = similarLogs.length > 0 && similarLogs[0].similarity >= this.similarityThreshold;

      if (hasSimilar) {
        logger.info(`Found similar logs for ${log.id}, applying learned rules`);
        
        // Apply learned rules from similar cases
        return await this.applyLearnedRules(log, similarLogs);
      } else {
        logger.info(`No similar logs found for ${log.id}, analyzing as new threat`);
        
        // New pattern - analyze and wait for admin decision
        return await this.analyzeNewPattern(log);
      }
    } catch (error) {
      logger.error('Error in auto-processing:', error);
      throw error;
    }
  }

  // Apply learned rules from similar logs
  async applyLearnedRules(log, similarLogs) {
    try {
      // Get the most similar log
      const mostSimilar = similarLogs[0];
      
      // Find admin decisions for similar logs
      const learnedRules = await prisma.adminDecision.findMany({
        where: {
          logId: mostSimilar.id,
          applied: true
        },
        orderBy: { decidedAt: 'desc' },
        take: 1
      });

      if (learnedRules.length > 0) {
        const rule = learnedRules[0];
        
        logger.info(`Applying learned rule: ${rule.action} for log ${log.id}`);

        // Execute the learned action automatically
        const response = await this.executeLearnedAction(log, rule);

        // Record that we applied a learned rule
        await prisma.autoAppliedRule.create({
          data: {
            logId: log.id,
            sourceDecisionId: rule.id,
            similarity: mostSimilar.similarity,
            actionTaken: rule.action,
            executedAt: new Date()
          }
        });

        return {
          status: 'auto_processed',
          log_id: log.id,
          action: rule.action,
          similarity: mostSimilar.similarity,
          learned_from: mostSimilar.id,
          response: response
        };
      } else {
        // Similar logs exist but no admin decision yet
        return await this.analyzeNewPattern(log);
      }
    } catch (error) {
      logger.error('Error applying learned rules:', error);
      throw error;
    }
  }

  // Analyze new pattern and wait for admin decision
  async analyzeNewPattern(log) {
    try {
      // Run AI analysis
      const analysis = await aiAnalysisService.analyzeLog(log.id);

      const threatLevel = analysis.analysis.threat_level;
      const isHighRisk = threatLevel === 'HIGH' || threatLevel === 'MEDIUM';

      if (isHighRisk) {
        logger.warn(`High risk detected for log ${log.id}, creating admin alert`);

        // Create admin alert and wait for decision
        const alert = await prisma.pendingAdminDecision.create({
          data: {
            logId: log.id,
            analysisId: analysis.analysis_record.id,
            threatLevel: threatLevel,
            analysis: analysis.analysis,
            status: 'pending',
            createdAt: new Date()
          }
        });

        // Send notification to admin (webhook, email, etc.)
        await this.notifyAdmin(alert, log, analysis);

        return {
          status: 'pending_admin_decision',
          log_id: log.id,
          alert_id: alert.id,
          threat_level: threatLevel,
          analysis: analysis.analysis,
          message: 'High risk detected. Waiting for admin decision.'
        };
      } else {
        // Low risk - just log it
        logger.info(`Low risk log ${log.id}, no action needed`);

        return {
          status: 'logged_only',
          log_id: log.id,
          threat_level: threatLevel,
          analysis: analysis.analysis,
          message: 'Low risk - logged for monitoring'
        };
      }
    } catch (error) {
      logger.error('Error analyzing new pattern:', error);
      throw error;
    }
  }

  // Execute action based on learned rule
  async executeLearnedAction(log, rule) {
    try {
      switch (rule.action) {
        case 'block':
          if (log.ipAddress) {
            return await securityResponseService.blockIP(
              log.ipAddress,
              rule.duration || 3600
            );
          }
          break;

        case 'monitor':
          return await securityResponseService.increaseMonitoring(log);

        case 'alert':
          return await securityResponseService.alertAdmin(log, {
            threatLevel: rule.threatLevel,
            result: rule.analysisData
          });

        case 'ignore':
          return {
            action: 'ignore',
            status: 'success',
            message: 'Log ignored based on learned rule'
          };

        default:
          logger.warn(`Unknown action: ${rule.action}`);
          return null;
      }
    } catch (error) {
      logger.error('Error executing learned action:', error);
      throw error;
    }
  }

  // Notify admin about pending decision
  async notifyAdmin(alert, log, analysis) {
    try {
      // In production, send real notifications:
      // - Email
      // - Slack/Teams webhook
      // - Push notification
      // - SMS for critical threats

      logger.info(`ADMIN NOTIFICATION: New threat requires decision - Alert ID: ${alert.id}`);
      
      // Create admin notification record
      await prisma.adminNotification.create({
        data: {
          alertId: alert.id,
          logId: log.id,
          type: 'pending_decision',
          title: `New ${analysis.analysis.threat_level} Threat Detected`,
          message: `${log.eventType} from ${log.ipAddress}: ${log.description}`,
          notificationData: {
            log: log,
            analysis: analysis.analysis,
            alert_id: alert.id
          },
          sentAt: new Date()
        }
      });

      return true;
    } catch (error) {
      logger.error('Error notifying admin:', error);
      return false;
    }
  }

  // Estimate initial severity from log data
  estimateInitialSeverity(logData) {
    // Check HTTP status codes
    if (logData.status >= 500) return 'HIGH';
    if (logData.status >= 400 && logData.status < 500) return 'MEDIUM';
    
    // Check for suspicious patterns in URL/request
    const suspiciousPatterns = [
      /\.\.\//,  // Directory traversal
      /union.*select/i,  // SQL injection
      /<script>/i,  // XSS
      /exec|eval|system/i,  // Command injection
    ];

    const request = logData.request || logData.raw_log || '';
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(request)) {
        return 'HIGH';
      }
    }

    return 'LOW';
  }

  // Detect event type from log data
  detectEventType(logData) {
    const request = (logData.request || logData.raw_log || '').toLowerCase();
    const status = logData.status;

    if (status === 401 || status === 403) return 'unauthorized_access';
    if (status === 404) return 'not_found';
    if (status >= 500) return 'server_error';
    if (request.includes('sql') || request.includes('union')) return 'sql_injection';
    if (request.includes('<script>') || request.includes('javascript:')) return 'xss_attempt';
    if (request.includes('../') || request.includes('..\\')) return 'directory_traversal';

    return 'general_request';
  }

  // Get pending decisions for admin dashboard
  async getPendingDecisions(limit = 50) {
    try {
      const pending = await prisma.pendingAdminDecision.findMany({
        where: { status: 'pending' },
        include: {
          log: true
        },
        orderBy: { createdAt: 'desc' },
        take: limit
      });

      return pending;
    } catch (error) {
      logger.error('Error getting pending decisions:', error);
      throw error;
    }
  }
}

module.exports = new AutoProcessingService();
