const { prisma } = require('../config/database');
const aiAnalysisService = require('./aiAnalysisService');
const logParserService = require('./logParserService');
const logger = require('../middleware/logger');

/**
 * ==================== AUTO PROCESSING SERVICE ====================
 * Simple Flow:
 * 1. Parse raw log → Save → Generate embedding
 * 2. Search similar logs in Vector DB
 * 3. Found similar? → Auto-apply previous action
 * 4. Not found? → LLM analysis → Admin decision
 */
class AutoProcessingService {
  constructor() {
    this.similarityThreshold = 0.85;
    this.ipAttempts = new Map();
    this.bruteForceThreshold = 5;
    this.bruteForceWindow = 300000;
  }

  /**
   * Main processing flow
   */
  async processIncomingLog(logData) {
    try {
      logger.info('🔄 Processing incoming log...');

      // 1. Parse & Save
      const enrichedLog = this.parseAndEnrichLog(logData);
      const log = await this.saveLog(enrichedLog);

      // 2. Generate Embedding
      await this.generateEmbedding(log);

      // 3. Search Similar
      const similarLogs = await aiAnalysisService.findSimilarLogs(log.id, 5);
      const hasSimilar = similarLogs.length > 0 && similarLogs[0].similarity >= this.similarityThreshold;

      // 4. Decision
      if (hasSimilar) {
        return await this.autoApplyPreviousAction(log, similarLogs[0]);
      } else {
        return await this.requestAdminDecision(log);
      }
    } catch (error) {
      logger.error('❌ Error:', error);
      throw error;
    }
  }

  /**
   * Parse and enrich log data
   */
  parseAndEnrichLog(logData) {
    if (logData.raw_log && !logData.event_type) {
      logger.info('📝 Parsing raw log...');
      const enriched = logParserService.processRawLog(logData.raw_log, logData);
      this.detectBruteForce(enriched);
      return enriched;
    }

    const enriched = {
      source: logData.source || 'nginx',
      severity: logData.severity || this.estimateInitialSeverity(logData),
      eventType: logData.event_type || logData.eventType || 'unknown',
      description: logData.description,
      ipAddress: logData.ip_address || logData.ipAddress,
      userAgent: logData.user_agent || logData.userAgent,
      rawLog: logData.raw_log || logData.rawLog || JSON.stringify(logData),
      metadata: logData.metadata || {},
      timestamp: logData.timestamp ? new Date(logData.timestamp) : new Date()
    };

    this.detectBruteForce(enriched);
    return enriched;
  }

  /**
   * Save log to database
   */
  async saveLog(enrichedLog) {
    const log = await prisma.securityLog.create({
      data: {
        source: enrichedLog.source,
        severity: enrichedLog.severity,
        eventType: enrichedLog.eventType,
        description: enrichedLog.description,
        ipAddress: enrichedLog.ipAddress,
        userAgent: enrichedLog.userAgent,
        rawLog: enrichedLog.rawLog,
        metadata: enrichedLog.metadata,
        timestamp: enrichedLog.timestamp
      }
    });
    logger.info(`✅ Log saved (ID: ${log.id})`);
    return log;
  }

  /**
   * Generate embedding for vector search
   */
  async generateEmbedding(log) {
    logger.info('🔮 Generating embedding...');
    const text = `${log.eventType} ${log.description || ''} ${log.rawLog || ''}`;
    const embedding = await aiAnalysisService.generateEmbedding(text);
    
    await prisma.securityLog.update({
      where: { id: log.id },
      data: { embedding: JSON.stringify(embedding) }
    });
    logger.info(`✅ Embedding saved`);
  }

  /**
   * PATH A: Auto-apply previous action from similar log
   */
  async autoApplyPreviousAction(log, similarLog) {
    try {
      logger.info(`✅ Similar log found (${(similarLog.similarity * 100).toFixed(1)}%)`);

      // Find previous admin decision
      const [adminDecision] = await prisma.adminDecision.findMany({
        where: { logId: similarLog.id, applied: true },
        orderBy: { decidedAt: 'desc' },
        take: 1
      });

      if (!adminDecision) {
        logger.warn('⚠️ No admin decision found for similar log');
        return await this.requestAdminDecision(log);
      }

      logger.info(`🚀 Auto-applying: "${adminDecision.action}"`);

      // Execute action
      const result = await this.executeAction(log, adminDecision.action, adminDecision.duration);

      // Record auto-applied rule
      await prisma.autoAppliedRule.create({
        data: {
          logId: log.id,
          sourceDecisionId: adminDecision.id,
          sourceLogId: similarLog.id,
          similarity: similarLog.similarity,
          actionTaken: adminDecision.action
        }
      });

      logger.info(`✅ Action executed (auto-applied)`);

      return {
        status: 'auto_applied',
        log_id: log.id,
        action: adminDecision.action,
        similarity: similarLog.similarity,
        learned_from_log_id: similarLog.id,
        message: `✅ "${adminDecision.action}" auto-applied (${(similarLog.similarity * 100).toFixed(1)}% match)`
      };
    } catch (error) {
      logger.error('❌ Error auto-applying:', error);
      throw error;
    }
  }

  /**
   * PATH B: Request admin decision
   */
  async requestAdminDecision(log) {
    try {
      logger.info(`❌ No similar log. Running LLM analysis...`);

      // LLM analysis
      const analysis = await aiAnalysisService.analyzeLog(log.id);
      logger.info(`🤖 LLM: Threat=${analysis.threatLevel}`);

      // Only create pending decision if threat level is HIGH or CRITICAL
      if (['HIGH', 'CRITICAL'].includes(analysis.threatLevel)) {
        const pendingDecision = await prisma.pendingAdminDecision.create({
          data: {
            logId: log.id,
            analysisId: analysis.id,
            threatLevel: analysis.threatLevel,
            analysis: analysis.result,
            status: 'pending'
          }
        });

        // Notify admin
        this.notifyAdmin(pendingDecision, log, analysis);

        logger.info(`📢 Pending decision created (ID: ${pendingDecision.id})`);

        return {
          status: 'pending_admin_decision',
          log_id: log.id,
          pending_decision_id: pendingDecision.id,
          threat_level: analysis.threatLevel,
          llm_analysis: analysis.result,
          message: '⏳ New pattern detected. Awaiting admin decision.'
        };
      } else {
        logger.info(`✅ Threat level ${analysis.threatLevel} - Auto-approved (low risk)`);
        
        return {
          status: 'auto_approved',
          log_id: log.id,
          threat_level: analysis.threatLevel,
          llm_analysis: analysis.result,
          message: `✅ Low risk (${analysis.threatLevel}) - No admin action needed.`
        };
      }
    } catch (error) {
      logger.error('❌ Error requesting admin decision:', error);
      throw error;
    }
  }

  /**
   * Execute action
   */
  async executeAction(log, action, duration = 3600) {
    logger.info(`⚡ Executing: "${action}"`);

    switch (action) {
      case 'block':
        if (log.ipAddress) {
          const expiresAt = new Date(Date.now() + duration * 1000);
          await prisma.blockedIP.upsert({
            where: { ipAddress: log.ipAddress },
            update: {
              expiresAt,
              reason: `Blocked by auto-learning: ${log.eventType}`,
              active: true,
              blockedAt: new Date()
            },
            create: {
              ipAddress: log.ipAddress,
              expiresAt,
              reason: `Blocked by auto-learning: ${log.eventType}`,
              active: true
            }
          });
          logger.info(`🚫 IP ${log.ipAddress} blocked (${duration}s)`);
          return { status: 'success', action: 'block', ip: log.ipAddress, duration };
        }
        return { status: 'skipped', message: 'No IP to block' };

      case 'monitor':
        logger.info(`👁️ Monitoring increased for IP: ${log.ipAddress}`);
        return { status: 'success', action: 'monitor', message: 'Monitoring flag set' };

      case 'alert':
        logger.info(`📢 Alert logged for Log ID: ${log.id}`);
        return { status: 'success', action: 'alert', message: 'Alert notification sent' };

      case 'ignore':
        logger.info(`✓ Ignored`);
        return { status: 'success', action: 'ignore' };

      default:
        logger.warn(`⚠️ Unknown action: ${action}`);
        return { status: 'unknown', action };
    }
  }

  /**
   * Notify admin (console only - implement real notification in production)
   */
  notifyAdmin(pendingDecision, log, analysis) {
    logger.info(`\n${'='.repeat(60)}`);
    logger.info(`🔔 ADMIN NOTIFICATION`);
    logger.info(`${'='.repeat(60)}`);
    logger.info(`📋 Pending Decision ID: ${pendingDecision.id}`);
    logger.info(`🆔 Log ID: ${log.id}`);
    logger.info(`⚠️  Threat Level: ${analysis.threatLevel}`);
    logger.info(`🌐 IP Address: ${log.ipAddress || 'N/A'}`);
    logger.info(`📝 Event Type: ${log.eventType}`);
    logger.info(`🔗 Decision URL: /api/admin/decide/${pendingDecision.id}`);
    logger.info(`${'='.repeat(60)}\n`);
    
    // TODO: Implement real notifications:
    // - Email (nodemailer)
    // - Slack/Discord webhook
    // - SMS (Twilio)
    // - Line Notify
  }

  /**
   * Brute force detection
   */
  detectBruteForce(logData) {
    const ip = logData.ipAddress;
    if (!ip) return;

    const isFailedAuth = 
      logData.eventType?.includes('auth') ||
      logData.eventType?.includes('login') ||
      logData.eventType?.includes('unauthorized') ||
      logData.metadata?.status_code === 401 ||
      logData.metadata?.status_code === 403;

    if (isFailedAuth) {
      const now = Date.now();
      
      if (!this.ipAttempts.has(ip)) {
        this.ipAttempts.set(ip, []);
      }

      const attempts = this.ipAttempts.get(ip);
      attempts.push(now);

      const recent = attempts.filter(t => now - t < this.bruteForceWindow);
      this.ipAttempts.set(ip, recent);

      if (recent.length >= this.bruteForceThreshold) {
        logger.warn(`🚨 Brute force: ${ip} (${recent.length} attempts)`);
        logData.eventType = 'brute_force';
        logData.severity = 'HIGH';
        logData.description = `Brute force: ${recent.length} attempts in ${this.bruteForceWindow / 1000}s`;
        this.ipAttempts.delete(ip);
      }
    }
  }

  /**
   * Estimate severity from log data
   */
  estimateInitialSeverity(logData) {
    const status = logData.status || logData.metadata?.status_code;
    if (status >= 500) return 'HIGH';
    if (status >= 400) return 'MEDIUM';
    
    const request = (logData.request || logData.raw_log || '').toLowerCase();
    if (/union.*select|\.\.\/|<script>|exec|eval/i.test(request)) return 'HIGH';
    
    return 'LOW';
  }

  /**
   * Get pending decisions
   */
  async getPendingDecisions(limit = 50) {
    return await prisma.pendingAdminDecision.findMany({
      where: { status: 'pending' },
      include: { log: true },
      orderBy: { createdAt: 'desc' },
      take: limit
    });
  }
}

module.exports = new AutoProcessingService();
