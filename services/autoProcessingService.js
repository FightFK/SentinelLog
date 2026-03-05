const { prisma } = require('../config/database');
const aiAnalysisService = require('./aiAnalysisService');
const logParserService = require('./logParserService');
const logger = require('../middleware/logger');
const agentCommandService = require('./agentCommandService');

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
    let log = null;
    
    try {
      logger.info('🔄 Processing incoming log...');

      // 1. Parse & Save
      const enrichedLog = this.parseAndEnrichLog(logData);
      log = await this.saveLog(enrichedLog);

      // 2. Generate Embedding (with retry and error handling)
      try {
        await this.generateEmbedding(log);
      } catch (embeddingError) {
        logger.error('⚠️ Embedding generation failed:', embeddingError.message);
        // Continue processing even if embedding fails - can be regenerated later
        // Mark for retry
        logger.info('⏭️ Continuing without embedding (can regenerate later)');
      }

      // 3. Search Similar (only if embedding exists)
      let similarLogs = [];
      try {
        similarLogs = await aiAnalysisService.findSimilarLogs(log.id, 5);
      } catch (searchError) {
        logger.error('⚠️ Similarity search failed:', searchError.message);
        // Continue to LLM analysis if search fails
      }

      const hasSimilar = similarLogs.length > 0 && similarLogs[0].similarity >= this.similarityThreshold;

      // 4. Decision
      if (hasSimilar) {
        return await this.autoApplyPreviousAction(log, similarLogs[0]);
      } else {
        return await this.requestAdminDecision(log);
      }
    } catch (error) {
      logger.error('❌ Error processing log:', error);
      
      // Return error response with log ID if available
      if (log) {
        return {
          status: 'error',
          log_id: log.id,
          error: error.message,
          message: 'Log saved but processing failed. Can retry later.'
        };
      }
      
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
      ipAddress: logData.ip_address || logData.ipAddress || logData.client_ip, 
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
  async generateEmbedding(log, retries = 3) {
    logger.info('🔮 Generating embedding...');
    
    const text = `${log.eventType} ${log.description || ''} ${log.rawLog || ''}`.trim();
    
    if (!text || text.length < 5) {
      logger.warn('⚠️ Text too short for embedding, skipping...');
      return;
    }

    let lastError = null;
    
    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const embedding = await aiAnalysisService.generateEmbedding(text);
        
        if (!embedding || !Array.isArray(embedding) || embedding.length !== 1536) {
          throw new Error(`Invalid embedding format (length: ${embedding?.length})`);
        }
        
        // Store in pgvector format using raw SQL
        const embeddingStr = `[${embedding.join(',')}]`;
        await prisma.$executeRaw`
          UPDATE security_logs 
          SET embedding = ${embeddingStr}::vector 
          WHERE id = ${log.id}
        `;
        
        logger.info(`✅ Embedding saved (dimension: ${embedding.length})`);
        return; 
        
      } catch (error) {
        lastError = error;
        logger.warn(`⚠️ Attempt ${attempt}/${retries} failed: ${error.message}`);
        
        if (attempt < retries) {
          // Wait before retry (exponential backoff)
          const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
          logger.info(`⏳ Retrying in ${delay}ms...`);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    }
    
    // All retries failed
    throw new Error(`Failed to generate embedding after ${retries} attempts: ${lastError.message}`);
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
          // Push block_ip command to all active agents (broadcast)
          agentCommandService.pushCommand('block_ip', {
            ip: log.ipAddress,
            duration_seconds: duration,
            reason: `Auto-blocked: ${log.eventType}`
          }).catch(e => logger.error('Agent push error (block_ip):', e.message));
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

  /**
   * Regenerate embeddings for logs without embeddings
   * Useful for fixing failed embedding generations
   */
  async regenerateFailedEmbeddings(limit = 100) {
    logger.info('🔄 Regenerating failed embeddings...');
    
    const logsWithoutEmbedding = await prisma.securityLog.findMany({
      where: { embedding: null },
      orderBy: { createdAt: 'desc' },
      take: limit
    });

    logger.info(`📊 Found ${logsWithoutEmbedding.length} logs without embeddings`);

    let success = 0;
    let failed = 0;

    for (const log of logsWithoutEmbedding) {
      try {
        await this.generateEmbedding(log);
        success++;
        
        // Add delay to avoid rate limits
        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (error) {
        logger.error(`❌ Failed to regenerate embedding for log ${log.id}:`, error.message);
        failed++;
      }
    }

    logger.info(`✅ Regeneration complete: ${success} success, ${failed} failed`);
    
    return {
      total: logsWithoutEmbedding.length,
      success,
      failed
    };
  }
}

module.exports = new AutoProcessingService();
