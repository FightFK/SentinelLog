const { prisma } = require('../config/database');
const logger = require('../middleware/logger');

class SecurityResponseService {
  constructor() {
    // Configuration for automated responses
    this.responseRules = {
      HIGH: {
        autoBlock: true,
        blockDuration: 3600, // 1 hour in seconds
        notifyAdmin: true,
        actions: ['block_ip', 'alert_admin', 'log_incident']
      },
      MEDIUM: {
        autoBlock: false,
        blockDuration: 1800, // 30 minutes
        notifyAdmin: true,
        actions: ['alert_admin', 'log_incident', 'increase_monitoring']
      },
      LOW: {
        autoBlock: false,
        blockDuration: 0,
        notifyAdmin: false,
        actions: ['log_incident']
      },
      NONE: {
        autoBlock: false,
        blockDuration: 0,
        notifyAdmin: false,
        actions: []
      }
    };

    // Simulated firewall/security systems
    this.blockedIPs = new Map(); // In production, this would be actual firewall rules
  }

  // Execute automated response based on threat level
  async executeResponse(logId, analysisResult) {
    try {
      const threatLevel = analysisResult.threatLevel || 'NONE';
      const rules = this.responseRules[threatLevel];

      if (!rules) {
        logger.warn(`Unknown threat level: ${threatLevel}`);
        return null;
      }

      // Get the original log
      const log = await prisma.securityLog.findUnique({
        where: { id: parseInt(logId) }
      });

      if (!log) {
        throw new Error('Log not found');
      }

      const actions = [];

      // Execute each action based on rules
      for (const actionType of rules.actions) {
        let actionResult;

        switch (actionType) {
          case 'block_ip':
            if (log.ipAddress && rules.autoBlock) {
              actionResult = await this.blockIP(log.ipAddress, rules.blockDuration);
              actions.push(actionResult);
            }
            break;

          case 'alert_admin':
            actionResult = await this.alertAdmin(log, analysisResult);
            actions.push(actionResult);
            break;

          case 'log_incident':
            actionResult = await this.logIncident(log, analysisResult);
            actions.push(actionResult);
            break;

          case 'increase_monitoring':
            actionResult = await this.increaseMonitoring(log);
            actions.push(actionResult);
            break;

          default:
            logger.warn(`Unknown action type: ${actionType}`);
        }
      }

      // Store response actions in database
      const responseRecord = await prisma.securityResponse.create({
        data: {
          logId: parseInt(logId),
          threatLevel: threatLevel,
          actionsExecuted: actions,
          autoBlocked: rules.autoBlock,
          executedAt: new Date()
        }
      });

      logger.info(`Executed ${actions.length} actions for log ${logId} with threat level ${threatLevel}`);

      return {
        response_id: responseRecord.id,
        threat_level: threatLevel,
        actions_executed: actions,
        auto_blocked: rules.autoBlock
      };
    } catch (error) {
      logger.error('Error executing response:', error);
      throw error;
    }
  }

  // Block an IP address
  async blockIP(ipAddress, duration) {
    try {
      const expiresAt = new Date(Date.now() + duration * 1000);

      // In production, this would call actual firewall API
      // For example: iptables, AWS Security Groups, Azure NSG, etc.
      this.blockedIPs.set(ipAddress, {
        blockedAt: new Date(),
        expiresAt: expiresAt,
        active: true
      });

      logger.info(`Blocked IP: ${ipAddress} until ${expiresAt.toISOString()}`);

      // Store in database
      await prisma.blockedIP.create({
        data: {
          ipAddress: ipAddress,
          blockedAt: new Date(),
          expiresAt: expiresAt,
          reason: 'Automated threat response',
          active: true
        }
      });

      return {
        action: 'block_ip',
        status: 'success',
        target: ipAddress,
        duration: duration,
        expires_at: expiresAt.toISOString(),
        message: `IP ${ipAddress} blocked for ${duration} seconds`
      };
    } catch (error) {
      logger.error(`Error blocking IP ${ipAddress}:`, error);
      return {
        action: 'block_ip',
        status: 'failed',
        target: ipAddress,
        error: error.message
      };
    }
  }

  // Unblock an IP address
  async unblockIP(ipAddress) {
    try {
      // Remove from memory
      this.blockedIPs.delete(ipAddress);

      // Update database
      await prisma.blockedIP.updateMany({
        where: {
          ipAddress: ipAddress,
          active: true
        },
        data: {
          active: false,
          unblockedAt: new Date()
        }
      });

      logger.info(`Unblocked IP: ${ipAddress}`);

      return {
        action: 'unblock_ip',
        status: 'success',
        target: ipAddress,
        message: `IP ${ipAddress} unblocked`
      };
    } catch (error) {
      logger.error(`Error unblocking IP ${ipAddress}:`, error);
      throw error;
    }
  }

  // Check if IP is blocked
  isIPBlocked(ipAddress) {
    const blocked = this.blockedIPs.get(ipAddress);
    
    if (!blocked) return false;
    
    // Check if block has expired
    if (new Date() > blocked.expiresAt) {
      this.blockedIPs.delete(ipAddress);
      return false;
    }
    
    return true;
  }

  // Alert admin about security incident
  async alertAdmin(log, analysisResult) {
    try {
      // In production, this would send actual notifications:
      // - Email
      // - Slack/Teams webhook
      // - SMS
      // - PagerDuty
      
      const alert = {
        severity: analysisResult.threatLevel,
        log_id: log.id,
        source: log.source,
        ip_address: log.ipAddress,
        event_type: log.eventType,
        description: log.description,
        analysis: analysisResult.result,
        timestamp: new Date().toISOString()
      };

      logger.warn('ADMIN ALERT:', alert);

      // Store alert in database
      await prisma.adminAlert.create({
        data: {
          logId: log.id,
          severity: analysisResult.threatLevel,
          message: `Security incident detected: ${log.eventType}`,
          alertData: alert,
          sentAt: new Date()
        }
      });

      return {
        action: 'alert_admin',
        status: 'success',
        message: 'Admin alert sent successfully'
      };
    } catch (error) {
      logger.error('Error sending admin alert:', error);
      return {
        action: 'alert_admin',
        status: 'failed',
        error: error.message
      };
    }
  }

  // Log security incident
  async logIncident(log, analysisResult) {
    try {
      const incident = await prisma.securityIncident.create({
        data: {
          logId: log.id,
          incidentType: log.eventType,
          severity: analysisResult.threatLevel,
          description: analysisResult.result.summary || log.description,
          ipAddress: log.ipAddress,
          indicators: analysisResult.result.indicators || [],
          recommendations: analysisResult.result.recommendations || [],
          status: 'open',
          detectedAt: log.timestamp
        }
      });

      logger.info(`Security incident logged: ${incident.id}`);

      return {
        action: 'log_incident',
        status: 'success',
        incident_id: incident.id,
        message: 'Security incident logged'
      };
    } catch (error) {
      logger.error('Error logging incident:', error);
      return {
        action: 'log_incident',
        status: 'failed',
        error: error.message
      };
    }
  }

  // Increase monitoring for suspicious source
  async increaseMonitoring(log) {
    try {
      // In production, this would:
      // - Increase log sampling rate
      // - Enable detailed packet inspection
      // - Add to watchlist

      await prisma.monitoringRule.create({
        data: {
          source: log.source,
          ipAddress: log.ipAddress,
          ruleType: 'increased_monitoring',
          priority: 'high',
          expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
          active: true
        }
      });

      logger.info(`Increased monitoring for source: ${log.source}, IP: ${log.ipAddress}`);

      return {
        action: 'increase_monitoring',
        status: 'success',
        target: log.ipAddress || log.source,
        message: 'Monitoring level increased for 24 hours'
      };
    } catch (error) {
      logger.error('Error increasing monitoring:', error);
      return {
        action: 'increase_monitoring',
        status: 'failed',
        error: error.message
      };
    }
  }

  // Get all blocked IPs
  async getBlockedIPs() {
    try {
      const blocked = await prisma.blockedIP.findMany({
        where: { active: true },
        orderBy: { blockedAt: 'desc' }
      });

      return blocked;
    } catch (error) {
      logger.error('Error getting blocked IPs:', error);
      throw error;
    }
  }

  // Get security incidents
  async getIncidents(status = null) {
    try {
      const where = status ? { status } : {};

      const incidents = await prisma.securityIncident.findMany({
        where,
        include: {
          log: true
        },
        orderBy: { detectedAt: 'desc' }
      });

      return incidents;
    } catch (error) {
      logger.error('Error getting incidents:', error);
      throw error;
    }
  }

  // Close an incident
  async closeIncident(incidentId, resolution) {
    try {
      const incident = await prisma.securityIncident.update({
        where: { id: parseInt(incidentId) },
        data: {
          status: 'closed',
          resolution: resolution,
          closedAt: new Date()
        }
      });

      logger.info(`Incident ${incidentId} closed`);

      return incident;
    } catch (error) {
      logger.error('Error closing incident:', error);
      throw error;
    }
  }
}

module.exports = new SecurityResponseService();
