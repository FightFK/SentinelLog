const securityResponseService = require('../services/securityResponseService');
const aiAnalysisService = require('../services/aiAnalysisService');
const { prisma } = require('../config/database');

class ResponseController {
  // Execute automated response for a log analysis
  async executeResponse(req, res, next) {
    try {
      const { log_id, analysis_id } = req.body;

      if (!log_id) {
        return res.status(400).json({
          error: 'log_id is required'
        });
      }

      // Get analysis result
      let analysisResult;
      if (analysis_id) {
        analysisResult = await prisma.analysisResult.findUnique({
          where: { id: parseInt(analysis_id) }
        });
      } else {
        // Get the latest analysis for this log
        const results = await prisma.analysisResult.findMany({
          where: { logId: parseInt(log_id) },
          orderBy: { analyzedAt: 'desc' },
          take: 1
        });
        analysisResult = results[0];
      }

      if (!analysisResult) {
        return res.status(404).json({
          error: 'No analysis found for this log'
        });
      }

      // Execute response
      const response = await securityResponseService.executeResponse(
        log_id,
        analysisResult
      );

      res.json({
        success: true,
        data: response
      });
    } catch (error) {
      next(error);
    }
  }

  // Analyze and auto-respond
  async analyzeAndRespond(req, res, next) {
    try {
      const { log_id } = req.body;

      if (!log_id) {
        return res.status(400).json({
          error: 'log_id is required'
        });
      }

      // First, analyze the log
      const analysis = await aiAnalysisService.analyzeLog(log_id);

      // Then, execute automated response
      const response = await securityResponseService.executeResponse(
        log_id,
        analysis.analysis_record
      );

      res.json({
        success: true,
        data: {
          analysis: analysis.analysis,
          response: response
        }
      });
    } catch (error) {
      next(error);
    }
  }

  // Block an IP manually
  async blockIP(req, res, next) {
    try {
      const { ip_address, duration = 3600, reason } = req.body;

      if (!ip_address) {
        return res.status(400).json({
          error: 'ip_address is required'
        });
      }

      const result = await securityResponseService.blockIP(ip_address, duration);

      if (reason) {
        await prisma.blockedIP.updateMany({
          where: { ipAddress: ip_address, active: true },
          data: { reason }
        });
      }

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Unblock an IP
  async unblockIP(req, res, next) {
    try {
      const { ip_address } = req.body;

      if (!ip_address) {
        return res.status(400).json({
          error: 'ip_address is required'
        });
      }

      const result = await securityResponseService.unblockIP(ip_address);

      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      next(error);
    }
  }

  // Get all blocked IPs
  async getBlockedIPs(req, res, next) {
    try {
      const blocked = await securityResponseService.getBlockedIPs();

      res.json({
        success: true,
        data: blocked
      });
    } catch (error) {
      next(error);
    }
  }

  // Get security incidents
  async getIncidents(req, res, next) {
    try {
      const { status } = req.query;

      const incidents = await securityResponseService.getIncidents(status);

      res.json({
        success: true,
        data: incidents
      });
    } catch (error) {
      next(error);
    }
  }

  // Close an incident
  async closeIncident(req, res, next) {
    try {
      const { incident_id } = req.params;
      const { resolution } = req.body;

      if (!resolution) {
        return res.status(400).json({
          error: 'resolution is required'
        });
      }

      const incident = await securityResponseService.closeIncident(
        incident_id,
        resolution
      );

      res.json({
        success: true,
        data: incident
      });
    } catch (error) {
      next(error);
    }
  }

  // Get response history for a log
  async getResponseHistory(req, res, next) {
    try {
      const { log_id } = req.params;

      const responses = await prisma.securityResponse.findMany({
        where: { logId: parseInt(log_id) },
        orderBy: { executedAt: 'desc' }
      });

      res.json({
        success: true,
        data: responses
      });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = new ResponseController();
