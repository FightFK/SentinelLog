const agentCommandService = require('../services/agentCommandService');
const logger = require('../middleware/logger');

/**
 * ==================== AGENT CONTROLLER ====================
 * Routes ที่ใช้โดย Agent บน Linux Server
 *
 * Authentication: ทุก request (ยกเว้น register) ต้องส่ง Header:
 *   X-Agent-ID:  <agentId>   (UUID ที่ agent สร้างเอง)
 *   X-Agent-Key: <apiKey>    (API key ที่ได้รับตอน register)
 */
class AgentController {
  /**
   * POST /api/agent/register
   * Agent ลงทะเบียนตัวเองกับ Backend ครั้งแรก (หรือ re-register)
   *
   * Body:
   *   agent_id    string   UUID ที่ agent สร้างเอง (ใช้ hostname+MAC หรือ uuidgen)
   *   hostname    string
   *   ip_address  string?  IP ของ server
   *   version     string?  version ของ agent script
   *   metadata    object?  { os, nginx_version, nginx_log_path, capabilities[] }
   *   secret      string   AGENT_REGISTER_SECRET จาก .env (เพื่อกัน agent แปลกปลอม)
   *
   * Response:
   *   api_key     string   *** แสดงครั้งเดียว *** ต้องเก็บใส่ .env ของ agent
   */
  async register(req, res, next) {
    try {
      const { agent_id, hostname, ip_address, version, metadata, secret } = req.body;

      // Validate register secret (กัน agent แปลกปลอม)
      if (!process.env.AGENT_REGISTER_SECRET) {
        return res.status(500).json({ error: 'AGENT_REGISTER_SECRET not configured on server' });
      }
      if (secret !== process.env.AGENT_REGISTER_SECRET) {
        logger.warn(`🚫 Invalid register secret from ${ip_address || 'unknown'}`);
        return res.status(401).json({ error: 'Invalid register secret' });
      }

      if (!agent_id || !hostname) {
        return res.status(400).json({ error: 'agent_id and hostname are required' });
      }

      const { agent, plainApiKey } = await agentCommandService.registerAgent({
        agentId: agent_id,
        hostname,
        ipAddress: ip_address,
        version,
        metadata
      });

      logger.info(`✅ Agent registered: ${hostname} (${agent_id})`);

      res.status(201).json({
        success: true,
        message: 'Agent registered successfully. Save the api_key — it will not be shown again.',
        data: {
          agent_db_id: agent.id,
          agent_id: agent.agentId,
          hostname: agent.hostname,
          api_key: plainApiKey,  // แสดงครั้งเดียวเท่านั้น
          status: agent.status,
          created_at: agent.createdAt
        }
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/agent/heartbeat
   * Agent ส่ง heartbeat เพื่อบอกว่ายังทำงานอยู่ (ทุก ~60s)
   */
  async heartbeat(req, res, next) {
    try {
      const agent = req.agent; // set by agentAuthMiddleware
      const { ip_address, metadata } = req.body;

      await agentCommandService.agentHeartbeat(agent.id, { ipAddress: ip_address, metadata });

      res.json({
        success: true,
        timestamp: new Date().toISOString(),
        agent_db_id: agent.id
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/agent/commands
   * Agent poll คำสั่งที่รอการดำเนินการ (ทุก ~10s)
   *
   * Query:
   *   limit  number?  default 10
   */
  async pollCommands(req, res, next) {
    try {
      const agent = req.agent;
      const limit = parseInt(req.query.limit) || 10;

      const commands = await agentCommandService.pollCommands(agent.id, limit);

      res.json({
        success: true,
        data: commands.map(cmd => ({
          id: cmd.id,
          command_type: cmd.commandType,
          payload: cmd.payload,
          created_at: cmd.createdAt,
          timeout_at: cmd.timeoutAt
        }))
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/agent/commands/:command_id/result
   * Agent รายงานผลการรัน command
   *
   * Body:
   *   success  boolean
   *   output   string?   stdout / success message
   *   error    string?   error message ถ้า success=false
   */
  async reportResult(req, res, next) {
    try {
      const agent = req.agent;
      const commandId = parseInt(req.params.command_id);
      const { success, output, error } = req.body;

      if (typeof success !== 'boolean') {
        return res.status(400).json({ error: 'success (boolean) is required' });
      }

      const updated = await agentCommandService.reportCommandResult(commandId, agent.id, {
        success,
        output,
        error
      });

      logger.info(
        `📋 Command #${commandId} result from ${agent.hostname}: ${success ? '✅ success' : '❌ failed'}`
      );

      res.json({ success: true, data: updated });
    } catch (error) {
      next(error);
    }
  }
}

// ==================== ADMIN AGENT CONTROLLER ====================
// Routes ที่ใช้โดย Admin (ผ่าน Dashboard)

class AdminAgentController {
  /**
   * GET /api/admin/agents
   * ดูรายการ agent ทั้งหมด + status
   */
  async listAgents(req, res, next) {
    try {
      const agents = await agentCommandService.listAgents();
      res.json({ success: true, data: agents });
    } catch (error) {
      next(error);
    }
  }

  /**
   * POST /api/admin/agents/:agent_db_id/command
   * Admin ส่งคำสั่งไปหา agent โดยตรง
   *
   * Body:
   *   command_type  string   block_ip | unblock_ip | reload_nginx | run_script
   *   payload       object
   *     block_ip:    { ip, duration_seconds?, reason? }
   *     unblock_ip:  { ip }
   *     reload_nginx: {}
   *     run_script:  { script_b64, description }
   */
  async sendCommand(req, res, next) {
    try {
      const agentDbId = req.params.agent_db_id === 'broadcast'
        ? null
        : parseInt(req.params.agent_db_id);

      const { command_type, payload } = req.body;

      if (!command_type) {
        return res.status(400).json({ error: 'command_type is required' });
      }

      const VALID_TYPES = ['block_ip', 'unblock_ip', 'reload_nginx', 'run_script'];
      if (!VALID_TYPES.includes(command_type)) {
        return res.status(400).json({
          error: `Invalid command_type. Valid: ${VALID_TYPES.join(', ')}`
        });
      }

      const commands = await agentCommandService.pushCommand(command_type, payload || {}, agentDbId);

      res.status(201).json({
        success: true,
        message: `Command "${command_type}" queued for ${agentDbId === null ? 'all agents' : `agent #${agentDbId}`}`,
        data: commands
      });
    } catch (error) {
      next(error);
    }
  }

  /**
   * GET /api/admin/agents/:agent_db_id/commands
   * ดูประวัติ command ของ agent
   */
  async getCommandHistory(req, res, next) {
    try {
      const agentDbId = parseInt(req.params.agent_db_id);
      const limit = parseInt(req.query.limit) || 50;

      const history = await agentCommandService.getCommandHistory(agentDbId, limit);
      res.json({ success: true, data: history });
    } catch (error) {
      next(error);
    }
  }
}

module.exports = {
  agentController: new AgentController(),
  adminAgentController: new AdminAgentController()
};
