const { prisma } = require('../config/database');
const bcrypt = require('bcryptjs');
const logger = require('../middleware/logger');

/**
 * ==================== AGENT COMMAND SERVICE ====================
 *
 * ระบบจัดการ Agent ที่รันบนเซิร์ฟเวอร์ Linux
 *
 * Flow:
 *   Agent (Linux) ────register()──────► Backend: สร้าง Agent record + return API key
 *   Agent           ────heartbeat()───► Backend: อัปเดต lastSeen / status
 *   Agent           ────pollCommands()► Backend: ดึง pending commands กลับไปรัน
 *   Agent           ────reportResult()► Backend: รายงานผลการรัน command
 *
 *   Admin/AutoProcess ─pushCommand()──► Backend: สร้าง command ในคิว
 */
class AgentCommandService {
  /**
   * ลงทะเบียน Agent ใหม่กับ Backend
   * @returns {{ agent, plainApiKey }} — plainApiKey แสดงครั้งเดียว ต้อง copy เก็บไว้
   */
  async registerAgent({ agentId, hostname, ipAddress, version, metadata }) {
    if (!agentId || !hostname) {
      throw new Error('agentId and hostname are required');
    }

    // สร้าง API key แบบ random
    const plainApiKey = this._generateApiKey();
    const apiKeyHash = await bcrypt.hash(plainApiKey, 10);

    // Upsert: ถ้า agentId เดิมมีอยู่แล้ว ให้ update ข้อมูล (re-register)
    const agent = await prisma.agent.upsert({
      where: { agentId },
      update: {
        hostname,
        ipAddress: ipAddress || null,
        apiKeyHash,
        version: version || null,
        metadata: metadata || {},
        status: 'active',
        lastSeen: new Date()
      },
      create: {
        agentId,
        hostname,
        ipAddress: ipAddress || null,
        apiKeyHash,
        version: version || null,
        metadata: metadata || {},
        status: 'active',
        lastSeen: new Date()
      }
    });

    logger.info(`🤖 Agent registered: ${hostname} (${agentId})`);

    return { agent, plainApiKey };
  }

  /**
   * ตรวจสอบ API key ของ Agent
   * @returns {Agent | null}
   */
  async authenticateAgent(agentId, apiKey) {
    const agent = await prisma.agent.findUnique({ where: { agentId } });
    if (!agent) return null;

    const valid = await bcrypt.compare(apiKey, agent.apiKeyHash);
    if (!valid) return null;

    return agent;
  }

  /**
   * อัปเดต heartbeat ของ Agent
   */
  async agentHeartbeat(agentDbId, { ipAddress, metadata } = {}) {
    const updated = await prisma.agent.update({
      where: { id: agentDbId },
      data: {
        lastSeen: new Date(),
        status: 'active',
        ...(ipAddress && { ipAddress }),
        ...(metadata && { metadata })
      }
    });
    return updated;
  }

  /**
   * Push command เข้าคิวสำหรับ Agent (ใช้โดย autoProcessingService / admin)
   *
   * commandType:
   *   block_ip     — { ip, duration_seconds, reason }
   *   unblock_ip   — { ip }
   *   reload_nginx — {}
   *   run_script   — { script_b64, description }
   *
   * สามารถส่งไปหา agent เดียว (agentDbId) หรือ broadcast ไปทุก active agent (agentDbId = null)
   */
  async pushCommand(commandType, payload, agentDbId = null) {
    const timeoutAt = new Date(Date.now() + 5 * 60 * 1000); // default 5 min timeout

    // Broadcast mode: ส่งไปทุก active agent
    if (!agentDbId) {
      const agents = await prisma.agent.findMany({
        where: { status: 'active' }
      });

      if (agents.length === 0) {
        logger.warn(`⚠️  No active agents to receive command: ${commandType}`);
        return [];
      }

      const commands = await prisma.$transaction(
        agents.map(a =>
          prisma.agentCommand.create({
            data: {
              agentDbId: a.id,
              commandType,
              payload,
              status: 'pending',
              timeoutAt
            }
          })
        )
      );

      logger.info(`📡 Command "${commandType}" queued for ${agents.length} agent(s)`);
      return commands;
    }

    // Unicast mode: ส่งไปหา agent เดียว
    const command = await prisma.agentCommand.create({
      data: {
        agentDbId,
        commandType,
        payload,
        status: 'pending',
        timeoutAt
      }
    });

    logger.info(`📡 Command "${commandType}" queued for agent DB#${agentDbId}`);
    return [command];
  }

  /**
   * Agent ดึง pending commands ของตัวเอง
   */
  async pollCommands(agentDbId, limit = 10) {
    // อัปเดต lastSeen ไปก่อน
    await prisma.agent.update({
      where: { id: agentDbId },
      data: { lastSeen: new Date(), status: 'active' }
    });

    // Mark timeout commands
    await prisma.agentCommand.updateMany({
      where: {
        agentDbId,
        status: 'pending',
        timeoutAt: { lt: new Date() }
      },
      data: { status: 'timeout' }
    });

    return await prisma.agentCommand.findMany({
      where: { agentDbId, status: 'pending' },
      orderBy: { createdAt: 'asc' },
      take: limit
    });
  }

  /**
   * Agent รายงานผลการรัน command กลับมา
   */
  async reportCommandResult(commandId, agentDbId, { success, output, error } = {}) {
    const command = await prisma.agentCommand.findFirst({
      where: { id: commandId, agentDbId }
    });

    if (!command) throw new Error('Command not found or not assigned to this agent');
    if (!['pending', 'executing'].includes(command.status)) {
      throw new Error(`Command already in terminal state: ${command.status}`);
    }

    return await prisma.agentCommand.update({
      where: { id: commandId },
      data: {
        status: success ? 'success' : 'failed',
        result: { success, output: output || null, error: error || null },
        executedAt: new Date()
      }
    });
  }

  /**
   * ดึงรายการ Agent ทั้งหมด
   */
  async listAgents() {
    return await prisma.agent.findMany({
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        agentId: true,
        hostname: true,
        ipAddress: true,
        status: true,
        version: true,
        lastSeen: true,
        metadata: true,
        createdAt: true,
        _count: { select: { commands: true } }
      }
    });
  }

  /**
   * ดึงประวัติ command ของ agent
   */
  async getCommandHistory(agentDbId, limit = 50) {
    return await prisma.agentCommand.findMany({
      where: { agentDbId },
      orderBy: { createdAt: 'desc' },
      take: limit
    });
  }

  /**
   * Mark agent ที่ไม่ heartbeat นานกว่า N นาทีเป็น disconnected
   * Call จาก scheduled job
   */
  async markStaleAgents(thresholdMinutes = 10) {
    const cutoff = new Date(Date.now() - thresholdMinutes * 60 * 1000);
    const { count } = await prisma.agent.updateMany({
      where: {
        status: 'active',
        lastSeen: { lt: cutoff }
      },
      data: { status: 'disconnected' }
    });
    if (count > 0) logger.warn(`⚠️  Marked ${count} agent(s) as disconnected (no heartbeat > ${thresholdMinutes}m)`);
    return count;
  }

  // ---------- helpers ----------

  _generateApiKey(length = 40) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let key = 'sk-agent-';
    for (let i = 0; i < length; i++) {
      key += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return key;
  }
}

module.exports = new AgentCommandService();
