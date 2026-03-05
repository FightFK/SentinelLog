-- ==================== Agent Management Tables ====================

-- Agent table: represents a SentinelLog agent running on a Linux server
CREATE TABLE "agents" (
    "id"           SERIAL PRIMARY KEY,
    "agent_id"     VARCHAR(100) NOT NULL UNIQUE,    -- UUID sent by agent on registration
    "hostname"     VARCHAR(255) NOT NULL,
    "ip_address"   VARCHAR(50),
    "api_key_hash" VARCHAR(255) NOT NULL,            -- bcrypt hash of agent API key
    "status"       VARCHAR(50)  NOT NULL DEFAULT 'active',  -- active | inactive | disconnected
    "last_seen"    TIMESTAMP(3),
    "version"      VARCHAR(50),
    "metadata"     JSONB,                            -- OS info, nginx path, capabilities
    "created_at"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX "agents_status_idx"    ON "agents"("status");
CREATE INDEX "agents_last_seen_idx" ON "agents"("last_seen");

-- AgentCommand table: command queue for each agent
CREATE TABLE "agent_commands" (
    "id"           SERIAL PRIMARY KEY,
    "agent_db_id"  INTEGER NOT NULL,
    "command_type" VARCHAR(100) NOT NULL,   -- block_ip | unblock_ip | reload_nginx | run_script
    "payload"      JSONB NOT NULL,          -- { ip, duration, reason, script, ... }
    "status"       VARCHAR(50) NOT NULL DEFAULT 'pending',  -- pending | executing | success | failed | timeout
    "result"       JSONB,                   -- execution result reported back by agent
    "created_at"   TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "executed_at"  TIMESTAMP(3),
    "timeout_at"   TIMESTAMP(3),

    CONSTRAINT "agent_commands_agent_db_id_fkey"
        FOREIGN KEY ("agent_db_id") REFERENCES "agents"("id") ON DELETE CASCADE
);

CREATE INDEX "agent_commands_agent_db_id_idx" ON "agent_commands"("agent_db_id");
CREATE INDEX "agent_commands_status_idx"      ON "agent_commands"("status");
CREATE INDEX "agent_commands_command_type_idx" ON "agent_commands"("command_type");
CREATE INDEX "agent_commands_created_at_idx"  ON "agent_commands"("created_at");
