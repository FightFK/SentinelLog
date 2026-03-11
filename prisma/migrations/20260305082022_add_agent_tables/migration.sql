-- DropForeignKey
ALTER TABLE "agent_commands" DROP CONSTRAINT "agent_commands_agent_db_id_fkey";

-- AddForeignKey
ALTER TABLE "agent_commands" ADD CONSTRAINT "agent_commands_agent_db_id_fkey" FOREIGN KEY ("agent_db_id") REFERENCES "agents"("id") ON DELETE CASCADE ON UPDATE CASCADE;
