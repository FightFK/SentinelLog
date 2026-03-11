/*
  Warnings:

  - You are about to drop the column `analysis_type` on the `analysis_results` table. All the data in the column will be lost.
  - You are about to drop the column `recommendations` on the `analysis_results` table. All the data in the column will be lost.
  - You are about to drop the column `unblocked_at` on the `blocked_ips` table. All the data in the column will be lost.
  - You are about to drop the `admin_alerts` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `monitoring_rules` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `security_incidents` table. If the table is not empty, all the data it contains will be lost.
  - You are about to drop the `security_responses` table. If the table is not empty, all the data it contains will be lost.
  - A unique constraint covering the columns `[ip_address]` on the table `blocked_ips` will be added. If there are existing duplicate values, this will fail.

*/
-- DropForeignKey
ALTER TABLE "security_incidents" DROP CONSTRAINT "security_incidents_log_id_fkey";

-- DropForeignKey
ALTER TABLE "security_responses" DROP CONSTRAINT "security_responses_log_id_fkey";

-- DropIndex
DROP INDEX "blocked_ips_ip_address_idx";

-- DropIndex
DROP INDEX "security_logs_embedding_idx";

-- AlterTable
ALTER TABLE "analysis_results" DROP COLUMN "analysis_type",
DROP COLUMN "recommendations";

-- AlterTable
ALTER TABLE "blocked_ips" DROP COLUMN "unblocked_at";

-- DropTable
DROP TABLE "admin_alerts";

-- DropTable
DROP TABLE "monitoring_rules";

-- DropTable
DROP TABLE "security_incidents";

-- DropTable
DROP TABLE "security_responses";

-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "password_hash" TEXT NOT NULL,
    "name" VARCHAR(255) NOT NULL,
    "role" VARCHAR(50) NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_login" TIMESTAMP(3),

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "activity_logs" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER NOT NULL,
    "action" VARCHAR(255) NOT NULL,
    "details" JSONB,
    "ip_address" INET,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "activity_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "pending_admin_decisions" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "analysis_id" INTEGER NOT NULL,
    "threat_level" VARCHAR(50) NOT NULL,
    "analysis" JSONB NOT NULL,
    "status" VARCHAR(50) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "resolved_at" TIMESTAMP(3),

    CONSTRAINT "pending_admin_decisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_decisions" (
    "id" SERIAL NOT NULL,
    "user_id" INTEGER,
    "log_id" INTEGER NOT NULL,
    "pending_id" INTEGER NOT NULL,
    "action" VARCHAR(50) NOT NULL,
    "reason" TEXT,
    "duration" INTEGER DEFAULT 3600,
    "threat_level" VARCHAR(50) NOT NULL,
    "analysis_data" JSONB NOT NULL,
    "applied" BOOLEAN NOT NULL DEFAULT true,
    "decided_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "admin_decisions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auto_applied_rules" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "source_decision_id" INTEGER NOT NULL,
    "source_log_id" INTEGER NOT NULL,
    "similarity" DOUBLE PRECISION NOT NULL,
    "action_taken" VARCHAR(50) NOT NULL,
    "executed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "auto_applied_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "activity_logs_user_id_idx" ON "activity_logs"("user_id");

-- CreateIndex
CREATE INDEX "activity_logs_timestamp_idx" ON "activity_logs"("timestamp");

-- CreateIndex
CREATE INDEX "pending_admin_decisions_log_id_idx" ON "pending_admin_decisions"("log_id");

-- CreateIndex
CREATE INDEX "pending_admin_decisions_status_idx" ON "pending_admin_decisions"("status");

-- CreateIndex
CREATE INDEX "admin_decisions_user_id_idx" ON "admin_decisions"("user_id");

-- CreateIndex
CREATE INDEX "admin_decisions_log_id_idx" ON "admin_decisions"("log_id");

-- CreateIndex
CREATE INDEX "admin_decisions_action_idx" ON "admin_decisions"("action");

-- CreateIndex
CREATE INDEX "admin_decisions_decided_at_idx" ON "admin_decisions"("decided_at");

-- CreateIndex
CREATE INDEX "auto_applied_rules_log_id_idx" ON "auto_applied_rules"("log_id");

-- CreateIndex
CREATE INDEX "auto_applied_rules_action_taken_idx" ON "auto_applied_rules"("action_taken");

-- CreateIndex
CREATE INDEX "auto_applied_rules_executed_at_idx" ON "auto_applied_rules"("executed_at");

-- CreateIndex
CREATE UNIQUE INDEX "blocked_ips_ip_address_key" ON "blocked_ips"("ip_address");

-- CreateIndex
CREATE INDEX "security_logs_ip_address_idx" ON "security_logs"("ip_address");

-- AddForeignKey
ALTER TABLE "activity_logs" ADD CONSTRAINT "activity_logs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pending_admin_decisions" ADD CONSTRAINT "pending_admin_decisions_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "security_logs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "admin_decisions" ADD CONSTRAINT "admin_decisions_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "auto_applied_rules" ADD CONSTRAINT "auto_applied_rules_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "security_logs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
