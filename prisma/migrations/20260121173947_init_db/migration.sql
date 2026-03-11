-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "vector";

-- CreateTable
CREATE TABLE "security_logs" (
    "id" SERIAL NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "source" VARCHAR(255) NOT NULL,
    "severity" VARCHAR(50) NOT NULL,
    "event_type" VARCHAR(100) NOT NULL,
    "description" TEXT,
    "ip_address" INET,
    "user_agent" TEXT,
    "raw_log" TEXT,
    "metadata" JSONB,
    "embedding" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_logs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "analysis_results" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "analysis_type" VARCHAR(100) NOT NULL,
    "result" JSONB NOT NULL,
    "confidence" DOUBLE PRECISION,
    "threat_level" VARCHAR(50),
    "recommendations" JSONB,
    "analyzed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "analysis_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_responses" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "threat_level" VARCHAR(50) NOT NULL,
    "actions_executed" JSONB NOT NULL,
    "auto_blocked" BOOLEAN NOT NULL DEFAULT false,
    "executed_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_responses_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "blocked_ips" (
    "id" SERIAL NOT NULL,
    "ip_address" INET NOT NULL,
    "blocked_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "unblocked_at" TIMESTAMP(3),
    "reason" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "blocked_ips_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_incidents" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "incident_type" VARCHAR(100) NOT NULL,
    "severity" VARCHAR(50) NOT NULL,
    "description" TEXT NOT NULL,
    "ip_address" INET,
    "indicators" JSONB NOT NULL,
    "recommendations" JSONB NOT NULL,
    "status" VARCHAR(50) NOT NULL,
    "resolution" TEXT,
    "detected_at" TIMESTAMP(3) NOT NULL,
    "closed_at" TIMESTAMP(3),

    CONSTRAINT "security_incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "admin_alerts" (
    "id" SERIAL NOT NULL,
    "log_id" INTEGER NOT NULL,
    "severity" VARCHAR(50) NOT NULL,
    "message" TEXT NOT NULL,
    "alert_data" JSONB NOT NULL,
    "sent_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "read_at" TIMESTAMP(3),

    CONSTRAINT "admin_alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "monitoring_rules" (
    "id" SERIAL NOT NULL,
    "source" VARCHAR(255),
    "ip_address" INET,
    "rule_type" VARCHAR(100) NOT NULL,
    "priority" VARCHAR(50) NOT NULL,
    "expires_at" TIMESTAMP(3) NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "monitoring_rules_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "security_logs_timestamp_idx" ON "security_logs"("timestamp");

-- CreateIndex
CREATE INDEX "security_logs_severity_idx" ON "security_logs"("severity");

-- CreateIndex
CREATE INDEX "security_logs_event_type_idx" ON "security_logs"("event_type");

-- CreateIndex
CREATE INDEX "analysis_results_log_id_idx" ON "analysis_results"("log_id");

-- CreateIndex
CREATE INDEX "analysis_results_threat_level_idx" ON "analysis_results"("threat_level");

-- CreateIndex
CREATE INDEX "security_responses_log_id_idx" ON "security_responses"("log_id");

-- CreateIndex
CREATE INDEX "security_responses_threat_level_idx" ON "security_responses"("threat_level");

-- CreateIndex
CREATE INDEX "blocked_ips_ip_address_idx" ON "blocked_ips"("ip_address");

-- CreateIndex
CREATE INDEX "blocked_ips_active_idx" ON "blocked_ips"("active");

-- CreateIndex
CREATE INDEX "security_incidents_log_id_idx" ON "security_incidents"("log_id");

-- CreateIndex
CREATE INDEX "security_incidents_status_idx" ON "security_incidents"("status");

-- CreateIndex
CREATE INDEX "security_incidents_severity_idx" ON "security_incidents"("severity");

-- CreateIndex
CREATE INDEX "admin_alerts_log_id_idx" ON "admin_alerts"("log_id");

-- CreateIndex
CREATE INDEX "admin_alerts_sent_at_idx" ON "admin_alerts"("sent_at");

-- CreateIndex
CREATE INDEX "monitoring_rules_ip_address_idx" ON "monitoring_rules"("ip_address");

-- CreateIndex
CREATE INDEX "monitoring_rules_active_idx" ON "monitoring_rules"("active");

-- AddForeignKey
ALTER TABLE "analysis_results" ADD CONSTRAINT "analysis_results_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "security_logs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_responses" ADD CONSTRAINT "security_responses_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "security_logs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_incidents" ADD CONSTRAINT "security_incidents_log_id_fkey" FOREIGN KEY ("log_id") REFERENCES "security_logs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
