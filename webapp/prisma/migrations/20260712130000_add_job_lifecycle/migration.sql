-- CreateTable: Job (unified scan-lifecycle projection — master-plan Phase 2)
CREATE TABLE "jobs" (
    "id" TEXT NOT NULL,
    "module_name" TEXT NOT NULL,
    "program_id" TEXT,
    "user_id" TEXT,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "progress" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "config" JSONB NOT NULL DEFAULT '{}',
    "error" TEXT,
    "retries" INTEGER NOT NULL DEFAULT 0,
    "started_at" TIMESTAMP(3),
    "finished_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "jobs_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "jobs_program_id_idx" ON "jobs"("program_id");
CREATE INDEX "jobs_status_idx" ON "jobs"("status");
