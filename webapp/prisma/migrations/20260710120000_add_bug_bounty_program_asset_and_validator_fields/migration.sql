-- AlterTable
ALTER TABLE "projects" ADD COLUMN     "asset_id" TEXT,
ADD COLUMN     "program_id" TEXT;

-- AlterTable
ALTER TABLE "remediations" ADD COLUMN     "business_impact" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "confidence_score" DOUBLE PRECISION,
ADD COLUMN     "false_positive_score" DOUBLE PRECISION,
ADD COLUMN     "likelihood" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "platform_report_url" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "program_id" TEXT,
ADD COLUMN     "reward_amount" DOUBLE PRECISION,
ADD COLUMN     "reward_currency" TEXT NOT NULL DEFAULT 'USD',
ADD COLUMN     "submission_status" TEXT NOT NULL DEFAULT 'not_submitted',
ADD COLUMN     "submitted_at" TIMESTAMP(3),
ADD COLUMN     "validator_status" TEXT NOT NULL DEFAULT 'needs_manual_review';

-- CreateTable
CREATE TABLE "programs" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "platform" TEXT NOT NULL DEFAULT 'manual',
    "platform_handle" TEXT NOT NULL DEFAULT '',
    "platform_url" TEXT NOT NULL DEFAULT '',
    "status" TEXT NOT NULL DEFAULT 'active',
    "scope_summary" TEXT NOT NULL DEFAULT '',
    "out_of_scope" TEXT NOT NULL DEFAULT '',
    "rate_limits" TEXT NOT NULL DEFAULT '',
    "credential_notes" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "reward_min" DOUBLE PRECISION,
    "reward_max" DOUBLE PRECISION,
    "reward_currency" TEXT NOT NULL DEFAULT 'USD',
    "start_date" TIMESTAMP(3),
    "deadline" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "programs_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "assets" (
    "id" TEXT NOT NULL,
    "program_id" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "in_scope" BOOLEAN NOT NULL DEFAULT true,
    "notes" TEXT NOT NULL DEFAULT '',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "assets_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "programs_user_id_idx" ON "programs"("user_id");

-- CreateIndex
CREATE INDEX "programs_user_id_status_idx" ON "programs"("user_id", "status");

-- CreateIndex
CREATE INDEX "assets_program_id_idx" ON "assets"("program_id");

-- CreateIndex
CREATE INDEX "assets_program_id_type_idx" ON "assets"("program_id", "type");

-- CreateIndex
CREATE INDEX "projects_program_id_idx" ON "projects"("program_id");

-- CreateIndex
CREATE INDEX "projects_asset_id_idx" ON "projects"("asset_id");

-- CreateIndex
CREATE INDEX "remediations_program_id_severity_idx" ON "remediations"("program_id", "severity");

-- CreateIndex
CREATE INDEX "remediations_program_id_submission_status_idx" ON "remediations"("program_id", "submission_status");

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "projects" ADD CONSTRAINT "projects_asset_id_fkey" FOREIGN KEY ("asset_id") REFERENCES "assets"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "programs" ADD CONSTRAINT "programs_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "assets" ADD CONSTRAINT "assets_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "remediations" ADD CONSTRAINT "remediations_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE SET NULL ON UPDATE CASCADE;

