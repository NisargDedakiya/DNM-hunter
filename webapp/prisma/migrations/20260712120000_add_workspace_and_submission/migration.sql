-- CreateTable: Workspace (top-level container — master-plan Phase 1)
CREATE TABLE "workspaces" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL DEFAULT '',
    "user_id" TEXT NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "workspaces_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "workspaces_user_id_idx" ON "workspaces"("user_id");

-- AddForeignKey
ALTER TABLE "workspaces" ADD CONSTRAINT "workspaces_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AlterTable: add nullable workspace_id to programs
ALTER TABLE "programs" ADD COLUMN "workspace_id" TEXT;

-- CreateIndex
CREATE INDEX "programs_workspace_id_idx" ON "programs"("workspace_id");

-- AddForeignKey
ALTER TABLE "programs" ADD CONSTRAINT "programs_workspace_id_fkey" FOREIGN KEY ("workspace_id") REFERENCES "workspaces"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- Data backfill: one default Workspace per user that owns at least one program,
-- then assign each of that user's unassigned programs to it. Idempotent-safe on
-- a fresh apply; existing program data is preserved.
INSERT INTO "workspaces" ("id", "name", "description", "user_id", "created_at", "updated_at")
SELECT
    'ws_default_' || u."id",
    'Default Workspace',
    'Auto-created to hold programs that predate the Workspace spine.',
    u."id",
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
FROM "users" u
WHERE EXISTS (SELECT 1 FROM "programs" p WHERE p."user_id" = u."id");

UPDATE "programs" p
SET "workspace_id" = 'ws_default_' || p."user_id"
WHERE p."workspace_id" IS NULL;

-- CreateTable: Submission (bug-bounty submission history — master-plan Phase 1, Priority 10)
CREATE TABLE "submissions" (
    "id" TEXT NOT NULL,
    "program_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL DEFAULT 'medium',
    "status" TEXT NOT NULL DEFAULT 'draft',
    "platform" TEXT,
    "bounty" DOUBLE PRECISION,
    "notes" TEXT NOT NULL DEFAULT '',
    "report_id" TEXT,
    "submitted_at" TIMESTAMP(3),
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "submissions_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "submissions_program_id_idx" ON "submissions"("program_id");
CREATE INDEX "submissions_program_id_status_idx" ON "submissions"("program_id", "status");

-- AddForeignKey
ALTER TABLE "submissions" ADD CONSTRAINT "submissions_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE CASCADE ON UPDATE CASCADE;
