-- CreateTable
CREATE TABLE "program_memories" (
    "id" TEXT NOT NULL,
    "program_id" TEXT NOT NULL,
    "tech_stack" JSONB NOT NULL DEFAULT '[]',
    "known_paths" JSONB NOT NULL DEFAULT '[]',
    "working_payloads" JSONB NOT NULL DEFAULT '[]',
    "prior_findings_summary" TEXT NOT NULL DEFAULT '',
    "last_computed_from_project_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "program_memories_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "program_memories_program_id_key" ON "program_memories"("program_id");

-- AddForeignKey
ALTER TABLE "program_memories" ADD CONSTRAINT "program_memories_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

