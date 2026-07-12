-- Master-plan Phase 4: user-authoritative memory fields (additive, non-clobbered by recompute)
ALTER TABLE "program_memories" ADD COLUMN "interesting_endpoints" JSONB NOT NULL DEFAULT '[]';
ALTER TABLE "program_memories" ADD COLUMN "recon_summaries" JSONB NOT NULL DEFAULT '[]';
ALTER TABLE "program_memories" ADD COLUMN "report_refs" TEXT[] DEFAULT ARRAY[]::TEXT[];
ALTER TABLE "program_memories" ADD COLUMN "user_notes" TEXT NOT NULL DEFAULT '';
