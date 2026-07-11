ALTER TABLE "remediations" ADD COLUMN     "source_finding_ids" TEXT[] DEFAULT ARRAY[]::TEXT[];
