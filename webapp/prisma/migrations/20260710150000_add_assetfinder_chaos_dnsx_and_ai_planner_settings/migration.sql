-- AlterTable
ALTER TABLE "projects" ADD COLUMN     "assetfinder_enabled" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "assetfinder_max_results" INTEGER NOT NULL DEFAULT 5000,
ADD COLUMN     "chaos_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "chaos_max_results" INTEGER NOT NULL DEFAULT 5000,
ADD COLUMN     "dnsx_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "dnsx_threads" INTEGER NOT NULL DEFAULT 100,
ADD COLUMN     "recon_ai_planner_enabled" BOOLEAN NOT NULL DEFAULT true;

