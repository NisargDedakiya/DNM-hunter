ALTER TABLE "projects" ADD COLUMN     "cloud_recon_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "cloud_recon_providers" TEXT NOT NULL DEFAULT 'aws_s3,gcs,azure_blob',
ADD COLUMN     "cloud_recon_seeds" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "iac_scan_enabled" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "iac_scan_github_org" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "iac_scan_github_repos" TEXT NOT NULL DEFAULT '',
ADD COLUMN     "mobile_scan_enabled" BOOLEAN NOT NULL DEFAULT false;


-- AlterTable
ALTER TABLE "projects" ADD COLUMN     "mobile_scan_uploaded_files" TEXT[] DEFAULT ARRAY[]::TEXT[];
