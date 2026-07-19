-- Add public share link fields to Scan
ALTER TABLE "scans" ADD COLUMN "share_token" TEXT;
ALTER TABLE "scans" ADD COLUMN "shared_at" TIMESTAMP(3);

-- CreateIndex (unique token for lookups)
CREATE UNIQUE INDEX "scans_share_token_key" ON "scans"("share_token");
