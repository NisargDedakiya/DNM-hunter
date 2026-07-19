-- CreateTable: Scan (an in-app scan run)
CREATE TABLE "scans" (
    "id" TEXT NOT NULL,
    "user_id" TEXT NOT NULL,
    "target" TEXT NOT NULL,
    "scan_type" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'completed',
    "total" INTEGER NOT NULL DEFAULT 0,
    "by_severity" JSONB NOT NULL DEFAULT '{}',
    "max_cvss" DOUBLE PRECISION NOT NULL DEFAULT 0,
    "error" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scans_pkey" PRIMARY KEY ("id")
);

-- CreateTable: ScanFinding
CREATE TABLE "scan_findings" (
    "id" TEXT NOT NULL,
    "scan_id" TEXT NOT NULL,
    "scanner" TEXT NOT NULL DEFAULT '',
    "rule_id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "file" TEXT NOT NULL DEFAULT '',
    "line" INTEGER,
    "detail" TEXT NOT NULL DEFAULT '',
    "vrt" TEXT NOT NULL DEFAULT '',
    "cwe" TEXT NOT NULL DEFAULT '',
    "cvss" DOUBLE PRECISION NOT NULL DEFAULT 0,

    CONSTRAINT "scan_findings_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "scans_user_id_idx" ON "scans"("user_id");
CREATE INDEX "scan_findings_scan_id_idx" ON "scan_findings"("scan_id");

-- AddForeignKey
ALTER TABLE "scans" ADD CONSTRAINT "scans_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "scan_findings" ADD CONSTRAINT "scan_findings_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scans"("id") ON DELETE CASCADE ON UPDATE CASCADE;
