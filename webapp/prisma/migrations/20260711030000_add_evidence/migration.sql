-- CreateTable
CREATE TABLE "evidence" (
    "id" TEXT NOT NULL,
    "remediation_id" TEXT NOT NULL,
    "type" TEXT NOT NULL DEFAULT 'screenshot',
    "label" TEXT NOT NULL DEFAULT '',
    "file_path" TEXT NOT NULL DEFAULT '',
    "file_size" INTEGER NOT NULL DEFAULT 0,
    "text_content" TEXT NOT NULL DEFAULT '',
    "source" TEXT NOT NULL DEFAULT 'manual',
    "captured_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "evidence_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "evidence_remediation_id_idx" ON "evidence"("remediation_id");

-- AddForeignKey
ALTER TABLE "evidence" ADD CONSTRAINT "evidence_remediation_id_fkey" FOREIGN KEY ("remediation_id") REFERENCES "remediations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

