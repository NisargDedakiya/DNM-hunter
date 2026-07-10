-- CreateTable
CREATE TABLE "auth_credentials" (
    "id" TEXT NOT NULL,
    "program_id" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT '',
    "auth_type" TEXT NOT NULL DEFAULT 'cookie',
    "cookies_encrypted" TEXT NOT NULL DEFAULT '',
    "jwt_encrypted" TEXT NOT NULL DEFAULT '',
    "headers_encrypted" TEXT NOT NULL DEFAULT '',
    "oauth_token_encrypted" TEXT NOT NULL DEFAULT '',
    "notes" TEXT NOT NULL DEFAULT '',
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "auth_credentials_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "auth_credentials_program_id_idx" ON "auth_credentials"("program_id");

-- AddForeignKey
ALTER TABLE "auth_credentials" ADD CONSTRAINT "auth_credentials_program_id_fkey" FOREIGN KEY ("program_id") REFERENCES "programs"("id") ON DELETE CASCADE ON UPDATE CASCADE;

