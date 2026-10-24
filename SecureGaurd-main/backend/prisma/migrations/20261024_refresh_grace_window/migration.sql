-- Refresh-token rotation grace window (Day 1: fixes the /refresh same-token race).
-- The rotation keeps the superseded token hash in "previousRefreshToken",
-- honored for 60 s via "refreshGraceExpiresAt". Idempotent: safe to re-run.
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "previousRefreshToken" TEXT;
ALTER TABLE "User" ADD COLUMN IF NOT EXISTS "refreshGraceExpiresAt" TIMESTAMP(3);
